package main

import (
	"embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/vault"
)

// completeCmd is the hidden command the completion scripts run on each Tab:
// `sesh __complete <word>...`, the words typed after "sesh", the last one
// being the word under the cursor ("" after a space). It prints one
// candidate per line, "value<TAB>description", or the single line
// filesDirective when the shell should complete a file path instead. It
// never reads the config, the vault, or the agent.
const completeCmd = "__complete"

// filesDirective tells a completion script to complete file paths.
const filesDirective = ":files"

// candidate is a completion: a word and what it does.
type candidate struct {
	value, desc string
}

//go:embed completion
var completionScripts embed.FS

// completionShells are the shells `sesh completion` has a script for.
var completionShells = []candidate{
	{"bash", "Bash completion script"},
	{"fish", "fish completion script"},
	{"zsh", "zsh completion script"},
}

// runCompletion is `sesh completion bash|zsh|fish`: it prints the shell's
// completion script.
func runCompletion(app *App, args []string) error {
	if len(args) > 0 && isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, "Usage: sesh completion bash|zsh|fish\n  Print the shell's completion script. In zsh, for one: eval \"$(sesh completion zsh)\"")
		return err
	}
	if len(args) != 1 || !slices.ContainsFunc(completionShells, func(c candidate) bool { return c.value == args[0] }) {
		return errors.New("usage: sesh completion bash|zsh|fish")
	}
	script, err := completionScripts.ReadFile("completion/sesh." + args[0])
	if err != nil {
		return err
	}
	_, err = app.Stdout.Write(script)
	return err
}

// writeCompletions answers `sesh __complete`.
func writeCompletions(w io.Writer, words []string) error {
	cands, files := complete(words)
	if files {
		_, err := fmt.Fprintln(w, filesDirective)
		return err
	}
	var b strings.Builder
	for _, c := range cands {
		b.WriteString(c.value)
		if c.desc != "" {
			b.WriteString("\t" + c.desc)
		}
		b.WriteString("\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// flagSpec is what completion knows about one flag.
type flagSpec struct {
	name, usage string
	values      []string
	takesValue  bool
	path        bool
}

// complete returns the candidates for the last of words, matching what's
// typed so far, or files=true for a file path.
func complete(words []string) (cands []candidate, files bool) {
	if len(words) == 0 {
		words = []string{""}
	}
	cur, before := words[len(words)-1], words[:len(words)-1]
	if slices.Contains(before, "--") {
		// After sesh run's --, the command and its arguments.
		return nil, firstWord(before) == "run"
	}
	// A setting flag's value, with any command: --db-path takes a path.
	if prev := lastWord(before); strings.HasPrefix(prev, "-") && !strings.Contains(prev, "=") {
		if spec, ok := findSpec(settingSpecs(), prev); ok {
			return nil, spec.path
		}
	}
	if (len(before) == 0 || len(before) == 1 && before[0] == "help") && !strings.HasPrefix(cur, "-") {
		return matching(subcommands, cur), false
	}

	var specs []flagSpec
	var verbs []candidate
	switch name := firstWord(before); name {
	case "agent":
		if len(before) == 1 && !strings.HasPrefix(cur, "-") {
			return matching(agentControls, cur), false
		}
		if len(before) > 1 && slices.ContainsFunc(agentControls, func(c candidate) bool { return c.value == before[1] }) {
			return nil, false // lock, status, and stop take no arguments
		}
		specs = flagSpecs(func(fs *flag.FlagSet) { addAgentFlags(fs, 0, 0) })
	case "audit":
		if len(before) == 1 && !strings.HasPrefix(cur, "-") {
			return matching(auditCommands, cur), false
		}
		if len(before) > 1 && before[1] == "prune" {
			specs = flagSpecs(func(fs *flag.FlagSet) { addAuditPruneFlags(fs) })
		} else {
			specs = flagSpecs(func(fs *flag.FlagSet) { addAuditFlags(fs) })
		}
	case "init":
		specs = append(flagSpecs(func(fs *flag.FlagSet) { addInitFlags(fs) }), settingSpecs()...)
	case "backup":
		words := positional(before, append(flagSpecs(func(fs *flag.FlagSet) { addBackupFlags(fs) }), flagSpecs(func(fs *flag.FlagSet) { addBackupDeleteFlags(fs) })...))
		switch {
		case len(words) == 1 && cur != "" && !strings.HasPrefix(cur, "-"):
			// list, delete, or the file to write.
			if c := matching(backupCommands, cur); len(c) > 0 {
				return c, false
			}
			return nil, true
		case len(words) == 1 && cur == "" && !slices.ContainsFunc(before, isForce):
			return backupCommands, false
		case len(words) == 1 && cur == "":
			return nil, true // after --force: the file to write
		case len(words) == 1:
			specs = flagSpecs(func(fs *flag.FlagSet) { addBackupFlags(fs) })
		case words[1] == "delete":
			// The backups' names aren't completed: that would list the
			// folder on a Tab press.
			specs = flagSpecs(func(fs *flag.FlagSet) { addBackupDeleteFlags(fs) })
		case words[1] == "list":
		default:
			specs = flagSpecs(func(fs *flag.FlagSet) { addBackupFlags(fs) })
		}
	case "edit":
		specs = flagSpecs(func(fs *flag.FlagSet) { addEditFlags(fs) })
		for i := range specs {
			if specs[i].name == "type" {
				specs[i].values = []string{string(vault.KindPassword), string(vault.KindAPIKey), string(vault.KindNote)}
			}
		}
	case "show":
		specs = flagSpecs(func(fs *flag.FlagSet) { addShowFlags(fs) })
	case "history":
		specs = flagSpecs(addHistoryFlags)
	case "list":
		if !strings.HasPrefix(cur, "-") && !takesValueAfter(before, "folder", "tag", "sort") {
			return matching(kindWords, cur), false
		}
		specs = flagSpecs(func(fs *flag.FlagSet) { addListFlags(fs) })
		for i := range specs {
			if specs[i].name == "sort" {
				specs[i].values = []string{"name", "created", "updated", "folder"}
			}
		}
	case "search":
		specs = flagSpecs(func(fs *flag.FlagSet) { addSearchFlags(fs) })
	case "copy":
		specs = flagSpecs(func(fs *flag.FlagSet) { addCopyFlags(fs) })
	case "get":
		specs = flagSpecs(func(fs *flag.FlagSet) { addGetFlags(fs) })
	case "code":
		specs = flagSpecs(func(fs *flag.FlagSet) { addCodeFlags(fs) })
	case "generate":
		specs = flagSpecs(func(fs *flag.FlagSet) { addGenerateFlags(fs) })
	case "add":
		if len(before) == 1 && !strings.HasPrefix(cur, "-") {
			return matching(addKindWords, cur), false
		}
		// --rename-field and --plain-field change fields an entry has.
		specs = slices.DeleteFunc(flagSpecs(func(fs *flag.FlagSet) { addAddFlags(fs) }), func(s flagSpec) bool {
			return s.name == "rename-field" || s.name == "plain-field"
		})
	case "export":
		if !strings.HasPrefix(cur, "-") && !takesValueAfter(before, "file", "format", "folder", "tag") {
			return matching(kindWords, cur), false
		}
		specs = flagSpecs(func(fs *flag.FlagSet) { addExportFlags(fs) })
		for i := range specs {
			switch specs[i].name {
			case "format":
				specs[i].values = []string{"encrypted", "json", "csv"}
			case "file":
				specs[i].path = true
			}
		}
	case "aws":
		if len(before) == 1 && !strings.HasPrefix(cur, "-") {
			return matching([]candidate{{"setup", "Store a profile's MFA key"}}, cur), false
		}
		specs = flagSpecs(func(fs *flag.FlagSet) { _, _, _ = addAWSFlags(fs) }) //nolint:errcheck // flags that fail add none
	case "passwd":
		specs = settingSpecs()
	case "trash":
		if len(before) == 1 && !strings.HasPrefix(cur, "-") {
			return matching(trashCommands, cur), false
		}
		switch {
		case len(before) < 2 || !slices.ContainsFunc(trashCommands, func(c candidate) bool { return c.value == before[1] }):
			specs = flagSpecs(func(fs *flag.FlagSet) { addTrashFlags(fs) })
		case before[1] == "restore":
			specs = flagSpecs(func(fs *flag.FlagSet) { addTrashRestoreFlags(fs) })
		case before[1] == "remove", before[1] == "empty":
			specs = flagSpecs(func(fs *flag.FlagSet) { addForceFlag(fs) })
		}
		// sesh trash list takes only the settings' flags.
	case "run":
		specs = flagSpecs(func(fs *flag.FlagSet) { addRunFlags(fs) })
		for i := range specs {
			specs[i].path = specs[i].name == "env-file"
		}
	case "inject":
		specs = flagSpecs(func(fs *flag.FlagSet) { addInjectFlags(fs) })
		for i := range specs {
			specs[i].path = true
		}
	case "import":
		specs = flagSpecs(func(fs *flag.FlagSet) { addImportFlags(fs) })
		for i := range specs {
			switch specs[i].name {
			case "from":
				specs[i].values = importSources
			case "on-conflict":
				specs[i].values = []string{"skip", "overwrite"}
			}
		}
		if cur != "" && !strings.HasPrefix(cur, "-") {
			return nil, true // the files to import
		}
	case "restore":
		specs = flagSpecs(func(fs *flag.FlagSet) { addRestoreFlags(fs) })
		if cur != "" && !strings.HasPrefix(cur, "-") {
			return nil, true // the backup file
		}
	case "touchid":
		verbs = touchIDCommands
	case "recovery":
		verbs = recoveryCommands
	case "folder":
		verbs = folderCommands
	case "tag":
		verbs = tagCommands
	case "completion":
		verbs = completionShells
	case "config":
		words := positional(before, flagSpecs(func(fs *flag.FlagSet) { addConfigSetFlags(fs) }))
		switch {
		case len(words) == 1 && !strings.HasPrefix(cur, "-"):
			return matching([]candidate{{"set", "Change a setting in the config file"}}, cur), false
		case len(words) == 2 && words[1] == "set" && !strings.HasPrefix(cur, "-"):
			return matching(settingKeys(), cur), false
		case len(words) > 1 && words[1] == "set":
			specs = flagSpecs(func(fs *flag.FlagSet) { addConfigSetFlags(fs) })
		case !strings.HasPrefix(cur, "-"):
			return nil, false
		}
	case "recover", "lock", "open":
		// Only the settings' flags, once a dash is typed.
		if !strings.HasPrefix(cur, "-") {
			return nil, false
		}
	default:
		// Before a command, the options plain sesh takes.
		specs = append([]flagSpec{{name: "help", usage: "Show the commands"}, {name: "version", usage: "Show the version"}}, settingSpecs()...)
	}
	// The settings' flags go with any command.
	for _, s := range settingSpecs() {
		if _, ok := findSpec(specs, "--"+s.name); !ok {
			specs = append(specs, s)
		}
	}
	if verbs != nil && !strings.HasPrefix(cur, "-") {
		if len(before) == 1 {
			return matching(verbs, cur), false
		}
		return nil, false
	}

	// --flag=value
	if name, value, ok := strings.Cut(cur, "="); ok && strings.HasPrefix(name, "-") {
		spec, found := findSpec(specs, name)
		if !found || !spec.takesValue {
			return nil, false
		}
		if spec.path {
			return nil, true
		}
		for _, c := range matching(valueCandidates(spec), value) {
			cands = append(cands, candidate{name + "=" + c.value, ""})
		}
		return cands, false
	}
	// The value of the flag before it.
	if prev := lastWord(before); strings.HasPrefix(prev, "-") && !strings.Contains(prev, "=") {
		if spec, found := findSpec(specs, prev); found && spec.takesValue {
			if spec.path {
				return nil, true
			}
			return matching(valueCandidates(spec), cur), false
		}
	}
	if cur != "" && !strings.HasPrefix(cur, "-") {
		return nil, false
	}

	// One dash as typed, otherwise two.
	dashes := "--"
	if strings.HasPrefix(cur, "-") && !strings.HasPrefix(cur, "--") && cur != "-" {
		dashes = "-"
	}
	used := map[string]bool{}
	for _, w := range before {
		if strings.HasPrefix(w, "-") {
			name, _, _ := strings.Cut(strings.TrimLeft(w, "-"), "=")
			used[name] = true
		}
	}
	var all []candidate
	for _, s := range specs {
		if !used[s.name] {
			all = append(all, candidate{dashes + s.name, s.usage})
		}
	}
	return matching(all, cur), false
}

// positional is the words of before that aren't flags, nor a flag's value
// (specs, with the settings', say which take one): the command and its
// words, wherever the flags are among them.
func positional(before []string, specs []flagSpec) []string {
	specs = append(slices.Clone(specs), settingSpecs()...)
	var out []string
	for i := 0; i < len(before); i++ {
		w := before[i]
		if !strings.HasPrefix(w, "-") || w == "-" {
			out = append(out, w)
			continue
		}
		if s, ok := findSpec(specs, w); ok && s.takesValue && !strings.Contains(w, "=") {
			i++ // its value
		}
	}
	return out
}

// isForce says whether w is --force, in any of the forms flag parses.
func isForce(w string) bool {
	name, _, _ := strings.Cut(strings.TrimLeft(w, "-"), "=")
	return strings.HasPrefix(w, "-") && name == "force"
}

// backupCommands are what sesh backup takes besides a file.
var backupCommands = []candidate{
	{"list", "List the backups, newest first"},
	{"delete", "Delete backups for good"},
}

// settingKeys are the settings sesh config set changes, in the order sesh
// config shows them.
func settingKeys() []candidate {
	var out []candidate
	for _, k := range config.Keys() {
		out = append(out, candidate{k, ""})
	}
	return out
}

// kindWords are the kinds sesh list and export take.
var kindWords = []candidate{
	{"passwords", "Passwords"}, {"keys", "API keys"}, {"notes", "Notes"}, {"totp", "TOTP entries"},
}

// addKindWords are the kinds sesh add takes.
var addKindWords = []candidate{
	{"password", "A password"}, {"key", "An API key"}, {"note", "A note"}, {"totp", "A TOTP entry"},
}

// takesValueAfter says whether the word before the cursor is one of the
// named flags, without its value: the cursor is at that value.
func takesValueAfter(before []string, names ...string) bool {
	prev := lastWord(before)
	return strings.HasPrefix(prev, "-") && !strings.Contains(prev, "=") && slices.Contains(names, strings.TrimLeft(prev, "-"))
}

// flagSpecs registers flags with register and describes them.
func flagSpecs(register func(*flag.FlagSet)) []flagSpec {
	fs := flag.NewFlagSet("sesh", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	register(fs)
	var specs []flagSpec
	fs.VisitAll(func(f *flag.Flag) {
		bf, isBool := f.Value.(interface{ IsBoolFlag() bool })
		specs = append(specs, flagSpec{name: f.Name, usage: f.Usage, takesValue: !isBool || !bf.IsBoolFlag()})
	})
	return specs
}

func settingSpecs() []flagSpec {
	var specs []flagSpec
	for name, sf := range settingFlags {
		specs = append(specs, flagSpec{name: name, usage: sf.usage, path: sf.path, takesValue: true})
	}
	slices.SortFunc(specs, func(a, b flagSpec) int { return strings.Compare(a.name, b.name) })
	return specs
}

func findSpec(specs []flagSpec, arg string) (flagSpec, bool) {
	name := strings.TrimLeft(arg, "-")
	for _, s := range specs {
		if s.name == name {
			return s, true
		}
	}
	return flagSpec{}, false
}

func valueCandidates(s flagSpec) []candidate {
	cands := make([]candidate, 0, len(s.values))
	for _, v := range s.values {
		cands = append(cands, candidate{value: v})
	}
	return cands
}

// matching returns the candidates that start with prefix.
func matching(cands []candidate, prefix string) []candidate {
	var out []candidate
	for _, c := range cands {
		if strings.HasPrefix(c.value, prefix) {
			out = append(out, c)
		}
	}
	return out
}

// lastWord is the last of words, or "" when there are none.
func lastWord(words []string) string {
	if len(words) == 0 {
		return ""
	}
	return words[len(words)-1]
}

// firstWord is the first word if it names a subcommand, else "".
func firstWord(words []string) string {
	if name, _ := subcommand(append([]string{"sesh"}, words...)); name != "" {
		return name
	}
	return ""
}
