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
	"github.com/bashhack/sesh/internal/provider"
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
func writeCompletions(w io.Writer, reg *provider.Registry, words []string) error {
	cands, files := complete(reg, words)
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
func complete(reg *provider.Registry, words []string) (cands []candidate, files bool) {
	if len(words) == 0 {
		words = []string{""}
	}
	cur, before := words[len(words)-1], words[:len(words)-1]
	if slices.Contains(before, "--") {
		return nil, false
	}
	if len(before) == 0 && !strings.HasPrefix(cur, "-") {
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
		specs = flagSpecs(func(fs *flag.FlagSet) { addAgentFlags(fs, 0, 0) }, nil)
	case "audit":
		if len(before) == 1 && !strings.HasPrefix(cur, "-") {
			return matching(auditCommands, cur), false
		}
		if len(before) > 1 && before[1] == "prune" {
			specs = flagSpecs(func(fs *flag.FlagSet) { addAuditPruneFlags(fs) }, nil)
		} else {
			specs = flagSpecs(func(fs *flag.FlagSet) { addAuditFlags(fs) }, nil)
		}
	case "init":
		specs = append(flagSpecs(func(fs *flag.FlagSet) { addInitFlags(fs) }, nil), settingSpecs()...)
	case "touchid":
		verbs = touchIDCommands
	case "recovery":
		verbs = recoveryCommands
	case "completion":
		verbs = completionShells
	case "config", "recover":
		return nil, false
	default:
		specs = mainSpecs(reg, before)
	}
	if verbs != nil {
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

	// One dash as typed (the docs' -service style), otherwise two.
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

// mainSpecs are the flags of a sesh command that isn't a subcommand: the
// common flags, the setting flags, --migrate and --rekey, and the selected
// provider's own flags; after --rekey, only its flags.
func mainSpecs(reg *provider.Registry, before []string) []flagSpec {
	if slices.ContainsFunc(before, func(w string) bool { return w == "--rekey" || w == "-rekey" }) {
		specs := flagSpecs(func(fs *flag.FlagSet) { addRekeyFlags(fs) }, nil)
		for i := range specs {
			if specs[i].name == "to" {
				specs[i].values = []string{config.KeySourcePassword, config.KeySourceKeychain}
			}
		}
		return append(specs, settingSpecs()...)
	}
	var p provider.ServiceProvider
	if name := extractServiceName(append([]string{"sesh"}, before...)); name != "" {
		p, _ = reg.GetProvider(name) //nolint:errcheck // an unknown provider just adds no flags
	}
	specs := flagSpecs(func(fs *flag.FlagSet) {
		addCommonFlags(fs, "")
		if p != nil {
			_ = p.SetupFlags(fs) //nolint:errcheck // a provider that fails here just adds no flags
		}
	}, p)
	for i := range specs {
		if specs[i].name == "service" {
			for _, rp := range reg.ListProviders() {
				specs[i].values = append(specs[i].values, rp.Name())
			}
		}
	}
	specs = append(specs,
		flagSpec{name: "migrate", usage: "Copy all entries from the macOS Keychain to the vault"},
		flagSpec{name: "rekey", usage: "Change the key source (--to), or the master password"},
	)
	return append(specs, settingSpecs()...)
}

// flagSpecs registers flags with register and describes them, taking
// values and paths from p's flag info when p isn't nil.
func flagSpecs(register func(*flag.FlagSet), p provider.ServiceProvider) []flagSpec {
	fs := flag.NewFlagSet("sesh", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	register(fs)
	info := map[string]provider.FlagInfo{}
	if p != nil {
		for _, fi := range p.GetFlagInfo() {
			info[fi.Name] = fi
		}
	}
	var specs []flagSpec
	fs.VisitAll(func(f *flag.Flag) {
		bf, isBool := f.Value.(interface{ IsBoolFlag() bool })
		s := flagSpec{name: f.Name, usage: f.Usage, takesValue: !isBool || !bf.IsBoolFlag()}
		if fi, ok := info[f.Name]; ok {
			s.values, s.path = fi.Values, fi.Path
		}
		specs = append(specs, s)
	})
	return specs
}

func settingSpecs() []flagSpec {
	var specs []flagSpec
	for name, sf := range settingFlags {
		specs = append(specs, flagSpec{name: name, usage: sf.usage, values: sf.values, path: sf.path, takesValue: true})
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
