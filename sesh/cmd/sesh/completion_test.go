package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestComplete(t *testing.T) {
	reg := NewDefaultApp(VersionInfo{}, unavailableStore{err: errNoStore}, 0).Registry
	all := func(vs ...string) []string { return vs }
	for _, tt := range []struct {
		name  string
		words []string
		want  []string // exactly these, in order
		has   []string // at least these
		lacks []string // none of these
		files bool
	}{
		{name: "subcommands", words: all(""), want: all("agent", "audit", "completion", "config", "init", "touchid")},
		{name: "subcommand prefix", words: all("co"), want: all("completion", "config")},
		{name: "audit commands", words: all("audit", ""), want: all("prune")},
		{name: "audit flags", words: all("audit", "-"), want: all("--limit")},
		{name: "audit prune flags", words: all("audit", "prune", "-"), want: all("--older-than")},
		{name: "audit prune days", words: all("audit", "prune", "--older-than", "")},
		{name: "first flag", words: all("-"), has: all("--service", "--list-services", "--migrate", "--rekey", "--backend", "--db-path"), lacks: all("--action")},
		{name: "one dash as typed", words: all("-se"), want: all("-service", "-setup")},
		{name: "providers", words: all("--service", ""), want: all("aws", "password", "totp")},
		{name: "provider prefix", words: all("-service", "p"), want: all("password")},
		{name: "provider after =", words: all("--service=t"), want: all("--service=totp")},
		{name: "provider flags", words: all("--service", "password", "--sh"), want: all("--show")},
		{name: "used flags not offered", words: all("--service", "password", "--list", "--l"), want: all("--length", "--limit", "--list-services")},
		{name: "unknown provider adds no flags", words: all("--service", "nosuch", "--"), has: all("--list"), lacks: all("--action")},
		{name: "actions", words: all("--service", "password", "--action", ""), want: all("store", "get", "generate", "search", "export", "import", "totp-store", "totp-generate")},
		{name: "value after =", words: all("--service", "password", "--format=j"), want: all("--format=json")},
		{name: "entry types", words: all("--service", "password", "--entry-type", ""), want: all("password", "api_key", "totp", "secure_note")},
		{name: "file path", words: all("--service", "password", "--file", ""), files: true},
		{name: "file path after =", words: all("--service", "password", "--file=ba"), files: true},
		{name: "free-text value", words: all("--service", "password", "--service-name", "")},
		{name: "positional word", words: all("--service", "password", "sto")},
		{name: "after --", words: all("--service", "password", "--", "-")},
		{name: "backend values", words: all("--backend", ""), want: all("sqlite", "keychain")},
		{name: "key source values", words: all("--key-source=p"), want: all("--key-source=password")},
		{name: "db path", words: all("--db-path", ""), files: true},
		{name: "rekey flags", words: all("--rekey", "--"), has: all("--to", "--key-source"), lacks: all("--service", "--rekey")},
		{name: "rekey target", words: all("--rekey", "--to", ""), want: all("password", "keychain")},
		{name: "agent commands", words: all("agent", ""), want: all("lock", "status", "stop")},
		{name: "agent flags", words: all("agent", "-"), want: all("--idle-timeout", "--max-lifetime", "--socket")},
		{name: "agent command takes no arguments", words: all("agent", "lock", "")},
		{name: "touchid commands", words: all("touchid", "e"), want: all("enable")},
		{name: "touchid takes one command", words: all("touchid", "enable", "")},
		{name: "completion shells", words: all("completion", ""), want: all("bash", "fish", "zsh")},
		{name: "init flags", words: all("init", "--"), want: all("--force", "--backend", "--db-path", "--key-source")},
		{name: "config takes nothing", words: all("config", "")},
		{name: "no words", words: nil, want: all("agent", "audit", "completion", "config", "init", "touchid")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cands, files := complete(reg, tt.words)
			if files != tt.files {
				t.Fatalf("files = %v, want %v", files, tt.files)
			}
			var got []string
			for _, c := range cands {
				got = append(got, c.value)
			}
			if tt.want != nil && !slices.Equal(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
			for _, h := range tt.has {
				if !slices.Contains(got, h) {
					t.Errorf("got %q, missing %q", got, h)
				}
			}
			for _, l := range tt.lacks {
				if slices.Contains(got, l) {
					t.Errorf("got %q, should not offer %q", got, l)
				}
			}
			if tt.want == nil && tt.has == nil && len(got) > 0 {
				t.Errorf("got %q, want nothing", got)
			}
		})
	}
}

func TestWriteCompletions(t *testing.T) {
	reg := NewDefaultApp(VersionInfo{}, unavailableStore{err: errNoStore}, 0).Registry
	var b bytes.Buffer
	if err := writeCompletions(&b, reg, []string{"agent", "st"}); err != nil {
		t.Fatal(err)
	}
	if want := "status\tShow whether the agent is running and unlocked\nstop\tShut the agent down\n"; b.String() != want {
		t.Errorf("output = %q, want %q", b.String(), want)
	}
	b.Reset()
	if err := writeCompletions(&b, reg, []string{"--db-path", ""}); err != nil {
		t.Fatal(err)
	}
	if b.String() != filesDirective+"\n" {
		t.Errorf("output = %q, want the files directive", b.String())
	}
}

func TestRunCompletion(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		app := agentTestApp()
		if err := runCompletion(app, []string{shell}); err != nil {
			t.Fatalf("%s: %v", shell, err)
		}
		if out := app.Stdout.(*bytes.Buffer).String(); !strings.Contains(out, "sesh "+completeCmd) {
			t.Errorf("%s script doesn't call sesh %s:\n%s", shell, completeCmd, out)
		}
	}
	for _, args := range [][]string{nil, {"powershell"}, {"bash", "zsh"}} {
		if err := runCompletion(agentTestApp(), args); err == nil || !strings.Contains(err.Error(), "usage: sesh completion bash|zsh|fish") {
			t.Errorf("runCompletion(%q) err = %v", args, err)
		}
	}
}

// fakeSesh puts a `sesh` on PATH that records its arguments, one per line,
// and prints out (with printf %b escapes). It returns the arguments file.
func fakeSesh(t *testing.T, out string) string {
	t.Helper()
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$SESH_FAKE_ARGS\"\nprintf '%b' \"$SESH_FAKE_OUT\"\n"
	if err := os.WriteFile(filepath.Join(dir, "sesh"), []byte(script), 0o755); err != nil { //nolint:gosec // an executable test stub
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SESH_FAKE_ARGS", argsFile)
	t.Setenv("SESH_FAKE_OUT", out)
	return argsFile
}

func completionScript(t *testing.T, shell string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sesh."+shell)
	app := agentTestApp()
	if err := runCompletion(app, []string{shell}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, app.Stdout.(*bytes.Buffer).Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readArgs(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // the test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func needShell(t *testing.T, shell string) string {
	t.Helper()
	path, err := exec.LookPath(shell)
	if err != nil {
		t.Skipf("%s isn't installed", shell)
	}
	return path
}

// The bash script is run as bash would on a Tab: COMP_LINE, COMP_POINT,
// COMP_WORDS (split at "=", as bash does), and COMP_CWORD set, then _sesh.
func TestCompletionScript_Bash(t *testing.T) {
	bash := needShell(t, "bash")
	script := completionScript(t, "bash")
	for _, tt := range []struct {
		name, line, words, cword, out string
		wantArgs, wantReply           []string
	}{
		{"flag value", "sesh --service pa", "(sesh --service pa)", "2", `password\tdesc\n`,
			[]string{"--service", "pa"}, []string{"password"}},
		{"after a space", "sesh --service ", `(sesh --service "")`, "2", `aws\npassword\n`,
			[]string{"--service", ""}, []string{"aws", "password"}},
		{"value after = (bash 4+ splits the word)", "sesh --format=j", "(sesh --format = j)", "3", `--format=json\n`,
			[]string{"--format=j"}, []string{"json"}},
		{"value after = (bash 3.2 doesn't)", "sesh --format=j", "(sesh --format=j)", "1", `--format=json\n`,
			[]string{"--format=j"}, []string{"json"}},
		{"nothing", "sesh config ", `(sesh config "")`, "2", ``,
			[]string{"config", ""}, nil},
		{"value right after = (bash 4+)", "sesh --format=", "(sesh --format =)", "2", `--format=json\n`,
			[]string{"--format="}, []string{"json"}},
		{"quoted value", `sesh --service "pa`, `(sesh --service '"pa')`, "2", `password\n`,
			[]string{"--service", "pa"}, []string{"password"}},
		{"quote after = (bash 3.2)", `sesh --format="j`, `(sesh '--format="j')`, "1", `--format=json\n`,
			[]string{"--format=j"}, []string{"json"}},
		{"quote after = (bash 4+)", `sesh --format="j`, `(sesh --format = '"j')`, "3", `--format=json\n`,
			[]string{"--format=j"}, []string{"json"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			argsFile := fakeSesh(t, tt.out)
			cmd := exec.Command(bash, "--norc", "-c", `source "$1"; COMP_LINE="$2"; COMP_POINT=${#COMP_LINE}; eval "COMP_WORDS=$3"; COMP_CWORD=$4; _sesh; printf '%s\n' "${COMPREPLY[@]}"`,
				"bash", script, tt.line, tt.words, tt.cword) //nolint:gosec // test inputs
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("bash: %v\n%s", err, out)
			}
			if got := readArgs(t, argsFile); !slices.Equal(got, append([]string{completeCmd}, tt.wantArgs...)) {
				t.Errorf("sesh got args %q, want %q", got, tt.wantArgs)
			}
			got := strings.Fields(string(out))
			if !slices.Equal(got, tt.wantReply) {
				t.Errorf("COMPREPLY = %q, want %q", got, tt.wantReply)
			}
		})
	}

	// COMP_WORDS keeps a quoted word whole, quote included; bash 4+ also
	// splits at "=", bash 3.2 doesn't.
	for _, tt := range []struct {
		name, line, words, cword, want string
		wantArgs                       []string
	}{
		{"path", "sesh --file ba", "(sesh --file ba)", "2", "backup.enc", []string{"--file", "ba"}},
		{"path after = (bash 3.2)", "sesh --file=ba", "(sesh --file=ba)", "1", "backup.enc", []string{"--file=ba"}},
		{"path after = (bash 4+)", "sesh --file=ba", "(sesh --file = ba)", "3", "backup.enc", []string{"--file=ba"}},
		{"quoted path with a space", `sesh --file "My Backup/ba`, `(sesh --file '"My Backup/ba')`, "2", "My Backup/backup.enc", []string{"--file", "My Backup/ba"}},
	} {
		t.Run("files: "+tt.name, func(t *testing.T) {
			argsFile := fakeSesh(t, `:files\n`)
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, "My Backup"), 0o700); err != nil {
				t.Fatal(err)
			}
			for _, f := range []string{"backup.enc", "My Backup/backup.enc"} {
				if err := os.WriteFile(filepath.Join(dir, f), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(bash, "--norc", "-c", `source "$1"; cd "$2"; COMP_LINE="$3"; COMP_POINT=${#COMP_LINE}; eval "COMP_WORDS=$4"; COMP_CWORD=$5; _sesh; printf '%s\n' "${COMPREPLY[@]}"`,
				"bash", script, dir, tt.line, tt.words, tt.cword) //nolint:gosec // test inputs
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("bash: %v\n%s", err, out)
			}
			if got := readArgs(t, argsFile); !slices.Equal(got, append([]string{completeCmd}, tt.wantArgs...)) {
				t.Errorf("sesh got args %q, want %q", got, tt.wantArgs)
			}
			if got := strings.TrimSuffix(string(out), "\n"); got != tt.want {
				t.Errorf("COMPREPLY = %q, want %q", got, tt.want)
			}
		})
	}
}

// The zsh script is run with the completion system's functions stubbed:
// _describe prints the candidates it was given, _files prints FILES.
func TestCompletionScript_Zsh(t *testing.T) {
	zsh := needShell(t, "zsh")
	script := completionScript(t, "zsh")
	for _, tt := range []struct {
		name, words, current, out string
		wantArgs, wantOut         []string
	}{
		{"described candidates", "(sesh agent st)", "3", `status\tShow it\nstop\tShut: down\n`,
			[]string{"agent", "st"}, []string{"status:Show it", "stop:Shut: down"}},
		{"colon in a value", "(sesh --x '')", "3", `a:b\n`,
			[]string{"--x", ""}, []string{`a\:b`}},
		{"files", "(sesh --file '')", "3", `:files\n`,
			[]string{"--file", ""}, []string{"FILES"}},
		{"files after =", "(sesh --file=ba)", "2", `:files\n`,
			[]string{"--file=ba"}, []string{"compset -P *=", "FILES"}},
		{"quoted value", `(sesh --service '"pa')`, "3", `password\n`,
			[]string{"--service", "pa"}, []string{"password"}},
		{"escaped space", `(sesh --x 'a\ b')`, "3", `a b\n`,
			[]string{"--x", "a b"}, []string{"a b"}},
		{"quote after =", `(sesh '--format="j')`, "2", `--format=json\n`,
			[]string{"--format=j"}, []string{"--format=json"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			argsFile := fakeSesh(t, tt.out)
			body := `compdef() { :; }; compset() { print -r -- "compset $*"; }; _describe() { print -rl -- "${(@P)4}"; }; _files() { print FILES; }
source "$1"; eval "words=$2"; CURRENT=$3; _sesh`
			out, err := exec.Command(zsh, "-f", "-c", body, "zsh", script, tt.words, tt.current).CombinedOutput() //nolint:gosec // test inputs
			if err != nil {
				t.Fatalf("zsh: %v\n%s", err, out)
			}
			if got := readArgs(t, argsFile); !slices.Equal(got, append([]string{completeCmd}, tt.wantArgs...)) {
				t.Errorf("sesh got args %q, want %q", got, tt.wantArgs)
			}
			if got := strings.Split(strings.TrimSpace(string(out)), "\n"); !slices.Equal(got, tt.wantOut) {
				t.Errorf("zsh offered %q, want %q", got, tt.wantOut)
			}
		})
	}
}

// fish can complete a command line without a terminal (complete -C).
func TestCompletionScript_Fish(t *testing.T) {
	fish := needShell(t, "fish")
	script := completionScript(t, "fish")
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "My Backup"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"backup.enc", "My Backup/backup.enc"} {
		if err := os.WriteFile(filepath.Join(dir, f), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tt := range []struct {
		name, line, out, want string
		wantArgs              []string
	}{
		{"described candidates", "sesh --service pa", `password\tStore passwords\npager\n`, "password\tStore passwords", []string{"--service", "pa"}},
		{"files", "sesh --file ba", `:files\n`, "backup.enc", []string{"--file", "ba"}},
		{"files after =", "sesh --file=ba", `:files\n`, "--file=backup.enc", []string{"--file=ba"}},
		{"after a space", "sesh --service ", `aws\npassword\n`, "aws", []string{"--service", ""}},
		{"quoted value", `sesh --service "pa`, `password\n`, "password", []string{"--service", "pa"}},
		{"quote after =", `sesh --format="j`, `--format=json\n`, "--format=json", []string{"--format=j"}},
		{"quoted path with a space", `sesh --file "My Backup/ba`, `:files\n`, "My", []string{"--file", "My Backup/ba"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			argsFile := fakeSesh(t, tt.out)
			cmd := exec.Command(fish, "--no-config", "-c", `source $argv[1]; cd $argv[2]; complete -C "$argv[3]"`, script, dir, tt.line) //nolint:gosec // test inputs
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("fish: %v\n%s", err, out)
			}
			if got := readArgs(t, argsFile); !slices.Equal(got, append([]string{completeCmd}, tt.wantArgs...)) {
				t.Errorf("sesh got args %q, want %q", got, tt.wantArgs)
			}
			if !slices.ContainsFunc(strings.Split(string(out), "\n"), func(l string) bool {
				return strings.HasPrefix(l, tt.want) && (!strings.Contains(tt.line, "My Backup") || strings.Contains(l, "backup.enc"))
			}) {
				t.Errorf("fish offered:\n%s\nwant a line starting %q", out, tt.want)
			}
		})
	}
}
