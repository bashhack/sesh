package subshell

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// testCustomizer adds a helper command and a prefix, as AWS's does.
type testCustomizer struct{}

func (testCustomizer) Functions() string    { return "sesh_status() { echo status-ok; }\n" }
func (testCustomizer) PromptPrefix() string { return "(sesh:test) " }

// write writes body to path, making its folder.
func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// inShell starts the shell GetShellConfig builds for $SHELL = sh,
// interactive (so it reads its startup files, as at a terminal), runs cmd
// in it, and returns what it printed. The config's files are removed after.
func inShell(t *testing.T, sh, cmd string) string {
	t.Helper()
	path, err := exec.LookPath(sh)
	if err != nil {
		t.Skipf("no %s here", sh)
	}
	t.Setenv("SHELL", path)
	sc, err := GetShellConfig(&Config{
		ServiceName:     "test",
		Variables:       map[string]string{"AWS_SESSION_TOKEN": "token"},
		Expiry:          time.Now().Add(time.Hour),
		ShellCustomizer: testCustomizer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Cleanup()
	c := exec.Command(sc.Shell, append(sc.Args, "-i", "-c", cmd)...) //nolint:gosec // a shell found on PATH, for the test
	c.Env = sc.Env
	out, err := c.Output()
	if err != nil {
		t.Fatalf("%s: %v\n%s", sh, err, out)
	}
	return strings.TrimSpace(string(out))
}

// A clean home for the shell, with SESH_MASTER_PASSWORD set to show it
// doesn't reach the shell.
func home(t *testing.T) string {
	t.Helper()
	h := t.TempDir()
	t.Setenv("HOME", h)
	t.Setenv("ZDOTDIR", "")
	t.Setenv("ENV", "")
	t.Setenv("SESH_MASTER_PASSWORD", "hunter2-hunter2")
	t.Setenv("PROMPT_COMMAND", "")
	return h
}

// prompts runs zsh's prompt hooks, as before a prompt (which a shell run
// with -c never shows).
const prompts = `for __f in $precmd_functions; do $__f; done 2>/dev/null; `

// zsh runs the user's .zshenv and .zshrc from their ZDOTDIR, which is
// theirs inside; sesh's helpers are there, unchanged by the user's aliases,
// and the prefix goes on at the first prompt. History is never in the
// folder sesh writes.
func TestZsh_UserStartupFilesFirst(t *testing.T) {
	h := home(t)
	zdot := filepath.Join(h, ".config", "zsh")
	t.Setenv("ZDOTDIR", zdot)
	write(t, filepath.Join(zdot, ".zshenv"), "export ENV_LOADED=1\n")
	write(t, filepath.Join(zdot, ".zshrc"), "alias marker=true\nalias echo='print ALIASED'\nPROMPT='mine> '\n")
	out := inShell(t, "zsh", prompts+`print -r -- "$ENV_LOADED|$(alias marker)|$ZDOTDIR|$PROMPT|$SESH_ACTIVE|$AWS_SESSION_TOKEN|${SESH_MASTER_PASSWORD-unset}|$HISTFILE"; sesh_status`)
	lines := strings.Split(out, "\n")
	fields := strings.Split(lines[0], "|")
	want := []string{"1", "marker=true", zdot, "(sesh:test) mine> ", "1", "token", "unset"}
	if len(fields) != 8 || !slices.Equal(fields[:7], want) || lines[len(lines)-1] != "status-ok" {
		t.Fatalf("got\n%s\nwant %q, then status-ok", out, want)
	}
	// macOS's /etc/zshrc sets a history file, from ZDOTDIR; Linux's sets none.
	if hist := fields[7]; hist != "" && hist != filepath.Join(zdot, ".zsh_history") {
		t.Errorf("HISTFILE = %q", hist)
	}
}

// Terminal.app's per-session history (/etc/zshrc_Apple_Terminal) is kept
// in the user's ZDOTDIR, not in the folder sesh writes and removes.
func TestZsh_TerminalAppSessionsAreTheUsers(t *testing.T) {
	if _, err := os.Stat("/etc/zshrc_Apple_Terminal"); err != nil {
		t.Skip("no Terminal.app setup here")
	}
	h := home(t)
	zdot := filepath.Join(h, "zdot")
	t.Setenv("ZDOTDIR", zdot)
	t.Setenv("TERM_PROGRAM", "Apple_Terminal")
	t.Setenv("TERM_SESSION_ID", "X")
	write(t, filepath.Join(zdot, ".zshrc"), "")
	if out := inShell(t, "zsh", `print -r -- "$SHELL_SESSION_DIR"`); out != filepath.Join(zdot, ".zsh_sessions") {
		t.Errorf("SHELL_SESSION_DIR = %q", out)
	}
}

// A ~/.zshenv that moves ZDOTDIR, as many setups do, is followed; with no
// ZDOTDIR of their own, the user's shell has none set.
func TestZsh_ZdotdirAsTheUserHasIt(t *testing.T) {
	h := home(t)
	write(t, filepath.Join(h, ".zshrc"), "alias marker=true\n")
	if out := inShell(t, "zsh", `print -r -- "$(alias marker)|${ZDOTDIR-unset}"`); out != "marker=true|unset" {
		t.Errorf("no ZDOTDIR: got %q", out)
	}
	zdot := filepath.Join(h, "cfg")
	write(t, filepath.Join(h, ".zshenv"), "ZDOTDIR=$HOME/cfg\n")
	write(t, filepath.Join(zdot, ".zshrc"), "alias moved=true\n")
	if out := inShell(t, "zsh", `print -r -- "$(alias moved)|$ZDOTDIR"`); out != "moved=true|"+zdot {
		t.Errorf("moved by .zshenv: got %q", out)
	}
}

// The prefix goes back on when a prompt theme redraws the prompt, once,
// with sesh's hook after the theme's from the first prompt on.
func TestZsh_PrefixSurvivesThemes(t *testing.T) {
	h := home(t)
	write(t, filepath.Join(h, ".zshrc"), "theme_precmd() { PROMPT='theme> ' }\nprecmd_functions+=(theme_precmd)\n")
	out := inShell(t, "zsh", prompts+prompts+`print -r -- "$PROMPT|$precmd_functions"`)
	if out != "(sesh:test) theme> |theme_precmd __sesh_prompt" {
		t.Errorf("got %q", out)
	}
}

// bash runs ~/.bashrc, after sesh's helpers (so its aliases don't change
// them); its prompt command keeps the prefix, after the user's own.
func TestBash_UserBashrcFirst(t *testing.T) {
	h := home(t)
	write(t, filepath.Join(h, ".bashrc"), "alias marker=true\nalias echo='printf ALIASED'\nPS1='mine> '\nPROMPT_COMMAND='PS1=\"theme> \"'\n")
	out := inShell(t, "bash", `alias marker; eval "$PROMPT_COMMAND"; printf '%s|%s|%s\n' "$PS1" "$SESH_ACTIVE" "${SESH_MASTER_PASSWORD-unset}"; sesh_status`)
	want := "alias marker='true'\n(sesh:test) theme> |1|unset\nstatus-ok"
	if out != want {
		t.Errorf("got\n%s\nwant\n%s", out, want)
	}
}

// A PROMPT_COMMAND array (bash 5.1 and later) gets sesh's hook after the
// user's own.
func TestBash_PromptCommandArray(t *testing.T) {
	h := home(t)
	write(t, filepath.Join(h, ".bashrc"), "PROMPT_COMMAND=(:)\nPROMPT_COMMAND+=('PS1=\"theme> \"')\n")
	out := inShell(t, "bash", `if (( BASH_VERSINFO[0] < 5 || (BASH_VERSINFO[0] == 5 && BASH_VERSINFO[1] < 1) )); then echo old; exit; fi; for c in "${PROMPT_COMMAND[@]}"; do eval "$c"; done; printf '%s|%s\n' "$PS1" "${PROMPT_COMMAND[-1]}"`)
	if out == "old" {
		t.Skip("bash before 5.1 runs a string PROMPT_COMMAND only")
	}
	if out != "(sesh:test) theme> |__sesh_prompt" {
		t.Errorf("got %q", out)
	}
}

// sh runs the user's own ENV file, expanded as sh expands ENV, after
// sesh's helpers.
func TestSh_UserEnvFileFirst(t *testing.T) {
	h := home(t)
	write(t, filepath.Join(h, ".shrc"), "OWN_LOADED=1\nPS1='mine> '\n")
	t.Setenv("ENV", "$HOME/.shrc")
	out := inShell(t, "sh", `printf '%s|%s|%s\n' "$OWN_LOADED" "$PS1" "${SESH_MASTER_PASSWORD-unset}"; sesh_status`)
	if want := "1|(sesh:test) mine> |unset\nstatus-ok"; out != want {
		t.Errorf("got\n%s\nwant\n%s", out, want)
	}
}

// The files sesh writes are removed by Cleanup, and readable only by the
// user until then.
func TestGetShellConfig_Cleanup(t *testing.T) {
	for _, sh := range []string{"/bin/zsh", "/bin/bash", "/bin/sh"} {
		home(t)
		t.Setenv("SHELL", sh)
		sc, err := GetShellConfig(&Config{ServiceName: "test", ShellCustomizer: testCustomizer{}})
		if err != nil {
			t.Fatal(err)
		}
		var path string
		switch filepath.Base(sh) {
		case "zsh":
			path = envValue(sc.Env, "ZDOTDIR")
		case "bash":
			path = sc.Args[len(sc.Args)-1]
		default:
			path = envValue(sc.Env, "ENV")
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s: %s is %v, %v", sh, path, info.Mode(), err)
		}
		sc.Cleanup()
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s: %s is still there: %v", sh, path, err)
		}
	}
}

func TestGetShellConfig_NeedsACustomizer(t *testing.T) {
	if _, err := GetShellConfig(&Config{ServiceName: "test"}); err == nil {
		t.Error("GetShellConfig() took no customizer")
	}
}

func TestFilterEnv(t *testing.T) {
	env := []string{"A=1", "AB=2", "A=3", "B=A=4"}
	if got := FilterEnv(env, "A"); !slices.Equal(got, []string{"AB=2", "B=A=4"}) {
		t.Errorf("FilterEnv() = %q", got)
	}
}

// Variables the config says to unset don't reach the shell.
func TestGetShellConfig_Unset(t *testing.T) {
	home(t)
	t.Setenv("SHELL", "/bin/sh")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIASTRAY")
	sc, err := GetShellConfig(&Config{ServiceName: "test", ShellCustomizer: testCustomizer{}, Unset: []string{"AWS_ACCESS_KEY_ID"}})
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Cleanup()
	if v := envValue(sc.Env, "AWS_ACCESS_KEY_ID"); v != "" {
		t.Errorf("AWS_ACCESS_KEY_ID = %q", v)
	}
}
