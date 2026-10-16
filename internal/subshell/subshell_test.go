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
	sc, err := GetShellConfig(Config{
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

// zsh runs the user's .zshenv and .zshrc from their ZDOTDIR, which is
// theirs again inside, with history theirs; then sesh's prefix and helpers.
func TestZsh_UserStartupFilesFirst(t *testing.T) {
	h := home(t)
	zdot := filepath.Join(h, ".config", "zsh")
	t.Setenv("ZDOTDIR", zdot)
	write(t, filepath.Join(zdot, ".zshenv"), "export ENV_LOADED=1\n")
	write(t, filepath.Join(zdot, ".zshrc"), "alias marker=true\nPROMPT='mine> '\n")
	out := inShell(t, "zsh", `print -r -- "$ENV_LOADED|$(alias marker)|$ZDOTDIR|$HISTFILE|$PROMPT|$SESH_ACTIVE|$AWS_SESSION_TOKEN|${SESH_MASTER_PASSWORD-unset}"; sesh_status`)
	want := strings.Join([]string{"1", "marker=true", zdot, zdot + "/.zsh_history", "(sesh:test) mine> ", "1", "token", "unset"}, "|") + "\nstatus-ok"
	if out != want {
		t.Errorf("got\n%s\nwant\n%s", out, want)
	}
}

// A ~/.zshenv that moves ZDOTDIR, as many setups do, is followed.
func TestZsh_ZshenvMovesZdotdir(t *testing.T) {
	h := home(t)
	zdot := filepath.Join(h, "cfg")
	write(t, filepath.Join(h, ".zshenv"), "ZDOTDIR=$HOME/cfg\n")
	write(t, filepath.Join(zdot, ".zshrc"), "alias marker=true\n")
	if out := inShell(t, "zsh", `print -r -- "$(alias marker)|$ZDOTDIR"`); out != "marker=true|"+zdot {
		t.Errorf("got %q", out)
	}
}

// The prefix goes back on when a prompt theme redraws the prompt, once.
func TestZsh_PrefixSurvivesThemes(t *testing.T) {
	home(t)
	out := inShell(t, "zsh", `PROMPT='theme> '; __sesh_prompt; __sesh_prompt; print -r -- "$PROMPT|${precmd_functions[-1]}"`)
	if out != "(sesh:test) theme> |__sesh_prompt" {
		t.Errorf("got %q", out)
	}
}

// bash runs ~/.bashrc, then sesh's; its prompt command keeps the prefix,
// after the user's own.
func TestBash_UserBashrcFirst(t *testing.T) {
	h := home(t)
	write(t, filepath.Join(h, ".bashrc"), "alias marker=true\nPS1='mine> '\nPROMPT_COMMAND='PS1=\"theme> \"'\n")
	out := inShell(t, "bash", `alias marker; eval "$PROMPT_COMMAND"; printf '%s|%s|%s\n' "$PS1" "$SESH_ACTIVE" "${SESH_MASTER_PASSWORD-unset}"; sesh_status`)
	want := "alias marker='true'\n(sesh:test) theme> |1|unset\nstatus-ok"
	if out != want {
		t.Errorf("got\n%s\nwant\n%s", out, want)
	}
}

// sh runs the user's own ENV file, then sesh's.
func TestSh_UserEnvFileFirst(t *testing.T) {
	h := home(t)
	own := filepath.Join(h, ".shrc")
	write(t, own, "OWN_LOADED=1\nPS1='mine> '\n")
	t.Setenv("ENV", own)
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
		sc, err := GetShellConfig(Config{ServiceName: "test", ShellCustomizer: testCustomizer{}})
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
	if _, err := GetShellConfig(Config{ServiceName: "test"}); err == nil {
		t.Error("GetShellConfig() took no customizer")
	}
}

func TestFilterEnv(t *testing.T) {
	env := []string{"A=1", "AB=2", "A=3", "B=A=4"}
	if got := FilterEnv(env, "A"); !slices.Equal(got, []string{"AB=2", "B=A=4"}) {
		t.Errorf("FilterEnv() = %q", got)
	}
}
