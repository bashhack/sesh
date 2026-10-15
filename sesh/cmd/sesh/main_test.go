package main

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/testutil"
)

// TestHelperProcess is needed for the testutil.MockExecCommand function
func TestHelperProcess(_ *testing.T) {
	testutil.TestHelperProcess()
}

// testHarness bundles a test App with its output buffers.
type testHarness struct {
	app    *App
	stdout *bytes.Buffer
	stderr *bytes.Buffer
}

func newTestHarness() *testHarness {
	stdoutBuf := new(bytes.Buffer)
	stderrBuf := new(bytes.Buffer)
	return &testHarness{
		app: &App{
			ExecLookPath:  func(string) (string, error) { return "/usr/local/bin/aws", nil },
			Exit:          func(int) {},
			ClipboardCopy: func(string) error { return nil },
			TimeNow:       time.Now,
			Stdin:         bytes.NewReader(nil),
			Stdout:        stdoutBuf,
			Stderr:        stderrBuf,
			VersionInfo:   VersionInfo{Version: "test-version", Commit: "test-commit", Date: "test-date"},
		},
		stdout: stdoutBuf,
		stderr: stderrBuf,
	}
}

func TestVersionFlag(t *testing.T) {
	h := newTestHarness()
	exitCalled := false
	h.app.Exit = func(int) { exitCalled = true }
	run(h.app, []string{"sesh", "--version"})
	if out := h.stdout.String(); !strings.Contains(out, "test-version") || !strings.Contains(out, "test-commit") {
		t.Errorf("version output: %s", out)
	}
	if exitCalled {
		t.Error("Exit was called but shouldn't have been")
	}
}

// --help lists every command on a line of its own, grouped, and no option of the old -service command line.
func TestPrintUsage(t *testing.T) {
	h := newTestHarness()
	run(h.app, []string{"sesh", "--help"})
	out := h.stdout.String()
	for _, c := range subcommands {
		if !regexp.MustCompile(`(?m)^  sesh ` + regexp.QuoteMeta(c.value) + `( |$)`).MatchString(out) {
			t.Errorf("--help doesn't list sesh %s", c.value)
		}
	}
	for _, group := range []string{"Everyday:", "Changing entries:", "The vault:", "Locking and keys:", "Setup and more:"} {
		if !strings.Contains(out, group) {
			t.Errorf("--help is missing the group %q", group)
		}
	}
	for _, old := range []string{"--service", "--action", "--list-services", "-rekey"} {
		if strings.Contains(out, old) {
			t.Errorf("--help still mentions %s", old)
		}
	}
	if len(commands) != len(subcommands) {
		t.Errorf("%d commands run, %d are listed", len(commands), len(subcommands))
	}
	for _, c := range subcommands {
		if commands[c.value] == nil {
			t.Errorf("sesh %s is listed but nothing runs it", c.value)
		}
	}
}

// With no terminal, a prompt says what it wanted, and for the master password how to give it without one.
func TestNoTerminalFor(t *testing.T) {
	if err := noTerminalFor("Master password: "); !strings.Contains(err.Error(), "type the master password at") || !strings.Contains(err.Error(), "SESH_MASTER_PASSWORD") || strings.Contains(err.Error(), "locked,") {
		t.Errorf("master password: %v", err)
	}
	if err := noTerminalFor("Create master password: "); !strings.Contains(err.Error(), "choose the new vault's master password") || strings.Contains(err.Error(), "unlocked") {
		t.Errorf("a new vault: %v", err)
	}
	if err := noTerminalFor("Recovery key: "); !strings.Contains(err.Error(), "type the recovery key at") || strings.Contains(err.Error(), "SESH_MASTER_PASSWORD") {
		t.Errorf("recovery key: %v", err)
	}
}

// -h or --help anywhere before "--" asks for a command's usage; help alone only first, since it can name an entry.
func TestAskedForHelp(t *testing.T) {
	for args, want := range map[string]bool{
		"restore 1 --help": true, "github -h": true, "-help": true, "help": true,
		"help me": true, "copy help": false, "github": false, "-- echo --help": false, "--env A=b -- x -h": false, "": false,
	} {
		if got := askedForHelp(strings.Fields(args)); got != want {
			t.Errorf("%q: %v, want %v", args, got, want)
		}
	}
}

// A first word that isn't a command is refused, naming the closest; an old option names the command it became.
func TestRun_NotACommand(t *testing.T) {
	for args, wantSub := range map[string]string{
		"lsit":         `sesh has no command "lsit"; did you mean: sesh list`,
		"frobnicate":   `sesh has no command "frobnicate"; the commands are listed by: sesh --help`,
		"--service":    "sesh has no --service: every kind of entry is in the same commands",
		"-rekey":       "sesh has no --rekey: sesh passwd",
		"--delete":     "sesh has no --delete: sesh trash <entry>",
		"--clip":       "sesh has no --clip: sesh copy <entry>",
		"--frobnicate": `sesh takes a command first, not "--frobnicate"`,
	} {
		h := newTestHarness()
		code := -1
		h.app.Exit = func(c int) { code = c }
		run(h.app, append([]string{"sesh"}, strings.Fields(args)...))
		if code != 1 || !strings.Contains(h.stderr.String(), wantSub) {
			t.Errorf("sesh %s: exit %d, said %q; want %q", args, code, h.stderr.String(), wantSub)
		}
	}
}

// sesh run's command keeps its own -h: run parses its flags, and stops at the command.
func TestRun_RunKeepsTheCommandsHelp(t *testing.T) {
	h := newTestHarness()
	h.app.Exit = func(int) {}
	run(h.app, []string{"sesh", "run", "--env", "K=v", "printf", "-h"})
	if strings.Contains(h.stdout.String(), "Usage: sesh run") || !strings.Contains(h.stderr.String(), "nothing from the vault") {
		t.Errorf("printed %q, %q", h.stdout.String(), h.stderr.String())
	}
	h = newTestHarness()
	run(h.app, []string{"sesh", "run", "--env", "K=v", "--help"})
	if !strings.Contains(h.stdout.String(), "Usage: sesh run") {
		t.Errorf("--help: %q, %q", h.stdout.String(), h.stderr.String())
	}
}

// sesh help is sesh --help; sesh help <command> is that command's.
func TestRun_Help(t *testing.T) {
	if err := checkCommandWord([]string{"sesh", "help"}); err != nil {
		t.Errorf("checkCommandWord: %v", err)
	}
	h := newTestHarness()
	run(h.app, []string{"sesh", "help"})
	if !strings.Contains(h.stdout.String(), "Everyday") {
		t.Errorf("sesh help printed %q, %q", h.stdout.String(), h.stderr.String())
	}
	h = newTestHarness()
	run(h.app, []string{"sesh", "help", "copy"})
	if !strings.HasPrefix(h.stdout.String(), "Usage: sesh copy") {
		t.Errorf("sesh help copy printed %q, %q", h.stdout.String(), h.stderr.String())
	}
}

func TestResolvePasswordPrompt_EnvVarYieldsConstantNonInteractive(t *testing.T) {
	// SESH_MASTER_PASSWORD short-circuits the terminal read with a
	// constant-bytes prompt. Such a prompt cannot meaningfully retry —
	// it would derive the same wrong key N times — so interactive must
	// be false to keep the retry budget off.
	t.Setenv("SESH_MASTER_PASSWORD", "secret-from-env")
	cfg := resolvePasswordPrompt()
	if cfg.interactive {
		t.Error("env-var prompt must not be marked interactive")
	}
	pw, err := cfg.prompt("ignored")
	if err != nil {
		t.Fatalf("env-var prompt should not error: %v", err)
	}
	if string(pw) != "secret-from-env" {
		t.Errorf("env-var prompt returned %q, want %q", pw, "secret-from-env")
	}
}

func TestResolvePasswordPrompt_NonTTYIsTerminalPromptButNotInteractive(t *testing.T) {
	// `go test` runs with stdin not attached to a terminal. We still pick
	// the terminal-read prompt (so a TTY-bound caller would work), but
	// interactive stays false — no retry budget for piped/scripted callers.
	t.Setenv("SESH_MASTER_PASSWORD", "")
	cfg := resolvePasswordPrompt()
	if cfg.interactive {
		t.Error("non-TTY stdin must not be marked interactive")
	}
	if cfg.prompt == nil {
		t.Fatal("prompt callback should be set even when not interactive")
	}
}
