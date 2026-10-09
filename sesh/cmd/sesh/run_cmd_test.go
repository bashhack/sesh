package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/vault"
)

// runVault is a vault with an API key, and a password with a plain and a
// secret field.
func runVault(t *testing.T) {
	t.Helper()
	env := setupRekeyEnv(t)
	useConfigFile(t, "")
	t.Setenv("SESH_MASTER_PASSWORD", "run-password-1234")
	populatePasswordStore(t, env, map[string]string{"api_key/openai": "sk-live-123", "password/db/app": "db-pass-456"})
	store := openDoctorVault(t, env)
	d := vault.Details{Fields: []vault.Field{{Name: "host", Value: []byte("db.internal")}, {Name: "pin", Value: []byte("4321"), Secret: true}}}
	if err := store.SetDetails(vault.Key{Kind: vault.KindPassword, Service: "db", Username: "app"}, &d); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func runRunOut(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	app := agentTestApp()
	err := runRun(app, args)
	return app.Stdout.(*bytes.Buffer).String(), app.Stderr.(*bytes.Buffer).String(), err
}

// The command gets the values in its environment; secrets it prints are
// concealed, on stdout and stderr, and plain values aren't.
func TestRun_SetsAndMasks(t *testing.T) {
	runVault(t)
	out, errOut, err := runRunOut(t, "--env", "KEY=sesh://api_key/openai", "--env", "HOST=sesh://password/db/app#host",
		"--env", "PIN=sesh://password/db/app#pin", "--env", "PLAIN=hello", "--",
		"sh", "-c", `echo "key=$KEY host=$HOST pin=$PIN plain=$PLAIN"; echo "err $KEY" >&2; [ -z "$SESH_MASTER_PASSWORD" ] || echo LEAKED`)
	if err != nil {
		t.Fatal(err)
	}
	if out != "key=<concealed by sesh> host=db.internal pin=<concealed by sesh> plain=hello\n" || errOut != "err <concealed by sesh>\n" {
		t.Errorf("stdout %q, stderr %q", out, errOut)
	}
	out, _, err = runRunOut(t, "--no-masking", "--env", "KEY=sesh://api_key/openai", "--", "sh", "-c", `echo "$KEY"`)
	if err != nil || out != "sk-live-123\n" {
		t.Errorf("--no-masking: %q, %v", out, err)
	}
}

// The env file gives variables, and --env replaces one it sets.
func TestRun_EnvFile(t *testing.T) {
	runVault(t)
	file := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(file, []byte("KEY=sesh://api_key/openai\nHOST=sesh://password/db/app#host\nMODE=file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, err := runRunOut(t, "--no-masking", "--env-file", file, "--env", "MODE=flag", "--", "sh", "-c", `echo "$KEY $HOST $MODE"`)
	if err != nil || out != "sk-live-123 db.internal flag\n" {
		t.Errorf("%q, %v", out, err)
	}
}

// sesh exits as the command does.
func TestRun_ExitStatus(t *testing.T) {
	runVault(t)
	_, _, err := runRunOut(t, "--env", "KEY=sesh://api_key/openai", "--", "sh", "-c", "exit 3")
	var status exitStatus
	if !errors.As(err, &status) || status != 3 {
		t.Errorf("err = %v, want exit status 3", err)
	}
	app := agentTestApp()
	code := 0
	app.Exit = func(c int) { code = c }
	fatal(app, err)
	if code != 3 || app.Stderr.(*bytes.Buffer).Len() != 0 {
		t.Errorf("fatal exited %d, printed %q; want 3 and nothing", code, app.Stderr.(*bytes.Buffer).String())
	}
}

// Nothing runs unless every reference resolves.
func TestRun_Refused(t *testing.T) {
	runVault(t)
	marker := filepath.Join(t.TempDir(), "ran")
	touch := []string{"--", "sh", "-c", "touch " + marker}
	for _, tc := range []struct {
		wantSub string
		args    []string
	}{
		{"name the command to run after --", []string{"--env", "K=sesh://api_key/openai"}},
		{"nothing from the vault to give the command", append([]string{"--env", "K=plain"}, touch...)},
		{"sesh://api_key/nope: entry not found", append([]string{"--env", "K=sesh://api_key/nope"}, touch...)},
		{`sesh://password/db/app#nope: password/db/app has no field "nope"`, append([]string{"--env", "K=sesh://password/db/app#nope"}, touch...)},
		{"can't run no-such-command-xyz", []string{"--env", "K=sesh://api_key/openai", "--", "no-such-command-xyz"}},
		{"--env wants NAME=value", append([]string{"--env", "K"}, touch...)},
	} {
		if _, _, err := runRunOut(t, tc.args...); err == nil || !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("%q: %v, want an error containing %q", tc.args, err, tc.wantSub)
		}
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Error("a command ran though a reference didn't resolve")
	}
}

// Reading values for run is recorded, naming the field read.
func TestRun_Audit(t *testing.T) {
	runVault(t)
	if _, _, err := runRunOut(t, "--env", "PIN=sesh://password/db/app#pin", "--", "true"); err != nil {
		t.Fatal(err)
	}
	app := agentTestApp()
	if err := runAudit(app, []string{"--limit", "1"}); err != nil {
		t.Fatal(err)
	}
	if out := app.Stdout.(*bytes.Buffer).String(); !strings.Contains(out, "db (app) (read field pin, to run)") {
		t.Errorf("audit:\n%s", out)
	}
	if _, _, err := runRunOut(t, "--env", "K=sesh://api_key/openai", "--", "true"); err != nil {
		t.Fatal(err)
	}
	app = agentTestApp()
	if err := runAudit(app, []string{"--limit", "1"}); err != nil {
		t.Fatal(err)
	}
	if out := app.Stdout.(*bytes.Buffer).String(); !strings.Contains(out, "openai (read secret, to run)") {
		t.Errorf("audit:\n%s", out)
	}
}

func runInjectOut(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	app := agentTestApp()
	app.Stdin = strings.NewReader(stdin)
	err := runInject(app, args)
	return app.Stdout.(*bytes.Buffer).String(), err
}

// inject fills the template into a file only its owner can read, replacing
// one already there, or to stdout.
func TestInject(t *testing.T) {
	runVault(t)
	dir := t.TempDir()
	tpl := filepath.Join(dir, "config.tpl")
	out := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(tpl, []byte("key: {{ sesh://api_key/openai }}\nhost: {{sesh://password/db/app#host}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte("old"), 0o644); err != nil { //nolint:gosec // a file to replace
		t.Fatal(err)
	}
	if _, err := runInjectOut(t, "", "-i", tpl, "-o", out); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil || string(b) != "key: sk-live-123\nhost: db.internal\n" {
		t.Errorf("%s = %q, %v", out, b, err)
	}
	if info, err := os.Stat(out); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, %v; want 0600", info.Mode(), err)
	}
	if got, err := runInjectOut(t, "x={{ sesh://api_key/openai }}"); err != nil || got != "x=sk-live-123" {
		t.Errorf("stdout: %q, %v", got, err)
	}
	// A reference that doesn't resolve leaves the file as it was.
	if _, err := runInjectOut(t, "{{ sesh://api_key/nope }}", "-o", out); err == nil || !strings.Contains(err.Error(), "entry not found") {
		t.Errorf("bad ref: %v", err)
	}
	if b, _ := os.ReadFile(out); string(b) != "key: sk-live-123\nhost: db.internal\n" { //nolint:errcheck // compared
		t.Errorf("the file changed: %q", b)
	}
	if _, err := runInjectOut(t, "no refs here"); err == nil || !strings.Contains(err.Error(), "has no {{ sesh://... }} references") {
		t.Errorf("no refs: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 { //nolint:errcheck // counted
		t.Errorf("files left in %s: %v", dir, entries)
	}
}

// sesh exits when the command does, not when a process it left running
// in the background lets go of its output.
func TestRun_DoesntWaitForBackgroundProcesses(t *testing.T) {
	runVault(t)
	start := time.Now()
	out, _, err := runRunOut(t, "--env", "K=sesh://api_key/openai", "--", "sh", "-c", "echo hi; sleep 10 &")
	if err != nil || out != "hi\n" {
		t.Fatalf("%q, %v", out, err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("sesh run took %v, waiting on the background sleep", d)
	}
}

// slowWriter takes its time before its first write, as a paused terminal
// or a pager does.
type slowWriter struct {
	bytes.Buffer
	delay time.Duration
	once  bool
}

func (w *slowWriter) Write(p []byte) (int, error) {
	if !w.once {
		w.once = true
		time.Sleep(w.delay)
	}
	return w.Buffer.Write(p)
}

// Output the command wrote before exiting all arrives, however slowly
// it's read: here the command finishes while the reader is stalled.
func TestRun_SlowReaderGetsEverything(t *testing.T) {
	runVault(t)
	app := agentTestApp()
	out := &slowWriter{delay: 3 * time.Second}
	app.Stdout = out
	if err := runRun(app, []string{"--env", "K=sesh://api_key/openai", "--", "seq", "1", "10000"}); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(out.String(), "\n"); lines != 10000 {
		t.Errorf("%d lines, want 10000", lines)
	}
}

// A Ctrl-C sent to sesh alone, not from its terminal, is passed on; a
// command killed by a signal ends sesh the same way.
func TestRun_Signals(t *testing.T) {
	runVault(t)
	old := fromTerminal
	t.Cleanup(func() { fromTerminal = old })
	fromTerminal = func() bool { return false }
	started := filepath.Join(t.TempDir(), "started")
	errc := make(chan error, 1)
	go func() {
		_, _, err := runRunOut(t, "--env", "K=sesh://api_key/openai", "--", "sh", "-c",
			`trap 'exit 4' INT; touch `+started+`; sleep 10 & wait`)
		errc <- err
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the command never started")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if status, ok := errors.AsType[exitStatus](err); !ok || status != 4 {
			t.Errorf("err = %v, want exit status 4 from the command's trap", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the Ctrl-C wasn't passed on")
	}

	_, _, err := runRunOut(t, "--env", "K=sesh://api_key/openai", "--", "sh", "-c", "kill -TERM $$")
	if sig, ok := errors.AsType[killedBy](err); !ok || syscall.Signal(sig) != syscall.SIGTERM {
		t.Errorf("err = %v, want killed by SIGTERM", err)
	}
	// A signal Go itself turns into a crash dump is an exit status instead.
	for _, sig := range []string{"QUIT", "SEGV", "ABRT"} {
		_, _, err := runRunOut(t, "--env", "K=sesh://api_key/openai", "--", "sh", "-c", "kill -"+sig+" $$")
		if status, ok := errors.AsType[exitStatus](err); !ok || status <= 128 {
			t.Errorf("killed by %s: err = %v (%T), want an exit status over 128", sig, err, err)
		}
	}
}

// inject refuses to write over its own template, fills a reference however
// it's written, and refuses what it can't do in full.
func TestInject_Refused(t *testing.T) {
	runVault(t)
	dir := t.TempDir()
	tpl := filepath.Join(dir, "c.tpl")
	if err := os.WriteFile(tpl, []byte("k: {{ sesh://api_key/openai }}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runInjectOut(t, "", "-i", tpl, "-o", filepath.Join(dir, ".", "c.tpl")); err == nil || !strings.Contains(err.Error(), "is the template itself") {
		t.Errorf("-o the template: %v", err)
	}
	if b, _ := os.ReadFile(tpl); !strings.Contains(string(b), "sesh://") { //nolint:errcheck // compared
		t.Errorf("the template was overwritten: %q", b)
	}
	if got, err := runInjectOut(t, "k={{ sesh://api_key/openai/ }}"); err != nil || got != "k=sk-live-123" {
		t.Errorf("a trailing slash: %q, %v", got, err)
	}
	if _, err := runInjectOut(t, "{{ sesh://api_key/openai }}"+strings.Repeat("x", 16<<20)); err == nil || !strings.Contains(err.Error(), "over 16 MiB") {
		t.Errorf("a big template: %v", err)
	}
	if _, err := runInjectOut(t, "{{ sesh://api_key/openai }}", "-o", dir); err == nil || !strings.Contains(err.Error(), "is a folder") {
		t.Errorf("-o a folder: %v", err)
	}
	app := agentTestApp()
	app.StdinIsTerminal = func() bool { return true }
	if err := runInject(app, nil); err == nil || !strings.Contains(err.Error(), "give the template with -i, or pipe it in") {
		t.Errorf("no template at a terminal: %v", err)
	}
}

// A process left behind that holds both outputs, or keeps writing, doesn't
// keep sesh open: it stops after waiting a second in all.
func TestRun_LeftoverProcesses(t *testing.T) {
	runVault(t)
	for name, script := range map[string]string{
		"quiet, holding both": "echo hi; sleep 10 &",
		"chatty":              "(while :; do echo tick; sleep 0.3; done) & echo hi",
	} {
		start := time.Now()
		if _, _, err := runRunOut(t, "--env", "K=sesh://api_key/openai", "--", "sh", "-c", script); err != nil {
			t.Fatal(err)
		}
		if d := time.Since(start); d > 1800*time.Millisecond {
			t.Errorf("%s: sesh run took %v", name, d)
		}
	}
	_ = exec.Command("pkill", "-f", "while :; do echo tick").Run() //nolint:errcheck // cleanup
}
