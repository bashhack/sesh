package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/bashhack/sesh/internal/agent"
	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/touchid"
	"github.com/bashhack/sesh/internal/tui"
	"github.com/bashhack/sesh/internal/vault"
)

// sesh ui needs a terminal, and takes no arguments.
func TestUI_Refuses(t *testing.T) {
	filingVault(t)
	app := agentTestApp()
	if err := runUI(app, nil); err == nil || !strings.Contains(err.Error(), "sesh ui needs a terminal") {
		t.Errorf("without a terminal: %v", err)
	}
	if err := runUI(app, []string{"x"}); err == nil || !strings.Contains(err.Error(), `takes no arguments, got "x"`) {
		t.Errorf("with an argument: %v", err)
	}
	if out := mustRun(t, runUI, "--help"); !strings.Contains(out, "sesh ui    Search every entry") {
		t.Errorf("help: %q", out)
	}
}

// The vault as the app reads it: every entry for no query, sesh's search
// otherwise; a secret read is audited, a code's key isn't; a change by
// another command is seen.
func TestUI_Vault(t *testing.T) {
	filingVault(t)
	putSecrets(t, vault.Key{Kind: vault.KindTOTP, Service: "github", Username: "alice"}, "JBSWY3DPEHPK3PXP")
	store, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	u := newUIVault(store)
	defer u.Close() //nolint:errcheck // test cleanup
	all, err := u.Search("")
	if err != nil || len(all) != 5 {
		t.Fatalf("Search(\"\") = %d entries, %v", len(all), err)
	}
	found, err := u.Search("git")
	var names []string
	for _, e := range found {
		names = append(names, e.Key.String())
	}
	slices.Sort(names)
	if err != nil || strings.Join(names, " ") != "password/github/alice password/gitlab totp/github/alice" {
		t.Errorf("Search(git) = %q, %v", names, err)
	}
	accesses := func() int { return strings.Count(mustRun(t, runAudit), "access") }
	before := accesses()
	if key, err := u.CodeKey(vault.Key{Kind: vault.KindTOTP, Service: "github", Username: "alice"}); err != nil || string(key) != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("CodeKey = %q, %v", key, err)
	}
	if n := accesses(); n != before {
		t.Errorf("reading a code's key logged an access: %d → %d", before, n)
	}
	if secret, err := u.Secret(vault.Key{Kind: vault.KindPassword, Service: "gitlab"}, "in sesh ui, to copy it"); err != nil || string(secret) != "b" {
		t.Fatalf("Secret = %q, %v", secret, err)
	}
	if log := mustRun(t, runAudit); !strings.Contains(log, "read in sesh ui, to copy it") {
		t.Errorf("audit:\n%s", log)
	}
	if changed, err := u.Check(); changed || err != nil {
		t.Errorf("Check with no change = %v, %v", changed, err)
	}
	putSecrets(t, vault.Key{Kind: vault.KindPassword, Service: "new"}, "x")
	if changed, err := u.Check(); !changed || err != nil {
		t.Errorf("Check after another store = %v, %v", changed, err)
	}
	if changed, err := u.Check(); changed || err != nil {
		t.Errorf("Check again = %v, %v", changed, err)
	}
	// A change before the first check is seen too.
	v2 := newUIVault(store)
	putSecrets(t, vault.Key{Kind: vault.KindPassword, Service: "newer"}, "x")
	if changed, err := v2.Check(); !changed || err != nil {
		t.Errorf("first Check after a change = %v, %v", changed, err)
	}
	if err := uiLocked(database.ErrVaultKeyChanged); !errors.Is(err, tui.ErrLocked) || !strings.Contains(err.Error(), "master password was changed") {
		t.Errorf("uiLocked(ErrVaultKeyChanged) = %v", err)
	}
}

// syncBuffer is a buffer written by one goroutine and read by another.
type syncBuffer struct {
	b  bytes.Buffer
	mu sync.Mutex
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// waitFor waits until cond holds, for at most a few seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// The app runs: typing searches, Enter copies, Ctrl-C quits, and the copy
// is in the audit log.
func TestUI_Run(t *testing.T) {
	filingVault(t)
	oldTerm, oldOpts := uiStdoutIsTerminal, uiProgramOptions
	t.Cleanup(func() { uiStdoutIsTerminal, uiProgramOptions = oldTerm, oldOpts })
	uiStdoutIsTerminal = func(io.Writer) bool { return true }
	uiProgramOptions = []tea.ProgramOption{tea.WithWindowSize(80, 24)}
	in, keys := io.Pipe()
	out := &syncBuffer{}
	app := agentTestApp()
	app.Stdin, app.Stdout = in, out
	app.StdinIsTerminal = func() bool { return true }
	copied := make(chan string, 1)
	app.ClipboardCopy = func(s string) error { copied <- s; return nil }
	done := make(chan error, 1)
	go func() { done <- runUI(app, nil) }()
	send := func(k string) {
		if _, err := keys.Write([]byte(k)); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "every entry", func() bool { return strings.Contains(out.String(), "4 entries") })
	send("gitl")
	waitFor(t, "the search", func() bool { return strings.Contains(out.String(), "1 entry") })
	send("\r")
	select {
	case got := <-copied:
		if got != "b" {
			t.Errorf("copied %q, want gitlab's secret", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nothing copied")
	}
	send("\x03")
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("sesh ui didn't quit")
	}
	// It drew on the alternate screen, and left it.
	if o := out.String(); strings.LastIndex(o, "\x1b[?1049l") < strings.Index(o, "\x1b[?1049h") || !strings.Contains(o, "\x1b[?1049h") {
		t.Errorf("the alternate screen wasn't entered and left:\n%q", o)
	}
	if log := mustRun(t, runAudit); !strings.Contains(log, "read in sesh ui, to copy it") {
		t.Errorf("audit:\n%s", log)
	}
}

// Unlocking again checks the password even while the agent is unlocked;
// an agent that locks is seen by Check and KeepAlive; a vault removed
// meanwhile isn't made again.
func TestUI_AgentLockAndUnlockAgain(t *testing.T) {
	dir := t.TempDir()
	writeLightVault(t, dir, "correct-horse")
	startTestAgent(t)
	useConfigFile(t, "")
	t.Setenv("SESH_MASTER_PASSWORD", "")
	t.Setenv(config.EnvDBPath, vaultIn(dir))
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopenWith(cfg, []byte("correct-horse")); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if _, err := reopenWith(cfg, []byte("not-the-password")); !errors.Is(err, tui.ErrWrongPassword) {
		t.Errorf("a wrong password with the agent unlocked: %v", err)
	}
	store, err := reopenWith(cfg, []byte("correct-horse"))
	if err != nil {
		t.Fatal(err)
	}
	u := newUIVault(store)
	defer u.Close() //nolint:errcheck // test cleanup
	if _, err := u.Check(); err != nil {
		t.Fatalf("Check while unlocked: %v", err)
	}
	if err := u.KeepAlive(); err != nil {
		t.Fatalf("KeepAlive while unlocked: %v", err)
	}
	conn, err := agent.EnsureAgent()
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Lock(conn); err != nil {
		t.Fatal(err)
	}
	conn.Close() //nolint:errcheck,gosec // test cleanup
	if _, err := u.Check(); !errors.Is(err, tui.ErrLocked) || err.Error() != "sesh's agent locked." {
		t.Errorf("Check once the agent locked: %v", err)
	}
	if err := u.KeepAlive(); !errors.Is(err, tui.ErrLocked) {
		t.Errorf("KeepAlive once the agent locked: %v", err)
	}
	if err := os.Remove(vaultIn(dir)); err != nil {
		t.Fatal(err)
	}
	if _, err := reopenWith(cfg, []byte("correct-horse")); err == nil || !strings.Contains(err.Error(), "the vault is gone") {
		t.Errorf("unlocking a removed vault: %v", err)
	}
	if _, err := os.Stat(vaultIn(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the vault was made again: %v", err)
	}
}

// What's written to stderr while the app runs comes out after it.
func TestUI_HoldStderr(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	was := os.Stderr
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = was })
	restore := holdStderr()
	fmt.Fprint(os.Stderr, "warning: held") //nolint:errcheck // test
	if os.Stderr == w {
		t.Fatal("stderr wasn't held")
	}
	restore()
	w.Close() //nolint:errcheck,gosec // test
	got, _ := io.ReadAll(r)
	if string(got) != "warning: held" || os.Stderr != w {
		t.Errorf("after: %q (stderr restored %v)", got, os.Stderr == w)
	}
}

// Unlocking again with Touch ID asks for the fingerprint even while the
// agent is unlocked; one refused doesn't unlock.
func TestUI_TouchIDAgainWhileAgentUnlocked(t *testing.T) {
	startTestAgent(t)
	prompts, fail := softwareTouchID(t)
	dbPath := createVaultWithTouchID(t)
	if !touchIDSetUp(dbPath) {
		t.Fatal("Touch ID unlock isn't seen as set up")
	}
	oracle, err := buildKeySourceWith(dbPath, interactivePrompt(t))
	if err != nil {
		t.Fatal(err)
	}
	closeKeySource(t, oracle)
	*fail = touchid.ErrCancelled
	if store, err := reopenWithTouchID(dbPath); err == nil {
		store.Close() //nolint:errcheck,gosec // test cleanup
		t.Error("a refused fingerprint unlocked the app while the agent was unlocked")
	}
	if *prompts != 2 {
		t.Errorf("Touch ID prompts = %d, want 2: the app's unlock didn't ask", *prompts)
	}
	*fail = nil
	store, err := reopenWithTouchID(dbPath)
	if err != nil {
		t.Fatalf("a fingerprint given: %v", err)
	}
	store.Close() //nolint:errcheck,gosec // test cleanup
}
