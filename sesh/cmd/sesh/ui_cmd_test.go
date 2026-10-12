package main

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/database"
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
	if changed, err := u.Changed(); changed || err != nil {
		t.Errorf("first Changed = %v, %v", changed, err)
	}
	putSecrets(t, vault.Key{Kind: vault.KindPassword, Service: "new"}, "x")
	if changed, err := u.Changed(); !changed || err != nil {
		t.Errorf("Changed after another store = %v, %v", changed, err)
	}
	if err := uiLocked(database.ErrVaultKeyChanged); !errors.Is(err, tui.ErrLocked) || !strings.Contains(err.Error(), "master password was changed") {
		t.Errorf("uiLocked(ErrVaultKeyChanged) = %v", err)
	}
}

// The app runs: typing searches, Enter copies, Ctrl-C quits, and the copy
// is in the audit log.
func TestUI_Run(t *testing.T) {
	filingVault(t)
	in, keys := io.Pipe()
	app := agentTestApp()
	app.Stdin = in
	app.StdinIsTerminal = func() bool { return true }
	var copied []string
	app.ClipboardCopy = func(s string) error { copied = append(copied, s); return nil }
	done := make(chan error, 1)
	go func() { done <- runUI(app, nil) }()
	// Each step waits for the app to have handled the last.
	for _, k := range []string{"gitl", "\r", "\x03"} {
		time.Sleep(300 * time.Millisecond)
		if _, err := keys.Write([]byte(k)); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("sesh ui didn't quit")
	}
	if len(copied) != 1 || copied[0] != "b" {
		t.Errorf("copied %q, want gitlab's secret", copied)
	}
	// It drew on the alternate screen, and left it.
	if out := app.Stdout.(*bytes.Buffer).String(); strings.LastIndex(out, "\x1b[?1049l") < strings.Index(out, "\x1b[?1049h") || !strings.Contains(out, "\x1b[?1049h") {
		t.Errorf("the alternate screen wasn't entered and left:\n%q", out)
	}
	if log := mustRun(t, runAudit); !strings.Contains(log, "read in sesh ui, to copy it") {
		t.Errorf("audit:\n%s", log)
	}
}
