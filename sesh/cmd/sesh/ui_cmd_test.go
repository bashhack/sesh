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

	"github.com/charmbracelet/x/ansi"

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
	all, total, err := u.Search("")
	if err != nil || len(all) != 5 || total != 5 {
		t.Fatalf("Search(\"\") = %d entries, %v", len(all), err)
	}
	found, _, err := u.Search("git")
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
	if err := uiLocked(database.ErrVaultKeyChanged); !errors.Is(err, tui.ErrLocked) || !strings.Contains(err.Error(), "changed the master password") {
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
	// What the screen shows, as the app draws it: the renderer writes only
	// what changed, so the output can't be searched for whole words. The
	// filter runs on the program's own loop, before each message.
	var screen syncBuffer
	uiProgramOptions = []tea.ProgramOption{tea.WithWindowSize(80, 24), tea.WithFilter(func(m tea.Model, msg tea.Msg) tea.Msg {
		if v, ok := m.(interface{ View() tea.View }); ok {
			screen.mu.Lock()
			screen.b.Reset()
			screen.b.WriteString(ansi.Strip(v.View().Content))
			screen.mu.Unlock()
		}
		return msg
	})}
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
	waitFor(t, "every entry", func() bool { return strings.Contains(screen.String(), "4 entries") })
	send("gitl")
	waitFor(t, "the search", func() bool { return strings.Contains(screen.String(), "1 of 4") })
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
	// Settings other than the defaults, so a store given the defaults shows.
	t.Setenv(config.EnvTrashKeepDays, "7")
	t.Setenv(config.EnvHistoryKeep, "4")
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
	if store.HistoryKeep() != cfg.HistoryKeep.Value || store.TrashDays() != cfg.TrashKeepDays.Value || store.TrashDays() == 0 {
		t.Errorf("unlocked again keeping %d earlier secrets and %d days of trash; want %d and %d",
			store.HistoryKeep(), store.TrashDays(), cfg.HistoryKeep.Value, cfg.TrashKeepDays.Value)
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
	if _, err := u.Check(); !errors.Is(err, tui.ErrLocked) || err.Error() != "sesh's agent locked the vault." {
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
	useConfigFile(t, "")
	t.Setenv(config.EnvDBPath, dbPath)
	t.Setenv(config.EnvTrashKeepDays, "7")
	t.Setenv(config.EnvHistoryKeep, "4")
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	if !touchIDSetUp(dbPath) {
		t.Fatal("Touch ID unlock isn't seen as set up")
	}
	oracle, err := buildKeySourceWith(dbPath, interactivePrompt(t))
	if err != nil {
		t.Fatal(err)
	}
	closeKeySource(t, oracle)
	*fail = touchid.ErrCancelled
	if store, err := reopenWithTouchID(cfg); err == nil {
		store.Close() //nolint:errcheck,gosec // test cleanup
		t.Error("a refused fingerprint unlocked the app while the agent was unlocked")
	}
	if *prompts != 2 {
		t.Errorf("Touch ID prompts = %d, want 2: the app's unlock didn't ask", *prompts)
	}
	*fail = nil
	store, err := reopenWithTouchID(cfg)
	if err != nil {
		t.Fatalf("a fingerprint given: %v", err)
	}
	if store.HistoryKeep() != cfg.HistoryKeep.Value || store.TrashDays() != cfg.TrashKeepDays.Value || store.TrashDays() == 0 {
		t.Errorf("unlocked with Touch ID keeping %d earlier secrets and %d days of trash", store.HistoryKeep(), store.TrashDays())
	}
	store.Close() //nolint:errcheck,gosec // test cleanup
}

// Notes, a secure note's text, and secret fields are read for the app,
// each recorded in the audit log.
func TestUI_NotesAndSecretFields(t *testing.T) {
	filingVault(t)
	store, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	gh := vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}
	note := vault.Key{Kind: vault.KindNote, Service: "wifi"}
	d := vault.Details{Notes: []byte("recovery codes in the safe"), Fields: []vault.Field{
		{Name: "pin", Value: []byte("4321"), Secret: true}, {Name: "email", Value: []byte("a@example.com")},
	}}
	if err := store.SaveWithDetails(&vault.Entry{Key: gh}, []byte("a"), &d); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(note, []byte("ssid home")); err != nil {
		t.Fatal(err)
	}
	u := newUIVault(store)
	defer u.Close() //nolint:errcheck // test cleanup
	if got, err := u.Notes(gh); err != nil || string(got) != "recovery codes in the safe" {
		t.Errorf("Notes = %q, %v", got, err)
	}
	if got, err := u.Notes(note); err != nil || string(got) != "ssid home" {
		t.Errorf("a secure note's Notes = %q, %v", got, err)
	}
	if got, err := u.SecretFields(gh); err != nil || len(got) != 1 || got[0].Name != "pin" || string(got[0].Value) != "4321" {
		t.Errorf("SecretFields = %+v, %v", got, err)
	}
	log := mustRun(t, runAudit)
	for _, want := range []string{"in sesh ui, to show its notes", "in sesh ui, to show it", "in sesh ui, to reveal its fields"} {
		if !strings.Contains(log, want) {
			t.Errorf("audit missing %q:\n%s", want, log)
		}
	}
}

// Only web addresses are opened; a bare host gets https://.
func TestUI_OpenURL(t *testing.T) {
	old := startBrowser
	t.Cleanup(func() { startBrowser = old })
	var opened []string
	startBrowser = func(a string) error { opened = append(opened, a); return nil }
	for in, want := range map[string]string{
		"github.com":                "https://github.com",
		"http://192.168.1.1/admin":  "http://192.168.1.1/admin",
		"https://example.com/a?b=c": "https://example.com/a?b=c",
	} {
		opened = nil
		if err := openURL(in); err != nil || len(opened) != 1 || opened[0] != want {
			t.Errorf("openURL(%q) opened %q, %v; want %q", in, opened, err, want)
		}
	}
	for _, in := range []string{"file:///etc/passwd", "javascript:alert(1)", "ssh://host", "https://"} {
		opened = nil
		if err := openURL(in); err == nil || len(opened) != 0 {
			t.Errorf("openURL(%q) opened %q, %v", in, opened, err)
		}
	}
}

// With nothing searched, the entries read most recently come first; the
// app's own reads for showing an entry don't count.
func TestUI_RecentFirst(t *testing.T) {
	filingVault(t)
	store, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	u := newUIVault(store)
	defer u.Close() //nolint:errcheck // test cleanup
	gitlab := vault.Key{Kind: vault.KindPassword, Service: "gitlab"}
	bank := vault.Key{Kind: vault.KindPassword, Service: "My Bank"}
	if _, err := u.Secret(gitlab, "in sesh ui, to copy it"); err != nil {
		t.Fatal(err)
	}
	if _, err := u.Secret(bank, "in sesh ui, to copy it"); err != nil {
		t.Fatal(err)
	}
	if _, err := u.Secret(gitlab, "in sesh ui, to reveal it"); err != nil {
		t.Fatal(err)
	}
	all, _, err := u.Search("")
	if err != nil || len(all) < 3 || all[0].Key != bank || all[1].Key != gitlab {
		var got []string
		for _, e := range all {
			got = append(got, e.Key.String())
		}
		t.Errorf("order = %q, %v; want My Bank, then gitlab, first", got, err)
	}
}

// Another window's reads (audit events) aren't changes; a store is.
func TestUI_CheckIgnoresAuditOnly(t *testing.T) {
	filingVault(t)
	open := func() *uiVault {
		store, err := openSQLiteStore()
		if err != nil {
			t.Fatal(err)
		}
		u := newUIVault(store)
		t.Cleanup(func() { u.Close() }) //nolint:errcheck,gosec // test cleanup
		return u
	}
	one, other := open(), open()
	if _, err := other.Notes(vault.Key{Kind: vault.KindPassword, Service: "gitlab"}); err != nil {
		t.Fatal(err)
	}
	if changed, err := one.Check(); changed || err != nil {
		t.Errorf("Check after another window's read = %v, %v; want no change", changed, err)
	}
	putSecrets(t, vault.Key{Kind: vault.KindPassword, Service: "new"}, "x")
	if changed, err := one.Check(); !changed || err != nil {
		t.Errorf("Check after a store = %v, %v; want a change", changed, err)
	}
}

// The actions' reads and writes on a real vault: a secret field and an
// earlier secret read (audited), a restore, the trash round trip, a name
// clash on restore; the app's own writes aren't another command's change.
func TestUI_Actions(t *testing.T) {
	filingVault(t)
	gh := vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}
	store, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	d := vault.Details{Fields: []vault.Field{{Name: "pin", Value: []byte("4321"), Secret: true}}}
	if err := store.SaveWithDetails(&vault.Entry{Key: gh}, []byte("a2"), &d); err != nil {
		t.Fatal(err)
	}
	u := newUIVault(store)
	defer u.Close() //nolint:errcheck // test cleanup
	if v, err := u.Field(gh, "pin"); err != nil || string(v) != "4321" {
		t.Errorf("Field = %q, %v", v, err)
	}
	if h, err := u.History(gh); err != nil || len(h) != 1 {
		t.Fatalf("History = %v, %v", h, err)
	}
	if v, err := u.ReadVersion(gh, 2); err != nil || string(v) != "a" {
		t.Errorf("ReadVersion = %q, %v", v, err)
	}
	if err := u.RestoreVersion(gh, 2); err != nil {
		t.Fatal(err)
	}
	if v, err := u.Secret(gh, "test"); err != nil || string(v) != "a" {
		t.Errorf("after restore = %q, %v", v, err)
	}
	if err := u.Delete(gh); err != nil {
		t.Fatal(err)
	}
	trash, err := u.Trash()
	if err != nil || len(trash) != 1 || trash[0].Key != gh {
		t.Fatalf("Trash = %+v, %v", trash, err)
	}
	if changed, err := u.Check(); changed || err != nil {
		t.Errorf("Check after the app's own writes = %v, %v; want no change", changed, err)
	}
	putSecrets(t, gh, "someone else's")
	if _, err := u.RestoreFromTrash(trash[0].ID); !errors.Is(err, tui.ErrNameTaken) || !strings.Contains(err.Error(), "--as <new name>") {
		t.Errorf("restore onto a name in use: %v", err)
	}
	if err := u.RemoveFromTrash(trash[0].ID); err != nil {
		t.Fatal(err)
	}
	if trash, err := u.Trash(); err != nil || len(trash) != 0 {
		t.Errorf("trash after removing = %+v, %v", trash, err)
	}
	log := mustRun(t, runAudit)
	for _, want := range []string{"in sesh ui, to copy or show its field pin", "in sesh ui, to copy it"} {
		if !strings.Contains(log, want) {
			t.Errorf("audit missing %q:\n%s", want, log)
		}
	}
}

// The app's own write doesn't hide a change another command made just
// before it; with no agent running, there's none to lock.
func TestUI_OwnWriteKeepsOthersChange(t *testing.T) {
	filingVault(t)
	store, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	u := newUIVault(store)
	defer u.Close() //nolint:errcheck // test cleanup
	if changed, err := u.Check(); changed || err != nil {
		t.Fatalf("Check = %v, %v", changed, err)
	}
	putSecrets(t, vault.Key{Kind: vault.KindPassword, Service: "gitlab"}, "changed elsewhere")
	if err := u.Delete(vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}); err != nil {
		t.Fatal(err)
	}
	if changed, err := u.Check(); !changed || err != nil {
		t.Errorf("Check after another command's change and the app's own write = %v, %v; want a change", changed, err)
	}
	t.Setenv("SESH_AUTH_SOCK", tempAgentSocket(t))
	if err := lockAgent(); err != nil {
		t.Errorf("lockAgent with no agent running: %v", err)
	}
}

// Save on a real vault: an entry added, a TOTP entry from an otpauth://
// link with its settings, a name that's taken, and an edit of name, notes,
// fields, folder and tags.
func TestUI_Save(t *testing.T) {
	filingVault(t)
	store, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	u := newUIVault(store)
	defer u.Close() //nolint:errcheck // test cleanup
	site := vault.Key{Kind: vault.KindPassword, Service: "site", Username: "me"}
	url, folder := "https://site.example", "work"
	if _, err := u.Save(&tui.Change{To: site, Secret: []byte("pw-1"), URL: &url, Folder: &folder, Tags: []string{"a"}, TagsSet: true,
		SetFields: []vault.Field{{Name: "pin", Value: []byte("4321"), Secret: true}}}); err != nil {
		t.Fatal(err)
	}
	e, err := store.Lookup(site)
	if err != nil || e.URL != url || e.Folder != folder || strings.Join(e.Tags, ",") != "a" || len(e.Fields) != 1 {
		t.Errorf("added = %+v, %v", e, err)
	}
	if _, err := u.Save(&tui.Change{To: site, Secret: []byte("again")}); !errors.Is(err, tui.ErrNameTaken) {
		t.Errorf("adding a name that's taken: %v", err)
	}
	code := vault.Key{Kind: vault.KindTOTP, Service: "site", Username: "me"}
	link := "otpauth://totp/Site:me?secret=JBSWY3DPEHPK3PXP&issuer=Site&algorithm=SHA256&digits=8&period=60"
	if _, err := u.Save(&tui.Change{To: code, Secret: []byte(link)}); err != nil {
		t.Fatal(err)
	}
	if key, err := store.Get(code); err != nil || string(key) != "JBSWY3DPEHPK3PXP" {
		t.Errorf("TOTP key = %q, %v", key, err)
	}
	if c, err := store.Lookup(code); err != nil || c.Settings.TOTP.Digits != 8 || c.Settings.TOTP.Period != 60 || c.Settings.TOTP.Algorithm != "SHA256" {
		t.Errorf("TOTP settings = %+v, %v", c.Settings.TOTP, err)
	}
	if _, err := u.Save(&tui.Change{To: vault.Key{Kind: vault.KindTOTP, Service: "bad"}, Secret: []byte("not base32!")}); err == nil {
		t.Error("a TOTP key that isn't one was saved")
	}

	renamed := vault.Key{Kind: vault.KindPassword, Service: "site2", Username: "me"}
	folder2 := ""
	k, err := u.Save(&tui.Change{Key: site, To: renamed, Notes: []byte("new notes"), SetNotes: true, NotesBase: nil,
		SetFields: []vault.Field{{Name: "email", Value: []byte("me@example.com")}}, RemoveFields: []string{"pin"},
		Folder: &folder2, Tags: []string{"b", "c"}, TagsSet: true})
	if err != nil || k != renamed {
		t.Fatalf("edit = %v, %v", k, err)
	}
	e, err = store.Lookup(renamed)
	if err != nil || e.Folder != "" || strings.Join(e.Tags, ",") != "b,c" || len(e.Fields) != 1 || e.Fields[0].Name != "email" || !e.HasNotes {
		t.Errorf("edited = %+v, %v", e, err)
	}
	if secret, err := store.Get(renamed); err != nil || string(secret) != "pw-1" {
		t.Errorf("the secret after a rename = %q, %v", secret, err)
	}
	// Notes changed by another command meanwhile are not written over.
	if _, err := u.Save(&tui.Change{Key: renamed, To: renamed, Notes: []byte("mine"), SetNotes: true, NotesBase: []byte("what I saw")}); err == nil {
		t.Error("notes written over ones that changed meanwhile")
	}
	if changed, err := u.Check(); changed || err != nil {
		t.Errorf("Check after the app's own saves = %v, %v", changed, err)
	}
}

// fieldsOf is k's fields as "name=value" (a secret one "name=*value"), in order.
func fieldsOf(t *testing.T, store *database.Store, k vault.Key) string {
	t.Helper()
	d, err := store.Details(k, "a test")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range d.Fields {
		mark := ""
		if f.Secret {
			mark = "*"
		}
		out = append(out, f.Name+"="+mark+string(f.Value))
	}
	return strings.Join(out, " ")
}

// A form's field renames, swaps and re-adds leave the fields the form showed.
func TestUI_SaveFieldRenames(t *testing.T) {
	filingVault(t)
	store, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	u := newUIVault(store)
	defer u.Close() //nolint:errcheck // test cleanup
	site := vault.Key{Kind: vault.KindPassword, Service: "site", Username: "me"}
	if _, err := u.Save(&tui.Change{To: site, Secret: []byte("pw-1"), SetFields: []vault.Field{
		{Name: "email", Value: []byte("a@b")}, {Name: "other", Value: []byte("o")}, {Name: "pin", Value: []byte("4321"), Secret: true},
	}}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		why, want string
		change    tui.Change
	}{
		{"a rename that only changes case", "other=o pin=*4321 Email=a@b",
			tui.Change{RemoveFields: []string{"email"}, SetFields: []vault.Field{{Name: "Email", Value: []byte("a@b")}}}},
		{"a field removed and added again", "pin=*4321 Email=a@b other=new",
			tui.Change{RemoveFields: []string{"other"}, SetFields: []vault.Field{{Name: "other", Value: []byte("new")}}}},
		{"two names swapped", "pin=*4321 other=a@b Email=new",
			tui.Change{RemoveFields: []string{"Email", "other"}, SetFields: []vault.Field{{Name: "other", Value: []byte("a@b")}, {Name: "Email", Value: []byte("new")}}}},
		{"a secret field made plain", "other=a@b Email=new pin=4321",
			tui.Change{RemoveFields: []string{"pin"}, SetFields: []vault.Field{{Name: "pin", Value: []byte("4321")}}}},
	} {
		c.change.Key, c.change.To = site, site
		if _, err := u.Save(&c.change); err != nil {
			t.Fatalf("%s: %v", c.why, err)
		}
		if got := fieldsOf(t, store, site); got != c.want {
			t.Errorf("%s: fields %q, want %q", c.why, got, c.want)
		}
	}
}

// A save one part of which is refused changes nothing.
func TestUI_SaveIsAllOrNothing(t *testing.T) {
	filingVault(t)
	store, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	u := newUIVault(store)
	defer u.Close() //nolint:errcheck // test cleanup
	site := vault.Key{Kind: vault.KindPassword, Service: "site", Username: "me"}
	if _, err := u.Save(&tui.Change{To: site, Secret: []byte("pw-1"), Tags: []string{"old"}, TagsSet: true}); err != nil {
		t.Fatal(err)
	}
	to := vault.Key{Kind: vault.KindPassword, Service: "site2", Username: "me"}
	badFolder := "work/"
	for why, c := range map[string]*tui.Change{
		"a tag with a space": {Key: site, To: to, Secret: []byte("pw-2"), Tags: []string{"a", "work prod"}, TagsSet: true},
		"a folder refused":   {Key: site, To: site, Secret: []byte("pw-2"), Folder: &badFolder},
	} {
		if _, err := u.Save(c); err == nil {
			t.Fatalf("%s: saved", why)
		}
		e, err := store.Lookup(site)
		if err != nil || strings.Join(e.Tags, ",") != "old" || e.Folder != "" {
			t.Errorf("%s: the entry is now %+v, %v", why, e, err)
		}
		if pw, err := store.Get(site); err != nil || string(pw) != "pw-1" {
			t.Errorf("%s: its secret is now %q, %v", why, pw, err)
		}
	}
	// And one that's fine does all of it.
	folder := "work"
	if _, err := u.Save(&tui.Change{Key: site, To: to, Secret: []byte("pw-2"), Folder: &folder, Tags: []string{"a"}, TagsSet: true}); err != nil {
		t.Fatal(err)
	}
	e, err := store.Lookup(to)
	if err != nil || strings.Join(e.Tags, ",") != "a" || e.Folder != "work" {
		t.Errorf("saved = %+v, %v", e, err)
	}
	if _, err := u.Save(&tui.Change{Key: to, To: to, Tags: nil, TagsSet: true}); err != nil {
		t.Fatal(err)
	}
	if e, err := store.Lookup(to); err != nil || len(e.Tags) != 0 {
		t.Errorf("tags cleared = %+v, %v", e.Tags, err)
	}
}

// A TOTP key from a link must be a usable key; a key alone on an edit makes
// the usual codes, whatever the key before it made.
func TestUI_SaveTOTPKeys(t *testing.T) {
	filingVault(t)
	store, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	u := newUIVault(store)
	defer u.Close() //nolint:errcheck // test cleanup
	code := vault.Key{Kind: vault.KindTOTP, Service: "site", Username: "me"}
	if _, err := u.Save(&tui.Change{To: code, Secret: []byte("otpauth://totp/x?secret=not-base32!1")}); err == nil || !strings.Contains(err.Error(), "key can't be used") {
		t.Errorf("a link with a bad key: %v", err)
	}
	link := "otpauth://totp/Site:me?secret=JBSWY3DPEHPK3PXP&issuer=Site&algorithm=SHA256&digits=8&period=60"
	if _, err := u.Save(&tui.Change{To: code, Secret: []byte(link)}); err != nil {
		t.Fatal(err)
	}
	if _, err := u.Save(&tui.Change{Key: code, To: code, Secret: []byte("GEZDGNBVGY3TQOJQ")}); err != nil {
		t.Fatal(err)
	}
	c, err := store.Lookup(code)
	if err != nil || !c.Settings.TOTP.IsDefault() || c.Settings.TOTP.Issuer != "Site" {
		t.Errorf("after a key alone, settings = %+v, %v", c.Settings.TOTP, err)
	}
	if key, err := store.Get(code); err != nil || string(key) != "GEZDGNBVGY3TQOJQ" {
		t.Errorf("key = %q, %v", key, err)
	}
}

// The app's tidying reaches the vault: folders and tags set, renamed and
// counted, and entries trashed together.
func TestUI_Tidy(t *testing.T) {
	filingVault(t)
	store, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	u := newUIVault(store)
	defer u.Close() //nolint:errcheck // test cleanup
	gh := vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}
	gl := vault.Key{Kind: vault.KindPassword, Service: "gitlab"}
	if n, err := u.MoveToFolder([]vault.Key{gh, gl}, "work/git"); err != nil || n != 2 {
		t.Fatalf("MoveToFolder = %d, %v", n, err)
	}
	if n, err := u.AddTag([]vault.Key{gh, gl}, "code"); err != nil || n != 2 {
		t.Fatalf("AddTag = %d, %v", n, err)
	}
	if n, err := u.RemoveTag([]vault.Key{gl}, "code"); err != nil || n != 1 {
		t.Fatalf("RemoveTag = %d, %v", n, err)
	}
	if n, merged, err := u.RenameFolder("work", "job"); err != nil || n != 2 || merged {
		t.Fatalf("RenameFolder = %d, %v, %v", n, merged, err)
	}
	if n, _, err := u.RenameTag("code", "src"); err != nil || n != 1 {
		t.Fatalf("RenameTag = %d, %v", n, err)
	}
	folders, tags, err := u.Filing()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range folders {
		got = append(got, fmt.Sprintf("%s=%d/%d", f.Name, f.Entries, f.Total))
	}
	for _, tg := range tags {
		got = append(got, fmt.Sprintf("#%s=%d", tg.Name, tg.Entries))
	}
	if want := "=2/2 job=0/2 job/git=2/2 #src=1"; strings.Join(got, " ") != want {
		t.Errorf("Filing = %q, want %q", strings.Join(got, " "), want)
	}
	if err := u.DeleteMany([]vault.Key{gh, gl}); err != nil {
		t.Fatal(err)
	}
	if trash, err := u.Trash(); err != nil || len(trash) != 2 {
		t.Errorf("Trash = %d, %v", len(trash), err)
	}
	if changed, err := u.Check(); changed || err != nil {
		t.Errorf("Check after the app's own writes = %v, %v; want no change", changed, err)
	}
}

// The app's health check is the command's, recorded as one audit event.
func TestUI_Health(t *testing.T) {
	healthVault(t)
	store, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	u := newUIVault(store)
	defer u.Close() //nolint:errcheck // test cleanup
	r, err := u.Health(time.Now(), 365*24*time.Hour)
	if err != nil || r.Checked != 4 || len(r.Weak) != 2 || len(r.Reused) != 1 {
		t.Fatalf("Health = %+v, %v", r, err)
	}
	if log := mustRun(t, runAudit); !strings.Contains(log, "Health check, in sesh ui: read 4 secrets") {
		t.Errorf("audit:\n%s", log)
	}
}

// health.old_after_days reaches the app as the age its report calls old.
func TestUI_OptionsOldAfter(t *testing.T) {
	useConfigFile(t, "[health]\nold_after_days = 30\n")
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	if got := uiOptions(agentTestApp(), cfg, nil).OldAfter; got != 30*24*time.Hour {
		t.Errorf("OldAfter = %v", got)
	}
}

// The app's settings are the config's; a change is written to the config file, and one set by the
// environment is said to be.
func TestUI_Settings(t *testing.T) {
	path := useConfigFile(t, "# mine\n[history]\nkeep = 10\n")
	t.Setenv(config.EnvTrashKeepDays, "3")
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	opts := uiOptions(agentTestApp(), cfg, nil)
	if _, err := opts.SetSetting("history.keep", "4"); err != nil {
		t.Fatal(err)
	}
	live, err := opts.SetSetting("health.old_after_days", "30")
	if err != nil || live.OldAfter != 30*24*time.Hour {
		t.Fatalf("OldAfter = %v, %v", live.OldAfter, err)
	}
	if body, _ := os.ReadFile(path); !strings.HasPrefix(string(body), "# mine\n[history]\nkeep = 4\n") || !strings.Contains(string(body), "[health]\nold_after_days = 30\n") { //nolint:errcheck // compared
		t.Errorf("config file:\n%s", body)
	}
	list, err := opts.Settings()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]tui.Setting{}
	for _, s := range list {
		got[s.Key] = s
	}
	if h := got["history.keep"]; h.Value != "4" || h.Said != "config file" || h.Env != "" {
		t.Errorf("history.keep = %+v", h)
	}
	if tr := got["trash.keep_days"]; tr.Env != config.EnvTrashKeepDays {
		t.Errorf("trash.keep_days = %+v", tr)
	}
	if d := got["db_path"]; d.Editable {
		t.Errorf("db_path = %+v", d)
	}
	if _, err := opts.SetSetting("history.keep", "-1"); err == nil || !strings.Contains(err.Error(), "history.keep") {
		t.Errorf("a refused value: %v", err)
	}
}
