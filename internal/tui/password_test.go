package tui

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/bashhack/sesh/internal/vault"
)

// passwordApp is the app with a fake master password change, which records what it's given and returns ch.
func passwordApp(t *testing.T, f *fakeVault, ch Changed, err error) (*app, *[]string) {
	t.Helper()
	var asked []string
	a := newApp(t, f, Options{
		Settings: func() ([]Setting, error) { return nil, nil },
		IsWeak:   func(pw []byte) bool { return string(pw) == "password" },
		ChangePassword: func(current, next []byte) (Changed, error) {
			asked = append(asked, string(current)+">"+string(next))
			return ch, err
		},
		RenewBackups: func() (string, error) {
			asked = append(asked, "renew")
			return "Deleted 2 backups; made a fresh one: ~/b/x", nil
		},
	})
	return a, &asked
}

// The form says what's wrong before anything changes, and asks once about an easy password.
func TestChangePasswordChecks(t *testing.T) {
	a, asked := passwordApp(t, newFake(), Changed{}, errors.New("unused"))
	a.press("ctrl+g", ",")
	if s := a.screen(); !strings.Contains(s, "Master password          change…") {
		t.Fatalf("the panel:\n%s", s)
	}
	a.press("enter")
	if a.form == nil || a.form.title != "Change the master password" {
		t.Fatalf("form %+v", a.form)
	}
	// Each try types all three afresh, from the first.
	fill := func(current, next, again string) {
		a.press("shift+tab", "shift+tab", "ctrl+u", current, "tab", "ctrl+u", next, "tab", "ctrl+u", again, "enter")
	}
	for _, c := range []struct{ current, next, again, wantSub string }{
		{"", "", "", "Type the current master password."},
		{"old-password", "short", "short", "at least 8 characters"},
		{"old-password", "new-password-1", "new-password-2", "don't match"},
		{"old-password", "old-password", "old-password", "That's the master password now"},
		{"old-password", "password", "password", "Press Enter again to use it anyway"},
	} {
		fill(c.current, c.next, c.again)
		if a.form == nil || !strings.Contains(a.form.err, c.wantSub) || len(*asked) != 0 {
			t.Fatalf("%q %q %q: asked %q, form %+v", c.current, c.next, c.again, *asked, a.form)
		}
	}
	a.press("enter")
	if len(*asked) != 1 || (*asked)[0] != "old-password>password" {
		t.Errorf("asked %q", *asked)
	}
}

// Changed, the app goes on with the vault opened anew, says what was done, and lets the old one go.
func TestChangePassword(t *testing.T) {
	old, fresh := newFake(), newFake()
	fresh.entries = fresh.entries[:1]
	a, asked := passwordApp(t, old, Changed{Vault: fresh, Said: []string{"Changed the master password, and re-encrypted 1 entry.", "Your recovery key still works."}}, nil)
	a.press("ctrl+g", ",", "enter", "old-password", "enter", "new-password-1", "enter", "new-password-1", "enter")
	if len(*asked) != 1 || a.form != nil || a.ov == nil || a.ov.kind != panelNotice {
		t.Fatalf("asked %q, form %+v, panel %+v", *asked, a.form, a.ov)
	}
	if s := a.screen(); !strings.Contains(s, "re-encrypted 1 entry.") || !strings.Contains(s, "Your recovery key still works.") {
		t.Errorf("what was said:\n%s", s)
	}
	if !old.closed || fresh.closed || fresh.searched == 0 || a.v == nil || a.v.v != Vault(fresh) {
		t.Errorf("old closed %v, new closed %v, new searched %d", old.closed, fresh.closed, fresh.searched)
	}
	a.press("enter")
	if a.ov == nil || a.ov.kind != panelSettings {
		t.Errorf("Enter went to %+v", a.ov)
	}
}

// A wrong current password keeps the form, and what was typed, to try again.
func TestChangePasswordWrong(t *testing.T) {
	a, asked := passwordApp(t, newFake(), Changed{}, ErrWrongPassword)
	a.press("ctrl+g", ",", "enter", "old-password", "enter", "new-password-1", "enter", "new-password-1", "enter")
	if a.form == nil || a.form.saving || !strings.Contains(a.form.err, "that's not the current master password") || len(*asked) != 1 {
		t.Fatalf("asked %q, form %+v", *asked, a.form)
	}
	if string(a.form.inputs[1].secret) != "new-password-1" || a.v == nil {
		t.Errorf("typed %q, locked %v", a.form.inputs[1].secret, a.v == nil)
	}
}

// While it runs, nothing reads the vault it's changing: a tick or key that would find it locked doesn't lock the app.
func TestChangePasswordMeanwhile(t *testing.T) {
	old, fresh := newFake(), newFake()
	a, _ := passwordApp(t, old, Changed{Vault: fresh, Said: []string{"Changed."}}, nil)
	a.press("ctrl+g", ",", "enter", "old-password", "enter", "new-password-1", "enter", "new-password-1")
	// A check begun before, and answered after the change committed.
	a.now = a.now.Add(time.Second)
	_, before := a.Update(tickMsg(a.now))
	_, change := a.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	old.checkErr, old.err = Locked("the key changed"), Locked("the key changed")
	a.run(before)
	kept := old.kept
	a.tick(2 * time.Minute)
	a.press("x")
	if a.v == nil || old.kept != kept || !strings.Contains(a.screen(), "Changing the master password…") {
		t.Fatalf("locked %v, kept-alive %d times\n%s", a.v == nil, old.kept-kept, a.screen())
	}
	a.run(change)
	if a.v == nil || a.v.v != Vault(fresh) || a.changing {
		t.Errorf("after: locked %v, changing %v", a.v == nil, a.changing)
	}
}

// Backups made before are offered for deleting, as sesh --rekey offers them.
func TestChangePasswordOldBackups(t *testing.T) {
	a, asked := passwordApp(t, newFake(), Changed{Vault: newFake(), Said: []string{"Changed."}, OldBackups: "2 backups made before this change still open with the old master password, in ~/b.", Renew: "Delete them and make a fresh backup?"}, nil)
	a.press("ctrl+g", ",", "enter", "old-password", "enter", "new-password-1", "enter", "new-password-1", "enter")
	if a.ov == nil || a.ov.kind != panelConfirm || !strings.Contains(a.ov.question, "Delete them and make a fresh backup?") {
		t.Fatalf("panel %+v", a.ov)
	}
	a.press("wait", "y")
	if len(*asked) != 2 || (*asked)[1] != "renew" || !strings.Contains(a.screen(), "Deleted 2 backups") || a.ov == nil || a.ov.kind != panelSettings {
		t.Errorf("asked %q\n%s", *asked, a.screen())
	}
}

// Changed, but not opened again: the app locks, saying so.
func TestChangePasswordNotReopened(t *testing.T) {
	a, _ := passwordApp(t, newFake(), Changed{Said: []string{"Changed the master password.", "It couldn't open the vault again (gone): unlock it with the new master password."},
		OldBackups: "2 backups made before this change still open with the old master password, in ~/b."}, nil)
	a.press("ctrl+g", ",", "enter", "old-password", "enter", "new-password-1", "enter", "new-password-1", "enter")
	if a.v != nil || !strings.Contains(a.lockedWhy, "unlock it with the new master password") || !strings.Contains(a.lockedWhy, "still open with the old master password") {
		t.Errorf("locked %v: %q", a.v == nil, a.lockedWhy)
	}
}

// A window resized during the change reads nothing from the vault being changed, though new rows come into view.
func TestChangePasswordResized(t *testing.T) {
	old, fresh := newFake(), newFake()
	for i := range 40 {
		k := vault.Key{Kind: vault.KindTOTP, Service: fmt.Sprintf("site%02d", i)}
		old.entries = append(old.entries, vault.Entry{Key: k})
	}
	a, _ := passwordApp(t, old, Changed{Vault: fresh, Said: []string{"Changed."}}, nil)
	a.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	a.run(a.reread())
	a.press("ctrl+g", ",", "enter", "old-password", "enter", "new-password-1", "enter", "new-password-1")
	_, change := a.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	old.err, old.checkErr = Locked("the key changed"), Locked("the key changed")
	reads := len(old.reads)
	_, cmd := a.Update(tea.WindowSizeMsg{Width: 100, Height: 60})
	a.run(cmd)
	if len(old.reads) != reads || a.v == nil {
		t.Fatalf("read %q meanwhile, locked %v (%q)", old.reads[reads:], a.v == nil, a.lockedWhy)
	}
	a.run(change)
	if a.v == nil || a.v.v != Vault(fresh) || a.ov == nil || a.ov.kind != panelNotice {
		t.Errorf("after: locked %v (%q), panel %+v", a.v == nil, a.lockedWhy, a.ov)
	}
}

// The longest unlock running out during the change doesn't lock the app under it.
func TestChangePasswordLifetime(t *testing.T) {
	old, fresh := newFake(), newFake()
	var asked []string
	a := newApp(t, old, Options{
		Settings:    func() ([]Setting, error) { return nil, nil },
		MaxLifetime: time.Minute,
		ChangePassword: func(current, next []byte) (Changed, error) {
			asked = append(asked, "change")
			return Changed{Vault: fresh, Said: []string{"Changed."}}, nil
		},
	})
	a.press("ctrl+g", ",", "enter", "old-password", "enter", "new-password-1", "enter", "new-password-1")
	_, change := a.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	a.tick(2 * time.Minute)
	if a.v == nil {
		t.Fatalf("locked meanwhile: %q", a.lockedWhy)
	}
	a.run(change)
	if a.v == nil || a.v.v != Vault(fresh) || len(asked) != 1 {
		t.Errorf("after: locked %v, asked %q", a.v == nil, asked)
	}
}

// Ctrl-C during the change quits once it's done, not under it.
func TestChangePasswordQuit(t *testing.T) {
	a, _ := passwordApp(t, newFake(), Changed{Vault: newFake(), Said: []string{"Changed.", "warning: could not lock the sesh agent."}, OldBackups: "2 backups still open."}, nil)
	a.press("ctrl+g", ",", "enter", "old-password", "enter", "new-password-1", "enter", "new-password-1")
	_, change := a.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	a.press("ctrl+c")
	if a.quit {
		t.Fatal("quit before the change was done")
	}
	a.run(change)
	if !a.quit || a.Afterword() != "Changed. warning: could not lock the sesh agent. 2 backups still open." {
		t.Errorf("quit %v, said after: %q", a.quit, a.Afterword())
	}
}

// Checks still running when the change starts don't leave the panel waiting for them for good.
func TestChangePasswordChecksRunning(t *testing.T) {
	old, fresh := newFake(), newFake()
	fresh.checks = Checks{Summary: "OK: no problems"}
	a, _ := passwordApp(t, old, Changed{Vault: fresh, Said: []string{"Changed."}}, nil)
	a.press("ctrl+g", ",", "down")
	_, checks := a.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	a.press("esc", "up", "enter", "old-password", "enter", "new-password-1", "enter", "new-password-1", "enter")
	a.run(checks)
	a.press("enter", "down", "enter")
	if s := a.screen(); !strings.Contains(s, "OK: no problems") || !slices.Contains(fresh.reads, "checks") {
		t.Errorf("checks after the change:\n%s", s)
	}
}

// Each easy password is asked about: saying yes to one doesn't let another through.
func TestChangePasswordEachEasyOne(t *testing.T) {
	var asked []string
	a := newApp(t, newFake(), Options{
		Settings: func() ([]Setting, error) { return nil, nil },
		IsWeak:   func(pw []byte) bool { return strings.HasPrefix(string(pw), "password") },
		ChangePassword: func(current, next []byte) (Changed, error) {
			asked = append(asked, string(next))
			return Changed{}, ErrWrongPassword
		},
	})
	a.press("ctrl+g", ",", "enter", "old-password", "enter", "password", "enter", "password", "enter", "enter")
	if len(asked) != 1 {
		t.Fatalf("the first easy one, said yes to: asked %q, form %+v", asked, a.form)
	}
	a.press("shift+tab", "ctrl+u", "password2", "tab", "ctrl+u", "password2", "enter")
	if len(asked) != 1 || a.form == nil || !strings.Contains(a.form.err, "easy to guess") {
		t.Errorf("another easy one: asked %q, form %+v", asked, a.form)
	}
}

// A danger confirmation is drawn in the warning colour; another isn't.
func TestConfirmDanger(t *testing.T) {
	a := newApp(t, newFake(), Options{})
	a.ov = a.confirm(nil, "Delete", "Delete it for good?", func() tea.Cmd { return nil })
	plain := a.View().Content
	a.ov.danger = true
	if a.View().Content == plain {
		t.Error("a danger confirmation looks like any other")
	}
}

// Notes being read as the change starts are read again after it fails, and not from the vault meanwhile.
func TestChangePasswordNotesInFlight(t *testing.T) {
	old := newFake()
	old.notes = map[vault.Key]string{}
	for i := range old.entries {
		old.entries[i].HasNotes = true
		old.notes[old.entries[i].Key] = "notes of " + old.entries[i].Key.String()
	}
	a, _ := passwordApp(t, old, Changed{}, ErrWrongPassword)
	_, inFlight := a.Update(tea.KeyPressMsg{Code: tea.KeyDown})
	k := a.selected().Key
	a.press("ctrl+g", ",", "enter", "old-password", "enter", "new-password-1", "enter", "new-password-1")
	_, change := a.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	a.run(inFlight)
	reads := len(old.reads)
	_, cmd := a.Update(tea.WindowSizeMsg{Width: 100, Height: 40})
	a.run(cmd)
	if len(old.reads) != reads {
		t.Fatalf("read %q meanwhile", old.reads[reads:])
	}
	a.run(change)
	a.press("esc", "esc", "esc")
	if string(a.notes[k]) != "notes of "+k.String() {
		t.Errorf("notes after the change failed: %q (pending %v)", a.notes[k], a.notesPending[k])
	}
}

// A TOTP key being read as the change starts is read again after it fails, so its code shows.
func TestChangePasswordKeyInFlight(t *testing.T) {
	old := &fakeVault{secrets: map[vault.Key]string{}}
	for i := range 30 {
		k := vault.Key{Kind: vault.KindPassword, Service: fmt.Sprintf("a%02d", i)}
		old.entries = append(old.entries, vault.Entry{Key: k})
	}
	totp := vault.Key{Kind: vault.KindTOTP, Service: "zz"}
	old.entries = append(old.entries, vault.Entry{Key: totp})
	old.secrets[totp] = seed
	a, _ := passwordApp(t, old, Changed{}, ErrWrongPassword)
	if a.keys[totp] != nil || a.pending[totp] {
		t.Fatal("the TOTP entry's key read before it's in view")
	}
	_, inFlight := a.Update(tea.WindowSizeMsg{Width: 100, Height: 50})
	a.press("ctrl+g", ",", "enter", "old-password", "enter", "new-password-1", "enter", "new-password-1")
	_, change := a.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	a.run(inFlight)
	a.run(change)
	if a.keys[totp] == nil {
		t.Errorf("the key after the change failed: pending %v", a.pending[totp])
	}
}

// Ctrl-R's hint shows once something is typed to show, not over an empty input, which says to type it; the form doesn't
// move when it does.
func TestRevealHintOnceTyped(t *testing.T) {
	a, _ := passwordApp(t, newFake(), Changed{}, nil)
	a.press("ctrl+k", ",", "enter")
	row := func() int {
		for i, l := range strings.Split(a.screen(), "\n") {
			if strings.Contains(l, "new master password") && !strings.Contains(l, "again") {
				return i
			}
		}
		return -1
	}
	before, at := a.screen(), row()
	if strings.Contains(before, "ctrl+r") || !strings.Contains(before, "type it: sesh keeps no copy") {
		t.Errorf("empty, the current password's hints:\n%s", before)
	}
	a.press("x")
	if s := a.screen(); !strings.Contains(s, "ctrl+r  show what you typed") || row() != at {
		t.Errorf("typed: the new password's label at %d, was %d\n%s", row(), at, s)
	}
	// At the narrowest window the prompt still fits one line, so the form doesn't move there either.
	a.press("backspace")
	a.Update(tea.WindowSizeMsg{Width: minWidth, Height: 30})
	narrow := row()
	a.press("x")
	if row() != narrow {
		t.Errorf("at %d columns: the new password's label at %d, was %d\n%s", minWidth, row(), narrow, a.screen())
	}
	a.press("backspace")
	a.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	a.press("x")
	// Shown, then emptied, or shown with nothing typed: the hint says it's shown, before what's typed next is.
	a.press("ctrl+r", "backspace")
	if s := a.screen(); !strings.Contains(s, "ctrl+r  hide it") {
		t.Errorf("shown, then emptied:\n%s", s)
	}
	a.press("tab", "ctrl+r")
	if s := a.screen(); !strings.Contains(s, "ctrl+r  hide it") {
		t.Errorf("shown with nothing typed:\n%s", s)
	}
}

// The export password's line, its own hint beside or below Ctrl-R's, is kept while it's empty: the form doesn't move.
func TestRevealHintKeepsLines(t *testing.T) {
	a := newApp(t, newFake(), Options{})
	a.press("ctrl+k", "i", "e", "tab")
	row := func() int {
		for i, l := range strings.Split(a.screen(), "\n") {
			if strings.Contains(l, "export password again") {
				return i
			}
		}
		return -1
	}
	for _, w := range []int{80, 60} {
		a.Update(tea.WindowSizeMsg{Width: w, Height: 30})
		at := row()
		a.press("x")
		if row() != at || at < 0 {
			t.Errorf("at %d columns: the next label at %d, was %d\n%s", w, row(), at, a.screen())
		}
		a.press("backspace")
	}
}
