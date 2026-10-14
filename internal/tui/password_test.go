package tui

import (
	"errors"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
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
	a.press("ctrl+k", ",")
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
	a.press("ctrl+k", ",", "enter", "old-password", "enter", "new-password-1", "enter", "new-password-1", "enter")
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
	a.press("ctrl+k", ",", "enter", "old-password", "enter", "new-password-1", "enter", "new-password-1", "enter")
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
	a.press("ctrl+k", ",", "enter", "old-password", "enter", "new-password-1", "enter", "new-password-1")
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
	a, asked := passwordApp(t, newFake(), Changed{Vault: newFake(), Said: []string{"Changed."}, OldBackups: "2 backups made before this change still open with the old master password, in ~/b."}, nil)
	a.press("ctrl+k", ",", "enter", "old-password", "enter", "new-password-1", "enter", "new-password-1", "enter")
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
	a, _ := passwordApp(t, newFake(), Changed{Said: []string{"Changed the master password.", "It couldn't open the vault again (gone): unlock it with the new master password."}}, nil)
	a.press("ctrl+k", ",", "enter", "old-password", "enter", "new-password-1", "enter", "new-password-1", "enter")
	if a.v != nil || !strings.Contains(a.lockedWhy, "unlock it with the new master password") {
		t.Errorf("locked %v: %q", a.v == nil, a.lockedWhy)
	}
}
