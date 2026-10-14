package tui

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// recoveryApp is the app with a fake recovery key, set or not, recording what's asked of it.
func recoveryApp(t *testing.T, set bool) (*app, *[]string) {
	t.Helper()
	var asked []string
	state := func() Recovery {
		if set {
			return Recovery{Said: "set, made 2026-10-05", Made: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC), Set: true}
		}
		return Recovery{Said: "none"}
	}
	a := newApp(t, newFake(), Options{
		Settings: func() ([]Setting, error) { return nil, nil },
		Recovery: func() (Recovery, error) { return state(), nil },
		NewRecovery: func() (*NewRecovery, error) {
			asked = append(asked, "new")
			return &NewRecovery{
				Key:     "ABCD-EFGH-JKMN-PQRS-TVWX-YZ01-2345",
				Matches: func(typed string) bool { return strings.EqualFold(typed, "2345") },
				Save: func() (Done, error) {
					asked = append(asked, "save")
					was := set
					set = true
					if was {
						return Done{Said: "The recovery key is set for this vault.", OldBackups: "1 backup still opens with the old recovery key.", Renew: "Delete it and make a fresh backup?"}, nil
					}
					return Done{Said: "The recovery key is set for this vault."}, nil
				},
			}, nil
		},
		RemoveRecovery: func() (Done, error) {
			asked = append(asked, "remove")
			set = false
			return Done{Said: "Removed the recovery key.", OldBackups: "2 backups still open with the old recovery key.", Renew: "Delete them and make a fresh backup?"}, nil
		},
		RenewBackups: func() (string, error) { asked = append(asked, "renew"); return "Deleted 2 backups.", nil },
	})
	return a, &asked
}

// With none, Enter shows a new key; it's saved once its last group is typed back, and the row says so.
func TestRecoveryMake(t *testing.T) {
	a, asked := recoveryApp(t, false)
	a.press("ctrl+k", ",")
	if s := a.screen(); !strings.Contains(s, "Recovery key             none") || !strings.Contains(s, "make one") {
		t.Fatalf("the row:\n%s", s)
	}
	a.press("enter")
	if s := a.screen(); a.form == nil || !strings.Contains(s, "ABCD-EFGH-JKMN-PQRS-TVWX-YZ01-2345") || !strings.Contains(s, "can't show it again") {
		t.Fatalf("the key shown:\n%s", s)
	}
	a.press("1234", "enter")
	if a.form == nil || !strings.Contains(a.form.err, "That's not the last group") || slices.Contains(*asked, "save") {
		t.Fatalf("a wrong group: asked %q, form %+v", *asked, a.form)
	}
	a.press("ctrl+u", "2345", "enter")
	if !slices.Equal(*asked, []string{"new", "save"}) || a.form != nil {
		t.Fatalf("asked %q, form %+v", *asked, a.form)
	}
	if s := a.screen(); !strings.Contains(s, "The recovery key is set for this vault.") || !strings.Contains(s, "Recovery key             set, made 2026-10-05") {
		t.Errorf("after:\n%s", s)
	}
}

// Not confirmed, by three wrong groups or Esc, it isn't saved, and that's said.
func TestRecoveryNotConfirmed(t *testing.T) {
	a, asked := recoveryApp(t, false)
	a.press("ctrl+k", ",", "enter", "1111", "enter", "ctrl+u", "2222", "enter", "ctrl+u", "3333", "enter")
	if a.form != nil || slices.Contains(*asked, "save") || !strings.Contains(a.screen(), "No recovery key was set, since it wasn't confirmed.") {
		t.Errorf("three wrong: asked %q\n%s", *asked, a.screen())
	}
	a.press("enter", "esc")
	if a.form != nil || slices.Contains(*asked, "save") || !strings.Contains(a.screen(), "No recovery key was set") {
		t.Errorf("Esc: asked %q\n%s", *asked, a.screen())
	}
}

// One there already is replaced only after asking, and the backups that still open with it are offered.
func TestRecoveryReplace(t *testing.T) {
	a, asked := recoveryApp(t, true)
	a.press("ctrl+k", ",", "enter")
	if a.ov == nil || a.ov.kind != panelMenu || a.ov.title != "Recovery key" {
		t.Fatalf("panel %+v", a.ov)
	}
	a.press("n")
	if a.ov == nil || a.ov.kind != panelConfirm || !a.ov.danger || !strings.Contains(a.ov.question, "already has a recovery key (made 2026-10-05)") || len(*asked) != 0 {
		t.Fatalf("asked %q, panel %+v", *asked, a.ov)
	}
	a.press("wait", "y", "2345", "enter")
	if a.ov == nil || a.ov.kind != panelConfirm || !strings.Contains(a.ov.question, "1 backup still opens") {
		t.Fatalf("asked %q, panel %+v", *asked, a.ov)
	}
	a.press("wait", "y")
	if !slices.Equal(*asked, []string{"new", "save", "renew"}) || a.ov == nil || a.ov.kind != panelSettings {
		t.Errorf("asked %q, panel %+v", *asked, a.ov)
	}
}

// Removing asks first, then offers the backups; the row says none after.
func TestRecoveryRemove(t *testing.T) {
	a, asked := recoveryApp(t, true)
	a.press("ctrl+k", ",", "enter", "x")
	if a.ov == nil || a.ov.kind != panelConfirm || !a.ov.danger || len(*asked) != 0 {
		t.Fatalf("asked %q, panel %+v", *asked, a.ov)
	}
	a.press("wait", "y")
	if !slices.Equal(*asked, []string{"remove"}) || a.ov == nil || !strings.Contains(a.ov.question, "Delete them and make a fresh backup?") {
		t.Fatalf("asked %q, panel %+v", *asked, a.ov)
	}
	// The settings under the question were read again meanwhile.
	if s := a.ov.back; s == nil || s.kind != panelSettings || !strings.Contains(s.items[0].label, "none") {
		t.Errorf("the panel under it: %+v", s)
	}
	a.press("n")
	if s := a.screen(); a.ov == nil || a.ov.kind != panelSettings || !strings.Contains(s, "Recovery key             none") {
		t.Errorf("after:\n%s", s)
	}
}

// One that can't be made says why in the panel; the agent locked meanwhile locks the app.
func TestRecoveryNotMade(t *testing.T) {
	for _, c := range []struct {
		err    error
		locked bool
	}{{errors.New("sesh's agent isn't running"), false}, {Locked("sesh's agent locked the vault."), true}} {
		a := newApp(t, newFake(), Options{
			Settings:    func() ([]Setting, error) { return nil, nil },
			Recovery:    func() (Recovery, error) { return Recovery{Said: "none"}, nil },
			NewRecovery: func() (*NewRecovery, error) { return nil, c.err },
		})
		a.press("ctrl+k", ",", "enter")
		switch {
		case c.locked && a.v != nil:
			t.Errorf("%v: not locked", c.err)
		case !c.locked && (a.ov == nil || !strings.Contains(a.ov.err, "No recovery key was made: sesh's agent isn't running")):
			t.Errorf("%v: panel %+v", c.err, a.ov)
		}
	}
}

// Backups that couldn't be listed are said, with no question to answer.
func TestRecoveryBackupsWarning(t *testing.T) {
	a := newApp(t, newFake(), Options{
		Settings: func() ([]Setting, error) { return nil, nil },
		Recovery: func() (Recovery, error) { return Recovery{Said: "set", Set: true}, nil },
		RemoveRecovery: func() (Done, error) {
			return Done{Said: "Removed.", OldBackups: "warning: old backups: permission denied"}, nil
		},
		RenewBackups: func() (string, error) { return "", nil },
	})
	a.press("ctrl+k", ",", "enter", "x", "wait", "y")
	if a.ov == nil || a.ov.kind != panelNotice || !strings.Contains(a.ov.question, "Removed.\n\nwarning: old backups: permission denied") {
		t.Fatalf("panel %+v", a.ov)
	}
	a.press("enter")
	if a.ov == nil || a.ov.kind != panelSettings {
		t.Errorf("Enter went to %+v", a.ov)
	}
}
