package tui

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
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
	a.press("ctrl+g", ",")
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
	a.press("ctrl+g", ",", "enter", "1111", "enter", "ctrl+u", "2222", "enter", "ctrl+u", "3333", "enter")
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
	a.press("ctrl+g", ",", "enter")
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
	a.press("ctrl+g", ",", "enter", "x")
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
	}{{errors.New("a recovery key is made through sesh's agent, which isn't running; run: sesh recovery new"), false}, {Locked("sesh's agent locked the vault."), true}} {
		a := newApp(t, newFake(), Options{
			Settings:    func() ([]Setting, error) { return nil, nil },
			Recovery:    func() (Recovery, error) { return Recovery{Said: "none"}, nil },
			NewRecovery: func() (*NewRecovery, error) { return nil, c.err },
		})
		a.press("ctrl+g", ",", "enter")
		switch {
		case c.locked && a.v != nil:
			t.Errorf("%v: not locked", c.err)
		case !c.locked && (a.ov == nil || !strings.Contains(a.ov.err, "No recovery key was made: a recovery key is made through sesh's agent, which isn't running")):
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
	a.press("ctrl+g", ",", "enter", "x", "wait", "y")
	if a.ov == nil || a.ov.kind != panelNotice || !strings.Contains(a.ov.question, "Removed.\n\nwarning: old backups: permission denied") {
		t.Fatalf("panel %+v", a.ov)
	}
	a.press("enter")
	if a.ov == nil || a.ov.kind != panelSettings {
		t.Errorf("Enter went to %+v", a.ov)
	}
}

// keyApp is the app showing a new recovery key, made replacing one or not, whose saves fail with each of fails in turn.
func keyApp(t *testing.T, replacing bool, fails ...error) (*app, *[]string) {
	t.Helper()
	var asked []string
	a := newApp(t, newFake(), Options{
		Settings: func() ([]Setting, error) { return nil, nil },
		Recovery: func() (Recovery, error) { return Recovery{Said: "none"}, nil },
		NewRecovery: func() (*NewRecovery, error) {
			asked = append(asked, "new")
			return &NewRecovery{
				Key: "ABCD-EFGH-JKMN-PQRS-TVWX-YZ01-2345", Replacing: replacing, Made: time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC),
				Matches: func(typed string) bool { return typed == "2345" },
				Save: func() (Done, error) {
					asked = append(asked, "save")
					if len(fails) > 0 {
						err := fails[0]
						fails = fails[1:]
						return Done{}, err
					}
					return Done{Said: "The recovery key is set for this vault."}, nil
				},
			}, nil
		},
	})
	return a, &asked
}

// One another command made since the panel was read is replaced only after asking.
func TestRecoveryMadeMeanwhile(t *testing.T) {
	a, asked := keyApp(t, true)
	a.press("ctrl+g", ",", "enter")
	if a.form != nil || a.ov == nil || a.ov.kind != panelConfirm || !strings.Contains(a.ov.question, "already has a recovery key (made 2026-10-01)") {
		t.Fatalf("form %v, panel %+v", a.form != nil, a.ov)
	}
	a.press("n")
	if a.form != nil || a.ov == nil || a.ov.kind != panelSettings {
		t.Fatalf("no: form %v, panel %+v", a.form != nil, a.ov)
	}
	a.press("enter", "wait", "y")
	if a.form == nil || slices.Contains(*asked, "save") {
		t.Errorf("yes: asked %q, form %v", *asked, a.form != nil)
	}
}

// No to replacing one, or Esc from the menu, makes nothing.
func TestRecoveryKept(t *testing.T) {
	a, asked := recoveryApp(t, true)
	a.press("ctrl+g", ",", "enter", "esc")
	if a.ov == nil || a.ov.kind != panelSettings || len(*asked) != 0 {
		t.Errorf("Esc from the menu: asked %q, panel %+v", *asked, a.ov)
	}
	a.press("enter", "n", "n")
	if a.ov == nil || a.ov.kind != panelSettings || len(*asked) != 0 {
		t.Errorf("no to replacing: asked %q, panel %+v", *asked, a.ov)
	}
	a.press("enter", "n", "esc")
	if a.ov == nil || a.ov.kind != panelSettings || len(*asked) != 0 {
		t.Errorf("Esc on replacing: asked %q, panel %+v", *asked, a.ov)
	}
}

// A lock while the key is shown says it wasn't set; one while it's saving says it may not have been.
func TestRecoveryLocked(t *testing.T) {
	a, _ := keyApp(t, false)
	a.press("ctrl+g", ",", "enter")
	a.run(a.lock("No use for 5 minutes."))
	if !strings.Contains(a.lockedWhy, "No use for 5 minutes. No recovery key was set, since it wasn't confirmed: throw away the one shown") {
		t.Errorf("shown: %q", a.lockedWhy)
	}
	b, _ := keyApp(t, false)
	b.press("ctrl+g", ",", "enter", "2345")
	_, save := b.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	b.run(b.lock("No use for 5 minutes."))
	b.run(save)
	if !strings.Contains(b.lockedWhy, "may not have been saved; see with: sesh recovery status") || b.v != nil {
		t.Errorf("saving: %q, locked %v", b.lockedWhy, b.v == nil)
	}
}

// Ctrl-C while it's saving quits once it's saved, and says so after.
func TestRecoveryQuit(t *testing.T) {
	a, _ := keyApp(t, false)
	a.press("ctrl+g", ",", "enter", "2345")
	_, save := a.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	a.press("ctrl+c")
	if a.quit || !strings.Contains(a.screen(), "Quitting once the recovery key is saved") {
		t.Fatalf("quit %v\n%s", a.quit, a.screen())
	}
	a.run(save)
	if !a.quit || a.Afterword() != "The recovery key is set for this vault." {
		t.Errorf("quit %v, said after %q", a.quit, a.Afterword())
	}
}

// A save that fails keeps the key shown, to try again.
func TestRecoverySaveRetried(t *testing.T) {
	a, asked := keyApp(t, false, errors.New("database is locked"))
	a.press("ctrl+g", ",", "enter", "2345", "enter")
	if a.form == nil || a.form.saving || !strings.Contains(a.form.err, "Not saved: database is locked") {
		t.Fatalf("form %+v", a.form)
	}
	a.press("enter")
	if a.form != nil || !slices.Equal(*asked, []string{"new", "save", "save"}) || !strings.Contains(a.screen(), "The recovery key is set") {
		t.Errorf("asked %q, form %v\n%s", *asked, a.form != nil, a.screen())
	}
}

// At every window size the key stays whole, and what's typed and the error stay in view; the note's end is cut.
func TestRecoveryFormFits(t *testing.T) {
	for w := minWidth; w <= 100; w += 8 {
		for h := minHeight; h <= 30; h++ {
			for _, wrong := range []bool{false, true} {
				a, _ := keyApp(t, false)
				a.Update(tea.WindowSizeMsg{Width: w, Height: h})
				a.press("ctrl+g", ",", "enter")
				// Typing clears the error, so the wrong group is what's seen with it.
				a.press("9Z")
				if wrong {
					a.press("enter")
				}
				s := a.screen()
				if strings.Count(s, "\n")+1 > h || !strings.Contains(s, "ABCD-EFGH-JKMN-PQRS-TVWX-YZ01-2345") || !strings.Contains(s, "9Z") ||
					(wrong && !strings.Contains(s, "That's not the last")) {
					t.Fatalf("at %dx%d, a wrong group typed %v:\n%s", w, h, wrong, s)
				}
			}
		}
	}
}

// What was under way when the app locked doesn't reach what's open after it unlocks again.
func TestRecoveryAcrossLock(t *testing.T) {
	a, _ := keyApp(t, false)
	a.press("ctrl+g", ",")
	_, made := a.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	a.run(a.lock("You locked it."))
	a.run(func() tea.Msg { return unlockedMsg{v: newFake()} })
	a.run(made)
	if a.form != nil {
		t.Fatal("a key made before the lock was shown after it")
	}
	a.press("ctrl+g", ",", "enter", "2345")
	_, save := a.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	a.run(a.lock("You locked it."))
	a.run(func() tea.Msg { return unlockedMsg{v: newFake()} })
	a.press("ctrl+g", ",", "enter")
	open := a.form
	a.run(save)
	if a.form == nil || a.form != open || strings.Contains(a.screen(), "The recovery key is set") {
		t.Errorf("a save from before the lock closed the form opened after it")
	}
}

// A form with a note and many inputs fits the window, scrolling the inputs.
func TestFormNoteFits(t *testing.T) {
	for h := minHeight; h <= 30; h++ {
		a := newApp(t, newFake(), Options{})
		a.Update(tea.WindowSizeMsg{Width: minWidth, Height: h})
		f := &form{title: "Many", row: -1, note: strings.Repeat("A long note that wraps. ", 6)}
		for i := range 6 {
			// Labels long enough to wrap at this width.
			f.inputs = append(f.inputs, a.textInput(fmt.Sprintf("input %d, whose label is long enough to wrap", i), ""))
		}
		f.focusInput(3)
		a.form = f
		a.press("9Z")
		if s := a.screen(); strings.Count(s, "\n")+1 > h || !strings.Contains(s, "input 3") || !strings.Contains(s, "9Z") {
			t.Fatalf("at %dx%d:\n%s", minWidth, h, s)
		}
	}
}

// Ctrl-C while it's saving, then a lock, quits at the lock, saying why, rather than at some later save.
func TestRecoveryQuitThenLock(t *testing.T) {
	a, _ := keyApp(t, false)
	a.press("ctrl+g", ",", "enter", "2345")
	_, save := a.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	a.press("ctrl+c")
	a.run(a.lock("No use for 5 minutes."))
	if !a.quit || !strings.HasPrefix(a.Afterword(), "No use for 5 minutes. The recovery key shown may not have been saved") {
		t.Fatalf("quit %v, said after %q", a.quit, a.Afterword())
	}
	a.run(save)
}

// A save refused for good closes the form, saying why; Esc after a save that failed says so.
func TestRecoverySaveRefused(t *testing.T) {
	a, asked := keyApp(t, false, Refused("the master password was changed: throw away the key."))
	a.press("ctrl+g", ",", "enter", "2345", "enter")
	if a.form != nil || a.ov == nil || !strings.Contains(a.ov.err, "Not changed: the master password was changed: throw away the key.") {
		t.Fatalf("form %v, panel %+v", a.form != nil, a.ov)
	}
	a.press("enter", "2345", "enter")
	if !slices.Equal(*asked, []string{"new", "save", "new", "save"}) {
		t.Errorf("asked %q", *asked)
	}
	b, _ := keyApp(t, false, errors.New("database is locked"))
	b.press("ctrl+g", ",", "enter", "2345", "enter", "esc", "esc")
	if b.form != nil || b.ov == nil || b.ov.err != "No recovery key was set, since it couldn't be saved." {
		t.Errorf("Esc after a failed save: form %v, panel %+v", b.form != nil, b.ov)
	}
	// A failed save, then three wrong groups: it wasn't confirmed.
	c, _ := keyApp(t, false, errors.New("database is locked"))
	c.press("ctrl+g", ",", "enter", "2345", "enter", "ctrl+u", "1", "enter", "ctrl+u", "2", "enter", "ctrl+u", "3", "enter")
	if c.form != nil || c.ov == nil || c.ov.err != "No recovery key was set, since it wasn't confirmed." {
		t.Errorf("wrong groups after a failed save: form %v, panel %+v", c.form != nil, c.ov)
	}
}

// What's shown too long for the window doesn't break the form; a cut error ends with "…".
func TestFormShownTooLong(t *testing.T) {
	a := newApp(t, newFake(), Options{})
	a.Update(tea.WindowSizeMsg{Width: minWidth, Height: minHeight})
	in := a.textInput("x", "")
	a.form = &form{title: "Long", row: -1, inputs: []*input{in}, shown: strings.Repeat("ABCD-", 40), err: strings.Repeat("Not saved: the vault is busy. ", 4)}
	a.form.focusInput(0)
	_ = a.screen()
	a.form.shown = "ABCD"
	s := a.screen()
	cut := false
	for l := range strings.SplitSeq(s, "\n") {
		cut = cut || (strings.Contains(l, "busy") || strings.Contains(l, "saved")) && strings.Contains(l, "…")
	}
	if !cut {
		t.Errorf("a cut error, without its …:\n%s", s)
	}
}
