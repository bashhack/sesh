package tui

import (
	"errors"
	"slices"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

// touchApp is the app with Touch ID unlock in state t, recording what's asked of it; SetTouchID fails with fail.
func touchApp(t *testing.T, state TouchID, fail error) (*app, *[]string) {
	t.Helper()
	var asked []string
	a := newApp(t, newFake(), Options{
		Settings:     func() ([]Setting, error) { return nil, nil },
		TouchIDState: func() (TouchID, error) { return state, nil },
		SetTouchID: func(on bool) (string, error) {
			if on {
				asked = append(asked, "on")
			} else {
				asked = append(asked, "off")
			}
			if fail != nil {
				return "", fail
			}
			state.On, state.Other = on, false
			state.Said = map[bool]string{true: "on", false: "off"}[on]
			return "Touch ID unlock is " + state.Said + ".", nil
		},
	})
	return a, &asked
}

// Enter turns it off when it's on, and on when it's off; the row says so after.
func TestTouchIDToggle(t *testing.T) {
	a, asked := touchApp(t, TouchID{Said: "on", On: true, Here: true}, nil)
	a.press("ctrl+k", ",")
	if s := a.screen(); !strings.Contains(s, "Touch ID unlock          on") || !strings.Contains(s, "turn it off") {
		t.Fatalf("the row:\n%s", s)
	}
	a.press("enter")
	if s := a.screen(); !slices.Equal(*asked, []string{"off"}) || !strings.Contains(s, "Touch ID unlock          off") || !strings.Contains(s, "Touch ID unlock is off.") {
		t.Fatalf("asked %q\n%s", *asked, s)
	}
	a.press("enter")
	if !slices.Equal(*asked, []string{"off", "on"}) || !strings.Contains(a.screen(), "Touch ID unlock          on") {
		t.Errorf("asked %q\n%s", *asked, a.screen())
	}
}

// Taking it from another vault asks first; where Touch ID isn't usable, Enter says why.
func TestTouchIDAsks(t *testing.T) {
	a, asked := touchApp(t, TouchID{Said: "set up for another vault", Other: true, Here: true}, nil)
	a.press("ctrl+k", ",", "enter")
	if a.ov == nil || a.ov.kind != panelConfirm || !a.ov.danger || len(*asked) != 0 {
		t.Fatalf("asked %q, panel %+v", *asked, a.ov)
	}
	a.press("n")
	if len(*asked) != 0 || a.ov == nil || a.ov.kind != panelSettings {
		t.Fatalf("no: asked %q, panel %+v", *asked, a.ov)
	}
	a.press("enter", "wait", "y")
	if !slices.Equal(*asked, []string{"on"}) {
		t.Errorf("yes: asked %q", *asked)
	}
	b, asked := touchApp(t, TouchID{Said: "off (Touch ID isn't usable here)"}, nil)
	b.press("ctrl+k", ",", "enter")
	if len(*asked) != 0 || b.ov == nil || !strings.Contains(b.ov.err, "not over SSH") {
		t.Errorf("not usable: asked %q, panel %+v", *asked, b.ov)
	}
}

// A failure is said in the panel; the agent locked meanwhile locks the app.
func TestTouchIDFails(t *testing.T) {
	a, _ := touchApp(t, TouchID{Said: "off", Here: true}, errors.New("touch ID unlock is set up through sesh's agent, which isn't running"))
	a.press("ctrl+k", ",", "enter")
	if a.ov == nil || !strings.Contains(a.ov.err, "Not changed: touch ID unlock is set up through sesh's agent") {
		t.Errorf("panel %+v", a.ov)
	}
	b, _ := touchApp(t, TouchID{Said: "off", Here: true}, Locked("sesh's agent locked the vault."))
	b.press("ctrl+k", ",", "enter")
	if b.v != nil {
		t.Error("not locked")
	}
}

// The locked screen offers a fingerprint only while Touch ID unlock is on, as it is when the app locks.
func TestTouchIDLockedScreen(t *testing.T) {
	on := false
	touched := 0
	a := newApp(t, newFake(), Options{
		TouchID:   func() (Vault, error) { touched++; return newFake(), nil },
		TouchIDOn: func() bool { return on },
	})
	a.run(a.lock("You locked it."))
	a.press("enter")
	if s := a.screen(); touched != 0 || strings.Contains(s, "Touch ID") {
		t.Errorf("off: touched %d\n%s", touched, s)
	}
	on = true
	a.run(a.lock("You locked it."))
	if s := a.screen(); !strings.Contains(s, "Touch ID if nothing is typed") {
		t.Errorf("on:\n%s", s)
	}
	a.press("enter")
	if touched != 1 || a.v == nil {
		t.Errorf("on: touched %d, locked %v", touched, a.v == nil)
	}
}

// Turned on or off just before the app locked, what it did isn't said over what's open after it unlocks again.
func TestTouchIDAcrossLock(t *testing.T) {
	a, _ := touchApp(t, TouchID{Said: "off", Here: true}, nil)
	a.press("ctrl+k", ",")
	_, set := a.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	a.run(a.lock("You locked it."))
	a.run(func() tea.Msg { return unlockedMsg{v: newFake()} })
	a.run(set)
	if strings.Contains(a.screen(), "Touch ID unlock is on.") {
		t.Errorf("said after unlocking again:\n%s", a.screen())
	}
}
