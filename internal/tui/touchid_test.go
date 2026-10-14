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
		SetTouchID: func(on, takeOther bool) (string, error) {
			switch {
			case on && takeOther:
				asked = append(asked, "take")
			case on:
				asked = append(asked, "on")
			default:
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
	if !slices.Equal(*asked, []string{"take"}) {
		t.Errorf("yes: asked %q", *asked)
	}
	b, asked := touchApp(t, TouchID{Said: "off (Touch ID isn't usable here)", Why: "not over SSH."}, nil)
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

// A fingerprint that failed and turned Touch ID unlock off isn't offered again; one turned on since the lock is.
func TestTouchIDLockedScreenFollows(t *testing.T) {
	on := true
	touched := 0
	a := newApp(t, newFake(), Options{
		TouchID: func() (Vault, error) {
			touched++
			on = false // its fingerprints changed: it's turned off
			return nil, errors.New("your fingerprints changed, so Touch ID unlock is now off")
		},
		TouchIDOn: func() bool { return on },
	})
	a.run(a.lock("You locked it."))
	a.press("enter")
	if s := a.screen(); touched != 1 || strings.Contains(s, "Touch ID if nothing is typed") || !strings.Contains(s, "fingerprints changed") {
		t.Fatalf("after it turned off: touched %d\n%s", touched, s)
	}
	a.press("enter")
	if touched != 1 || !strings.Contains(a.screen(), "fingerprints changed") {
		t.Errorf("Enter again: touched %d\n%s", touched, a.screen())
	}
	on = true
	a.press("enter")
	if touched != 2 {
		t.Errorf("turned on since: touched %d", touched)
	}
}

// One refused because another vault took the file meanwhile says so, and the next Enter asks.
func TestTouchIDTakenMeanwhile(t *testing.T) {
	a, asked := touchApp(t, TouchID{Said: "off", Here: true}, Refused("touchid.key in this folder is set up for another vault; Enter again asks whether to take it."))
	a.press("ctrl+k", ",", "enter")
	if a.ov == nil || !strings.Contains(a.ov.err, "Enter again asks") || !slices.Equal(*asked, []string{"on"}) {
		t.Fatalf("asked %q, panel %+v", *asked, a.ov)
	}
}

// On, but not usable here, the row says so, and Enter turns it off.
func TestTouchIDOnNotHere(t *testing.T) {
	a, asked := touchApp(t, TouchID{Said: "on (Touch ID isn't usable here)", On: true, Why: "not over SSH."}, nil)
	a.press("ctrl+k", ",")
	if s := a.screen(); !strings.Contains(s, "It's on, but not usable here: not over SSH.") {
		t.Errorf("the row:\n%s", s)
	}
	a.press("enter")
	if !slices.Equal(*asked, []string{"off"}) {
		t.Errorf("asked %q", *asked)
	}
}

// Turned on as the app locked, the locked screen offers it once that's done.
func TestTouchIDOnAsItLocked(t *testing.T) {
	on := false
	a := newApp(t, newFake(), Options{
		Settings:     func() ([]Setting, error) { return nil, nil },
		TouchIDState: func() (TouchID, error) { return TouchID{Said: "off", Here: true}, nil },
		SetTouchID:   func(bool, bool) (string, error) { on = true; return "Touch ID unlock is on.", nil },
		TouchID:      func() (Vault, error) { return newFake(), nil },
		TouchIDOn:    func() bool { return on },
	})
	a.press("ctrl+k", ",")
	_, set := a.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	a.run(a.lock("No use for 5 minutes."))
	a.run(set)
	if s := a.screen(); !strings.Contains(s, "Touch ID if nothing is typed") {
		t.Errorf("the locked screen:\n%s", s)
	}
}
