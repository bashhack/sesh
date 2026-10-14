package tui

import (
	"errors"
	"fmt"

	tea "charm.land/bubbletea/v2"
)

// TouchID is Touch ID unlock's state, as the settings panel shows it.
type TouchID struct {
	// Said is its state in a few words: "on", "off".
	Said string
	// Why says why Touch ID isn't usable here, when it isn't.
	Why string
	// On is it set up for this vault, and working.
	On bool
	// Other is its file set up for another vault, or an earlier master
	// password: turning it on takes it from that one.
	Other bool
	// Here is Touch ID usable on this Mac, in this session.
	Here bool
}

// touchIDMsg is Touch ID unlock turned on or off, or why not.
type touchIDMsg struct {
	err   error
	said  string
	epoch int
}

// touchIDRow is the settings panel's row for Touch ID unlock, in state t.
func (m *Model) touchIDRow(t TouchID) item {
	it := item{
		label: fmt.Sprintf("%-24s %s", "Touch ID unlock", t.Said),
		run:   func() tea.Cmd { return m.toggleTouchID(&t) },
		stay:  true,
	}
	switch {
	case t.On && !t.Here:
		it.does = "turn it off"
		it.detail = "It's on, but not usable here: " + t.Why + " Enter turns it off."
	case t.On:
		it.does = "turn it off"
		it.detail = "When the app locks, Enter with nothing typed unlocks it with your fingerprint, as sesh does when its agent has locked; your master password still works. Enter turns it off."
	case !t.Here:
		it.does = "why"
		it.detail = "Touch ID isn't usable here: " + t.Why
	case t.Other:
		it.does = "turn it on for this vault"
		it.detail = "It's set up for another vault in this folder, or for this one under an earlier master password. Enter turns it on for this vault, after asking: another vault would then need its password."
	default:
		it.does = "turn it on"
		it.detail = "Enter turns it on: a key in this Mac's Secure Enclave, which only your fingerprint unlocks, opens the vault when the app or sesh's agent has locked. Your master password still works."
	}
	return it
}

// toggleTouchID turns Touch ID unlock off when it's on, and otherwise on,
// asking first when that takes it from another vault.
func (m *Model) toggleTouchID(t *TouchID) tea.Cmd {
	switch {
	case t.On:
		return m.setTouchID(false, false)
	case !t.Here:
		m.ov.err = "Touch ID isn't usable here: " + t.Why
		return nil
	case t.Other:
		settings := m.ov
		m.ov = m.confirm(settings, "Touch ID unlock", "Touch ID unlock in this folder is set up for another vault, or for an earlier master password; another vault would then need its password. Turn it on for this vault?", func() tea.Cmd {
			m.ov = settings
			return m.setTouchID(true, true)
		})
		m.ov.danger = true
		return nil
	}
	return m.setTouchID(true, false)
}

// setTouchID turns Touch ID unlock on or off; takeOther is taking it from
// another vault asked about.
func (m *Model) setTouchID(on, takeOther bool) tea.Cmd {
	set, epoch := m.opts.SetTouchID, m.epoch
	return func() tea.Msg {
		said, err := set(on, takeOther)
		return touchIDMsg{said: said, err: err, epoch: epoch}
	}
}

// gotTouchID says what turning Touch ID unlock on or off did.
func (m *Model) gotTouchID(msg *touchIDMsg) tea.Cmd {
	if m.v == nil {
		// Turned on or off as it locked: the locked screen follows.
		m.touchOn = m.touchIDOn()
	}
	if msg.epoch != m.epoch || m.v == nil {
		return nil
	}
	switch {
	case errors.Is(msg.err, ErrLocked):
		return m.lock(lockedReason(msg.err))
	case msg.err != nil:
		// One refused for another vault's is read again, and asked about.
		m.safetySaid("Not changed: "+msg.err.Error(), true)
	default:
		m.say(msg.said)
	}
	return m.refreshSettings()
}

// touchIDOn says whether the locked screen offers a fingerprint: Touch ID
// unlock on for this vault, now.
func (m *Model) touchIDOn() bool {
	return m.opts.TouchID != nil && (m.opts.TouchIDOn == nil || m.opts.TouchIDOn())
}
