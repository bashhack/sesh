package tui

import (
	"errors"
	"fmt"
	"time"

	tea "charm.land/bubbletea/v2"
)

// Recovery is the vault's recovery key, as the settings panel shows it.
type Recovery struct {
	Made time.Time
	// Said is its state in a few words: "set, made 2026-10-05", "none".
	Said string
	// Set is a record being there, for this vault or not: one to replace
	// or remove.
	Set bool
}

// NewRecovery is a recovery key made for the vault, shown until its last
// group is typed back, and saved then: until it is, it opens nothing.
type NewRecovery struct {
	// Matches says whether what was typed is the key's last group.
	Matches func(typed string) bool
	// Save saves it, replacing the vault's other one.
	Save func() (Done, error)
	Key  string
}

// Done is what a change to the vault's safety did, and the backups it
// leaves opening with what it replaced: said in OldBackups, and Renew
// asks whether to delete them and make a fresh one ("" when none).
type Done struct {
	Said, OldBackups, Renew string
}

// Messages from the recovery key's changes.
type (
	newRecoveryMsg struct {
		err error
		nr  *NewRecovery
	}
	recoveryMsg struct {
		err  error
		done Done
	}
)

// openRecovery is the recovery key's row chosen: a new one is made when
// there's none, and otherwise a new one or removing it is offered.
func (m *Model) openRecovery(r *Recovery) tea.Cmd {
	settings := m.ov
	if !r.Set {
		return m.makeRecovery()
	}
	made := ""
	if !r.Made.IsZero() {
		made = " (made " + r.Made.Local().Format("2006-01-02") + ")"
	}
	m.ov = &overlay{kind: panelMenu, back: settings, title: "Recovery key", items: []item{
		{key: "n", label: "make a new one…", stay: true, run: func() tea.Cmd {
			m.ov = m.confirm(settings, "Recovery key", "This vault already has a recovery key"+made+". A new one replaces it, and the old one stops working. Make a new one?", func() tea.Cmd {
				m.ov = settings
				return m.makeRecovery()
			})
			m.ov.danger = true
			return nil
		}},
		{key: "x", label: "remove it…", stay: true, run: func() tea.Cmd {
			m.ov = m.confirm(settings, "Recovery key", "Remove the recovery key? It will no longer open this vault, so a forgotten master password can't be reset.", func() tea.Cmd {
				m.ov = settings
				remove := m.opts.RemoveRecovery
				return func() tea.Msg {
					done, err := remove()
					return recoveryMsg{done: done, err: err}
				}
			})
			m.ov.danger = true
			return nil
		}},
	}}
	return nil
}

// makeRecovery makes a recovery key, to show.
func (m *Model) makeRecovery() tea.Cmd {
	newKey := m.opts.NewRecovery
	return func() tea.Msg {
		nr, err := newKey()
		return newRecoveryMsg{nr: nr, err: err}
	}
}

// showRecovery shows a recovery key made, and saves it once its last
// group is typed back.
func (m *Model) showRecovery(msg *newRecoveryMsg) tea.Cmd {
	if m.v == nil {
		return nil
	}
	switch {
	case errors.Is(msg.err, ErrLocked):
		return m.lock(lockedReason(msg.err))
	case msg.err != nil:
		m.recoverySaid("No recovery key was made: "+msg.err.Error(), true)
		return nil
	}
	nr := msg.nr
	in := m.textInput("its last group (4 characters), to confirm you've saved it", "")
	f := &form{title: "Your recovery key", row: -1, inputs: []*input{in}, working: "Saving the recovery key…",
		note: "    " + nr.Key + "\n\nWrite it down and keep it somewhere safe, away from this computer. If you forget your master password, sesh recover uses it to set a new one. Anyone who has it and your vault file can open the vault. sesh doesn't keep a copy, so it can't show it again."}
	tries := 0
	f.cancel = func() { m.recoverySaid("No recovery key was set, since it wasn't confirmed.", true) }
	f.submit = func() tea.Cmd {
		if !nr.Matches(in.value()) {
			tries++
			if tries < confirmTries {
				f.err = "That's not the last group. Type it again."
				return nil
			}
			m.form = nil
			f.cancel()
			return nil
		}
		f.saving, f.err = true, ""
		save := nr.Save
		return func() tea.Msg {
			done, err := save()
			return recoveryMsg{done: done, err: err}
		}
	}
	f.focusInput(0)
	m.form = f
	return nil
}

// confirmTries is how many times a recovery key's last group may be typed
// wrong before it's thrown away, as sesh recovery new allows.
const confirmTries = 3

// gotRecovery says what a change to the recovery key did, and offers the
// backups it leaves opening with the one replaced.
func (m *Model) gotRecovery(msg *recoveryMsg) tea.Cmd {
	if m.form != nil && m.form.saving {
		m.form = nil
	}
	if m.v == nil {
		return nil
	}
	switch {
	case errors.Is(msg.err, ErrLocked):
		return m.lock(lockedReason(msg.err))
	case msg.err != nil:
		m.recoverySaid("Not changed: "+msg.err.Error(), true)
		return nil
	}
	if msg.done.OldBackups != "" {
		m.afterChange(m.ov, "Recovery key", msg.done.Said, msg.done.OldBackups, msg.done.Renew)
	} else {
		m.recoverySaid(msg.done.Said, false)
	}
	return m.refreshSettings()
}

// recoverySaid says what happened to the recovery key: in the settings
// panel when it's open, which has room for it, and otherwise below.
func (m *Model) recoverySaid(said string, bad bool) {
	if m.ov != nil && m.ov.kind == panelSettings && bad {
		m.ov.err = said
		return
	}
	if bad {
		m.sayBad(said)
		return
	}
	m.say(said)
}

// recoveryRow is the settings panel's row for the recovery key r.
func (m *Model) recoveryRow(r Recovery) item {
	does := "make one"
	detail := "None yet. If you forget the master password, a recovery key is the one way to set a new one: sesh recover asks for it. Enter makes one."
	if r.Set {
		does = "make a new one, or remove it"
		detail = "If you forget the master password, sesh recover sets a new one with it. Enter makes a new one, replacing it, or removes it."
	}
	return item{
		label:  fmt.Sprintf("%-24s %s", "Recovery key", r.Said),
		detail: detail,
		does:   does,
		run:    func() tea.Cmd { return m.openRecovery(&r) },
		stay:   true,
	}
}
