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
	// Made is when the key it replaces was made, if Replacing one.
	Made      time.Time
	Key       string
	Replacing bool
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
		err   error
		nr    *NewRecovery
		epoch int
		asked bool // replacing one was asked about
	}
	recoveryMsg struct {
		err  error
		f    *form // the key's form, when one was saved; nil for a removal
		done Done
	}
)

// openRecovery is the recovery key's row chosen: a new one is made when
// there's none, and otherwise a new one or removing it is offered.
func (m *Model) openRecovery(r *Recovery) tea.Cmd {
	settings := m.ov
	if !r.Set {
		return m.makeRecovery(false)
	}
	m.ov = &overlay{kind: panelMenu, back: settings, title: "Recovery key", items: []item{
		{key: "n", label: "make a new one…", stay: true, run: func() tea.Cmd {
			m.ov = m.confirm(settings, "Recovery key", replaceQuestion(r.Made), func() tea.Cmd {
				m.ov = settings
				return m.makeRecovery(true)
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

// makeRecovery makes a recovery key, to show; asked is whether replacing
// the one the panel showed was asked about.
func (m *Model) makeRecovery(asked bool) tea.Cmd {
	newKey, epoch := m.opts.NewRecovery, m.epoch
	return func() tea.Msg {
		nr, err := newKey()
		return newRecoveryMsg{nr: nr, err: err, asked: asked, epoch: epoch}
	}
}

// replaceQuestion asks whether to replace the recovery key made at made.
func replaceQuestion(made time.Time) string {
	when := ""
	if !made.IsZero() {
		when = " (made " + made.Local().Format("2006-01-02") + ")"
	}
	return "This vault already has a recovery key" + when + ". A new one replaces it, and the old one stops working. Make a new one?"
}

// showRecovery shows a recovery key made, once replacing one is asked
// about: one another command made since the panel was read is too.
func (m *Model) showRecovery(msg *newRecoveryMsg) tea.Cmd {
	if msg.epoch != m.epoch || m.v == nil {
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
	if nr.Replacing && !msg.asked {
		settings := m.ov
		m.ov = m.confirm(settings, "Recovery key", replaceQuestion(nr.Made), func() tea.Cmd {
			m.ov = settings
			m.keyForm(nr)
			return nil
		})
		m.ov.danger = true
		return m.refreshSettings()
	}
	m.keyForm(nr)
	return nil
}

// keyForm shows the recovery key nr, and saves it once its last group is
// typed back.
func (m *Model) keyForm(nr *NewRecovery) {
	in := m.textInput("type its last group (4 characters)", "")
	f := &form{title: "Your recovery key", row: -1, inputs: []*input{in}, working: "Saving the recovery key…",
		quitting: "Quitting once the recovery key is saved…", shown: nr.Key,
		note: "Write it down and keep it somewhere safe, away from this computer. If you forget your master password, sesh recover uses it to set a new one. Anyone who has it and your vault file can open the vault. sesh doesn't keep a copy, so it can't show it again. Type its last group to confirm you've saved it."}
	tries := 0
	f.cancel = func() { m.recoverySaid("No recovery key was set, since it wasn't confirmed.", true) }
	f.lost = func() string {
		if f.saving {
			return "The recovery key shown may not have been saved; see with: sesh recovery status"
		}
		return "No recovery key was set, since it wasn't confirmed: throw away the one shown, and make one again."
	}
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
			return recoveryMsg{f: f, done: done, err: err}
		}
	}
	f.focusInput(0)
	m.form = f
}

// confirmTries is how many times a recovery key's last group may be typed
// wrong before it's thrown away, as sesh recovery new allows.
const confirmTries = 3

// gotRecovery says what a change to the recovery key did, and offers the
// backups it leaves opening with the one replaced.
func (m *Model) gotRecovery(msg *recoveryMsg) tea.Cmd {
	if f := msg.f; f != nil {
		switch {
		case m.form != f:
			// Locked meanwhile, which said so.
			return nil
		case m.quitAfter:
			m.form = nil
			m.afterword = msg.done.Said + " " + msg.done.OldBackups
			if msg.err != nil {
				m.afterword = "The recovery key wasn't saved: " + msg.err.Error()
			}
			return tea.Quit
		case msg.err != nil && !errors.Is(msg.err, ErrLocked):
			// The key shown can still be saved.
			f.saving = false
			f.err = "Not saved: " + msg.err.Error() + " Press Enter to try again, or Esc to leave it unsaved."
			return nil
		}
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
