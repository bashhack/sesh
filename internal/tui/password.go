package tui

import (
	"bytes"
	"errors"
	"strings"

	tea "charm.land/bubbletea/v2"
)

// Changed is a master password changed.
type Changed struct {
	// Vault is the vault opened again with the new master password; nil
	// when it couldn't be, and the app locks.
	Vault Vault
	// OldBackups says the backups made before the change, which still
	// open with the old master password; "" when there are none. Renew
	// asks whether to delete them and make a fresh one.
	OldBackups, Renew string
	// Said is what the change did, then what else to know.
	Said []string
}

// changedMsg is the master password changed, or why it wasn't.
type changedMsg struct {
	err error
	ch  Changed
}

// changePassword asks for the current master password and a new one,
// twice, and changes it.
func (m *Model) changePassword() tea.Cmd {
	// Empty until typed: sesh keeps no copy of it to show.
	current := &input{kind: inputSecret, label: "current master password", prompt: "type it: sesh keeps no copy"}
	next := &input{kind: inputSecret, label: "new master password", rated: true, hint: "at least 8 characters"}
	again := &input{kind: inputSecret, label: "new master password again"}
	f := &form{title: "Change the master password", inputs: []*input{current, next, again}, row: -1, enterDone: "change it",
		working: "Changing the master password…", quitting: "Quitting once the master password is changed…"}
	f.submit = func() tea.Cmd {
		switch {
		case len(current.secret) == 0:
			f.err = "Type the current master password."
		case len(next.secret) < 8:
			f.err = "The new master password must be at least 8 characters."
		case !bytes.Equal(next.secret, again.secret):
			f.err = "The new master password and its repeat don't match."
		case bytes.Equal(next.secret, current.secret):
			f.err = "That's the master password now; type a new one."
		case next.weak && !next.accepted:
			next.accepted = true
			f.err = "The new master password is easy to guess: a cracking program would likely find it in under 100 million tries, and it protects every secret in the vault. Press Enter again to use it anyway."
		default:
			return m.runChange(bytes.Clone(current.secret), bytes.Clone(next.secret))
		}
		return nil
	}
	if m.opts.PasswordChangeNote != nil {
		f.note = m.opts.PasswordChangeNote()
	}
	f.focusInput(0)
	m.form = f
	return nil
}

// runChange changes the master password from current to next, with the
// form open until it's done. The vault the app has open stops opening
// once the change commits, so nothing reads it meanwhile: what was being
// read is let go, and the checks that would lock the app wait.
func (m *Model) runChange(current, next []byte) tea.Cmd {
	m.form.saving, m.form.err = true, ""
	m.changing = true
	// What's being read now comes back to an epoch gone: it's read again
	// when next wanted.
	m.checking = false
	clear(m.pending)
	clear(m.notesPending)
	m.epoch++
	change := m.opts.ChangePassword
	return func() tea.Msg {
		ch, err := change(current, next)
		return changedMsg{ch: ch, err: err}
	}
}

// changed takes up the vault opened with the new master password, or
// says why the change wasn't made.
func (m *Model) changed(msg *changedMsg) tea.Cmd {
	m.changing = false
	m.lastKey = m.opts.Now()
	cmd := m.takeChange(msg)
	if !m.quitAfter {
		return cmd
	}
	// Said once the app has ended, since it won't be on screen.
	switch {
	case errors.Is(msg.err, ErrWrongPassword):
		m.afterword = "The master password wasn't changed: that's not the current one."
	case msg.err != nil:
		m.afterword = "The master password wasn't changed: " + msg.err.Error()
	default:
		m.afterword = strings.TrimSpace(strings.Join(msg.ch.Said, " ") + " " + msg.ch.OldBackups)
	}
	return tea.Quit
}

// takeChange is changed, but for a quit asked meanwhile.
func (m *Model) takeChange(msg *changedMsg) tea.Cmd {
	if msg.err != nil {
		if m.form != nil {
			m.form.saving = false
			m.form.err = "Not changed: " + msg.err.Error()
			if errors.Is(msg.err, ErrWrongPassword) {
				m.form.err = "Not changed: that's not the current master password."
			}
		}
		switch {
		case m.v == nil:
			return nil
		case errors.Is(msg.err, ErrLocked):
			return m.lock(lockedReason(msg.err))
		}
		return m.reread()
	}
	if m.form != nil {
		m.form.wipe()
		m.form = nil
	}
	said := strings.Join(msg.ch.Said, " ")
	if msg.ch.OldBackups != "" && msg.ch.Vault == nil {
		said += " " + msg.ch.OldBackups
	}
	switch {
	case msg.ch.Vault == nil:
		return m.lock(said)
	case m.v == nil:
		// Locked meanwhile: it's unlocked again as usual, with the new one.
		msg.ch.Vault.Close() //nolint:errcheck,gosec // nothing more to do with it
		m.lockedWhy = said + " Unlock with the new master password."
		return nil
	}
	// The vault opened anew, with the agent's timers started again.
	closing := m.v.shut()
	m.shut = append(m.shut, m.v)
	m.wipe()
	m.v = newGate(msg.ch.Vault)
	m.epoch++
	now := m.opts.Now()
	m.unlockedAt, m.lastKeepAlive = now, now
	m.afterChange(m.ov, "Master password changed", said, msg.ch.OldBackups, msg.ch.Renew)
	return tea.Batch(closing, m.reread())
}

// afterChange says, over back, what a change did, and the backups it left
// opening with what it replaced (old), asking whether to delete them
// (ask), when there's a question to ask.
func (m *Model) afterChange(back *overlay, title, said, old, ask string) {
	if ask != "" && m.opts.RenewBackups != nil {
		m.ov = m.confirm(back, title, said+"\n\n"+old+" "+ask, func() tea.Cmd {
			m.ov = back
			return m.renewBackups()
		})
		m.ov.danger = true
		return
	}
	if old != "" {
		said += "\n\n" + old
	}
	m.ov = &overlay{kind: panelNotice, back: back, title: title, question: said}
}

// renewBackups makes a fresh backup of the vault, then deletes the rest.
func (m *Model) renewBackups() tea.Cmd {
	renew, epoch := m.opts.RenewBackups, m.epoch
	return func() tea.Msg {
		said, err := renew()
		if err != nil {
			return doneMsg{err: errors.New("old backups: " + err.Error()), epoch: epoch}
		}
		return doneMsg{what: said, epoch: epoch}
	}
}
