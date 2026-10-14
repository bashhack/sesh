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
	// open with the old master password; "" when there are none.
	OldBackups string
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
	current := &input{kind: inputSecret, label: "current master password"}
	next := &input{kind: inputSecret, label: "new master password", rated: true, hint: "at least 8 characters"}
	again := &input{kind: inputSecret, label: "new master password again"}
	f := &form{title: "Change the master password", inputs: []*input{current, next, again}, row: -1, enterDone: "change it", working: "Changing the master password…"}
	sure := false // to an easy one, asked about once
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
		case next.weak && !sure:
			sure = true
			f.err = "The new master password is easy to guess: a cracking program would likely find it in under 100 million tries, and it protects every secret in the vault. Press Enter again to use it anyway."
		default:
			return m.runChange(bytes.Clone(current.secret), bytes.Clone(next.secret))
		}
		return nil
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
	if msg.err != nil {
		if m.form != nil {
			m.form.saving = false
			m.form.err = "Not changed: " + msg.err.Error()
			if errors.Is(msg.err, ErrWrongPassword) {
				m.form.err = "Not changed: that's not the current master password."
			}
		}
		if errors.Is(msg.err, ErrLocked) {
			return m.lock(lockedReason(msg.err))
		}
		return m.reread()
	}
	if m.form != nil {
		m.form.wipe()
		m.form = nil
	}
	said := strings.Join(msg.ch.Said, " ")
	if msg.ch.Vault == nil {
		return m.lock(said)
	}
	if m.v == nil {
		// Locked meanwhile: it's unlocked again as usual.
		msg.ch.Vault.Close() //nolint:errcheck,gosec // nothing more to do with it
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
	back := m.ov
	if msg.ch.OldBackups != "" && m.opts.RenewBackups != nil {
		m.ov = m.confirm(back, "Master password changed", said+"\n\n"+msg.ch.OldBackups+" If the old master password may have leaked, delete them. Delete them and make a fresh backup?", func() tea.Cmd {
			m.ov = back
			return m.renewBackups()
		})
		m.ov.danger = true
	} else {
		m.ov = &overlay{kind: panelNotice, back: back, title: "Master password changed", question: said}
	}
	return tea.Batch(closing, m.reread())
}

// renewBackups deletes the vault's backups and makes a fresh one.
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
