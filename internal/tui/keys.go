package tui

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// key handles a key while unlocked: typing searches, the arrows move,
// Enter copies, Esc clears the search or quits.
func (m *Model) key(msg tea.KeyPressMsg) tea.Cmd {
	m.lastKey = m.opts.Now()
	switch msg.String() {
	case "ctrl+c":
		return tea.Quit
	case "esc":
		if len(m.query) == 0 {
			return tea.Quit
		}
		m.query = m.query[:0]
		return m.requery()
	case "enter":
		return m.copySelected()
	case "up", "ctrl+p":
		m.sel--
	case "down", "ctrl+n":
		m.sel++
	case "pgup":
		m.sel -= m.listHeight()
	case "pgdown":
		m.sel += m.listHeight()
	case "backspace":
		if len(m.query) == 0 {
			return nil
		}
		m.query = m.query[:len(m.query)-1]
		return m.requery()
	case "ctrl+u":
		m.query = m.query[:0]
		return m.requery()
	case "ctrl+w":
		q := strings.TrimRightFunc(string(m.query), unicode.IsSpace)
		q = strings.TrimRightFunc(q, func(r rune) bool { return !unicode.IsSpace(r) })
		m.query = []rune(q)
		return m.requery()
	default:
		if msg.Text == "" || msg.Mod&(tea.ModCtrl|tea.ModAlt) != 0 {
			return nil
		}
		m.query = append(m.query, []rune(msg.Text)...)
		return m.requery()
	}
	m.scroll()
	return m.readKeys()
}

// lockedKey handles a key on the locked screen: typing the password,
// Enter to unlock with it (or with Touch ID, when nothing is typed),
// Esc or Ctrl-C to quit.
func (m *Model) lockedKey(msg tea.KeyPressMsg) tea.Cmd {
	switch msg.String() {
	case "ctrl+c", "esc":
		return tea.Quit
	}
	if m.unlocking {
		return nil
	}
	switch msg.String() {
	case "enter":
		if len(m.password) == 0 {
			if m.opts.TouchID == nil {
				return nil
			}
			m.unlocking = true
			touch := m.opts.TouchID
			return func() tea.Msg {
				v, err := touch()
				return unlockedMsg{v: v, err: err}
			}
		}
		pw := m.password
		m.password = nil
		m.unlocking = true
		unlock := m.opts.Unlock
		return func() tea.Msg {
			v, err := unlock(pw)
			return unlockedMsg{v: v, err: err}
		}
	case "backspace":
		if _, size := utf8.DecodeLastRune(m.password); size > 0 {
			secure.SecureZeroBytes(m.password[len(m.password)-size:])
			m.password = m.password[:len(m.password)-size]
		}
	case "ctrl+u":
		secure.SecureZeroBytes(m.password)
		m.password = m.password[:0]
	default:
		if msg.Text == "" || msg.Mod&(tea.ModCtrl|tea.ModAlt) != 0 {
			return nil
		}
		m.password = appendSecret(m.password, msg.Text)
	}
	return nil
}

// appendSecret is secret with text added. When it outgrows its array, the
// old one is wiped, so no copy of what was typed is left behind.
func appendSecret(secret []byte, text string) []byte {
	if len(secret)+len(text) <= cap(secret) {
		return append(secret, text...)
	}
	grown := make([]byte, len(secret), max(2*cap(secret), len(secret)+len(text), 64))
	copy(grown, secret)
	secure.SecureZeroBytes(secret)
	return append(grown, text...)
}

// trimNewlines is text without the line ends at its end, and with any
// within it as spaces.
func trimNewlines(text string) string {
	text = strings.TrimRight(text, "\r\n")
	return strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ").Replace(text)
}

// copySelected copies the selected entry's secret, or its TOTP code, to
// the clipboard: a read the audit log records.
func (m *Model) copySelected() tea.Cmd {
	if m.sel < 0 || m.sel >= len(m.rows) {
		return nil
	}
	e := m.rows[m.sel]
	epoch, opts := m.epoch, m.opts
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		reading := "in sesh ui, to copy it"
		if e.Kind == vault.KindTOTP {
			reading = "in sesh ui, to copy its code"
		}
		secret, err := v.Secret(e.Key, reading)
		if err != nil {
			return copiedMsg{err: err, epoch: epoch}
		}
		defer secure.SecureZeroBytes(secret)
		text, what := string(secret), "Copied "+e.Key.String()
		if e.Kind == vault.KindTOTP {
			if text, err = totp.CodeAt(secret, e.Settings.TOTP, opts.Now()); err != nil {
				return copiedMsg{what: fmt.Sprintf("Couldn't make %s's code: %v", e.Key, err), epoch: epoch}
			}
			what = "Copied " + e.Key.String() + "'s code"
		}
		if err := opts.Copy(text); err != nil {
			return copiedMsg{what: "Couldn't copy: " + err.Error(), epoch: epoch}
		}
		if opts.ClearAfter > 0 {
			what += fmt.Sprintf("; the clipboard clears in %s.", opts.ClearAfter)
		} else {
			what += "."
		}
		return copiedMsg{what: what, epoch: epoch}
	})
}

// readKeys reads the keys of the TOTP entries shown that aren't held yet.
func (m *Model) readKeys() tea.Cmd {
	if m.v == nil {
		return nil
	}
	var cmds []tea.Cmd
	end := min(m.top+m.listHeight(), len(m.rows))
	for i := m.top; i < end; i++ {
		k := m.rows[i].Key
		if k.Kind != vault.KindTOTP || m.keys[k] != nil || m.pending[k] || m.failed[k] {
			continue
		}
		m.pending[k] = true
		epoch := m.epoch
		cmds = append(cmds, m.read(func(v Vault, closed func() bool) tea.Msg {
			key, err := v.CodeKey(k)
			if closed() {
				// The app locked or ended meanwhile: the key isn't kept.
				secure.SecureZeroBytes(key)
				return nil
			}
			return keyMsg{k: k, key: key, err: err, epoch: epoch}
		}))
	}
	return tea.Batch(cmds...)
}

// listHeight is how many entries fit: the screen less the search line,
// the count line, and the footer.
func (m *Model) listHeight() int {
	return max(m.height-3, 1)
}

// scroll keeps the selection on an entry, and on screen.
func (m *Model) scroll() {
	m.sel = max(min(m.sel, len(m.rows)-1), 0)
	h := m.listHeight()
	switch {
	case m.sel < m.top:
		m.top = m.sel
	case m.sel >= m.top+h:
		m.top = m.sel - h + 1
	}
	m.top = max(min(m.top, len(m.rows)-h), 0)
}

// requery searches again for a changed query, from its best match.
func (m *Model) requery() tea.Cmd {
	m.sel, m.top = 0, 0
	return m.search()
}
