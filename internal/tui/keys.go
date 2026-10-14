package tui

import (
	"fmt"
	"strings"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// key handles a key while unlocked: typing searches, the arrows move,
// Enter copies, Esc clears the search or quits, ? shows the keys.
func (m *Model) key(msg tea.KeyPressMsg) tea.Cmd {
	m.lastKey = m.opts.Now()
	switch msg.String() {
	case "ctrl+c":
		return tea.Quit
	case "esc":
		switch {
		case m.showHelp:
			m.showHelp = false
			return nil
		case m.input.Value() == "":
			return tea.Quit
		}
		m.input.SetValue("")
		return m.requery()
	case "enter", "tab", "ctrl+y", "ctrl+o":
		if !m.listShown() {
			// The entries aren't on screen: nothing is done to one unseen.
			return nil
		}
		switch msg.String() {
		case "tab":
			return m.toggleReveal()
		case "ctrl+y":
			return m.copyUsername()
		case "ctrl+o":
			return m.openURL()
		}
		return m.copySelected()
	case "up", "ctrl+p":
		m.sel--
	case "down", "ctrl+n":
		m.sel++
	case "pgup":
		m.sel -= m.listHeight()
	case "pgdown":
		m.sel += m.listHeight()
	case "shift+up":
		m.scrollPreview(-1)
		return nil
	case "shift+down":
		m.scrollPreview(1)
		return nil
	case "?":
		if m.input.Value() == "" {
			m.showHelp = !m.showHelp
			return nil
		}
		return m.typed(msg)
	default:
		return m.typed(msg)
	}
	m.scroll()
	return m.moved()
}

// typed hands a key to the search box, and searches again when it
// changed what's searched for.
func (m *Model) typed(msg tea.KeyPressMsg) tea.Cmd {
	before := m.input.Value()
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	if m.input.Value() == before {
		return cmd
	}
	m.showHelp = false
	return tea.Batch(cmd, m.requery())
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
			return tea.Batch(m.spin.Tick, func() tea.Msg {
				v, err := touch()
				return unlockedMsg{v: v, err: err}
			})
		}
		pw := m.password
		m.password = nil
		m.unlocking = true
		unlock := m.opts.Unlock
		return tea.Batch(m.spin.Tick, func() tea.Msg {
			v, err := unlock(pw)
			return unlockedMsg{v: v, err: err}
		})
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
		text, what := string(secret), "Copied "+entryName(&e)+"'s "+secretWord(e.Kind)
		if e.Kind == vault.KindTOTP {
			if text, err = totp.CodeAt(secret, e.Settings.TOTP, opts.Now()); err != nil {
				return copiedMsg{what: fmt.Sprintf("Couldn't make %s's code: %v", e.Key, err), epoch: epoch, bad: true}
			}
			what = "Copied " + entryName(&e) + "'s code"
		}
		if err := opts.Copy(text); err != nil {
			return copiedMsg{what: "Couldn't copy: " + err.Error(), epoch: epoch, bad: true}
		}
		if opts.ClearAfter > 0 {
			what += fmt.Sprintf(" · clears in %s", opts.ClearAfter)
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

// listHeight is how many entries fit: the screen less the frame's top
// and bottom, the search line, the rules around the list, and the keys.
func (m *Model) listHeight() int {
	return max(m.height-6, 1)
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
	m.sel, m.top, m.selKey = 0, 0, vault.Key{}
	return m.search()
}

// listShown says whether the entries are on screen: not behind the help,
// nor in a window too small to draw them.
func (m *Model) listShown() bool {
	return !m.showHelp && m.width >= minWidth && m.height >= minHeight
}

// entryName is an entry as the app names it: its service, and its
// username after it.
func entryName(e *vault.Entry) string {
	if e.Username == "" {
		return e.Service
	}
	return e.Service + " (" + e.Username + ")"
}

// secretWord names what copying an entry of kind k copies.
func secretWord(k vault.Kind) string {
	switch k {
	case vault.KindAPIKey:
		return "key"
	case vault.KindNote:
		return "note"
	}
	return "password"
}

// copyUsername copies the selected entry's username, which isn't secret,
// so nothing is read from the vault for it.
func (m *Model) copyUsername() tea.Cmd {
	e := m.selected()
	if e == nil {
		return nil
	}
	if e.Username == "" {
		m.sayBad(e.Service + " has no username")
		return nil
	}
	name, user, opts, epoch := entryName(e), e.Username, m.opts, m.epoch
	return func() tea.Msg {
		if err := opts.Copy(user); err != nil {
			return copiedMsg{what: "Couldn't copy: " + err.Error(), epoch: epoch, bad: true}
		}
		what := "Copied " + name + "'s username"
		if opts.ClearAfter > 0 {
			what += fmt.Sprintf(" · clears in %s", opts.ClearAfter)
		}
		return copiedMsg{what: what, epoch: epoch}
	}
}

// openedMsg is a URL opened, or why it wasn't.
type openedMsg struct {
	err error
	url string
}

// openURL opens the selected entry's URL in the browser.
func (m *Model) openURL() tea.Cmd {
	e := m.selected()
	if e == nil {
		return nil
	}
	if e.URL == "" || m.opts.OpenURL == nil {
		m.sayBad(e.Service + " has no URL")
		return nil
	}
	u, open := e.URL, m.opts.OpenURL
	return func() tea.Msg { return openedMsg{url: u, err: open(u)} }
}

// rowAt is the entry at a point on the screen, when the list is there.
func (m *Model) rowAt(x, y int) (int, bool) {
	const firstRow = 3 // the frame's top, the search line, the rule
	n := m.top + y - firstRow
	if x < 1 || x > m.listWidth() || y < firstRow || y >= firstRow+m.listHeight() || n >= len(m.rows) {
		return 0, false
	}
	return n, true
}
