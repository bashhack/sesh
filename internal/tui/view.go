package tui

import (
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// Plain escape codes, as the rest of sesh writes them.
const (
	bold    = "\x1b[1m"
	dim     = "\x1b[2m"
	reverse = "\x1b[7m"
	reset   = "\x1b[0m"
)

// View draws the app on the alternate screen, so nothing it shows stays
// in the terminal's scrollback.
func (m *Model) View() tea.View {
	var b strings.Builder
	if m.v == nil {
		m.drawLocked(&b)
	} else {
		m.drawSearch(&b)
	}
	v := tea.NewView(b.String())
	v.AltScreen = true
	return v
}

// drawLocked is the locked screen: why, and the password field, which
// shows nothing of what's typed.
func (m *Model) drawLocked(b *strings.Builder) {
	b.WriteString(bold + " sesh is locked" + reset + "\n")
	if m.lockedWhy != "" {
		b.WriteString(" " + m.fit(m.lockedWhy, 1) + "\n")
	}
	b.WriteString("\n")
	if m.unlocking {
		b.WriteString(" Unlocking…\n")
	} else {
		b.WriteString(" Master password: \n")
	}
	hint := "Enter unlock · Esc quit"
	if m.opts.TouchID != nil {
		hint = "Enter unlock (with nothing typed: Touch ID) · Esc quit"
	}
	b.WriteString("\n" + dim + " " + m.fit(hint, 1) + reset)
}

// drawSearch is the search line, how many entries match, the entries,
// and a line of keys, or what was just done.
func (m *Model) drawSearch(b *strings.Builder) {
	b.WriteString(" " + bold + "›" + reset + " " + m.fit(string(m.query), 4) + reverse + " " + reset + "\n")
	count := fmt.Sprintf("%d %s", len(m.rows), plural(len(m.rows), "entry", "entries"))
	switch {
	case len(m.rows) == 0 && len(m.query) == 0:
		count = "The vault is empty."
	case len(m.rows) == 0:
		count = "Nothing matches."
	}
	b.WriteString(dim + " " + count + reset + "\n")

	h := m.listHeight()
	nameWidth, folderWidth := 0, 0
	end := min(m.top+h, len(m.rows))
	for i := m.top; i < end; i++ {
		nameWidth = max(nameWidth, ansi.StringWidth(entryName(&m.rows[i])))
		folderWidth = max(folderWidth, ansi.StringWidth(m.rows[i].Folder))
	}
	nameWidth = min(nameWidth, max(m.width/2, 10))
	folderWidth = min(folderWidth, max(m.width/4, 6))
	now := m.opts.Now()
	for i := m.top; i < m.top+h; i++ {
		if i >= end {
			b.WriteString("\n")
			continue
		}
		e := &m.rows[i]
		line := fmt.Sprintf(" %-8s  %s  %s  %s", kindWord(e.Kind), pad(entryName(e), nameWidth), pad(e.Folder, folderWidth), m.code(e, now))
		line = m.fit(strings.TrimRight(line, " "), 0)
		if i == m.sel {
			line = reverse + pad(line, m.width) + reset
		}
		b.WriteString(line + "\n")
	}

	footer := "Enter copy · ↑↓ move · Esc clear, or quit · Ctrl-C quit"
	if m.status != "" && now.Before(m.statusUntil) {
		footer = m.status
	}
	b.WriteString(dim + " " + m.fit(footer, 1) + reset)
}

// code is a TOTP entry's code now, and the seconds it has left; "" for
// other entries.
func (m *Model) code(e *vault.Entry, t time.Time) string {
	if e.Kind != vault.KindTOTP {
		return ""
	}
	switch {
	case m.failed[e.Key]:
		return "can't read"
	case m.keys[e.Key] == nil:
		return "…"
	}
	code, err := totp.CodeAt(m.keys[e.Key], e.Settings.TOTP, t)
	if err != nil {
		return "can't make"
	}
	half := len(code) / 2
	return fmt.Sprintf("%s %s  %2ds", code[:half], code[half:], totp.SecondsLeft(e.Settings.TOTP, t))
}

// entryName is an entry's name as the list shows it: the service, and
// the username after it.
func entryName(e *vault.Entry) string {
	if e.Username == "" {
		return e.Service
	}
	return e.Service + " (" + e.Username + ")"
}

// kindWord names a kind in the list.
func kindWord(k vault.Kind) string {
	switch k {
	case vault.KindAPIKey:
		return "api key"
	case vault.KindNote:
		return "note"
	}
	return string(k)
}

// fit cuts s to the screen's width less margin.
func (m *Model) fit(s string, margin int) string {
	return ansi.Truncate(s, max(m.width-margin, 1), "…")
}

// pad cuts or pads s to width columns.
func pad(s string, width int) string {
	s = ansi.Truncate(s, width, "…")
	return s + strings.Repeat(" ", max(width-ansi.StringWidth(s), 0))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
