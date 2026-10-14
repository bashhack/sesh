package tui

import (
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// The smallest window the app draws in; below it, it asks for more room.
const (
	minWidth, minHeight = 44, 12
	// previewFrom is the width from which the selected entry is shown
	// beside the list.
	previewFrom = 76
)

// View draws the app on the alternate screen, so nothing it shows stays
// in the terminal's scrollback.
func (m *Model) View() tea.View {
	var s string
	switch {
	case m.width < minWidth || m.height < minHeight:
		s = lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center,
			m.th.dimmed().Render(fmt.Sprintf("sesh ui needs a bigger window (%d×%d)", minWidth, minHeight)))
	case m.v == nil:
		s = m.drawLocked()
	default:
		s = m.drawApp()
		if m.ov != nil {
			s = m.drawOverlay(s)
		}
	}
	v := tea.NewView(s)
	v.AltScreen = true
	if m.v != nil && m.width >= minWidth && m.height >= minHeight {
		v.MouseMode = tea.MouseModeCellMotion
	}
	return v
}

// listWidth is the list's width inside the frame: all of it, or less the
// preview beside it when the window is wide enough.
func (m *Model) listWidth() int {
	inner := m.width - 2
	if m.width < previewFrom || m.showHelp {
		return inner
	}
	return max(inner*9/20, 30)
}

// frame draws the app's outline: a title in the top border, rows of
// content, and rules between groups of them. A split row is two cells
// and a divider.
type frame struct {
	th    theme
	b     strings.Builder
	width int // outer
}

func (f *frame) inner() int { return f.width - 2 }

func (f *frame) top(title string) {
	l := f.th.lines()
	t := f.th.accented().Bold(true).Render(" " + title + " ")
	fill := max(f.inner()-1-lipgloss.Width(t), 0)
	f.b.WriteString(l.Render("╭─") + t + l.Render(strings.Repeat("─", fill)+"╮") + "\n")
}

func (f *frame) row(s string) {
	l := f.th.lines()
	f.b.WriteString(l.Render("│") + fitTo(s, f.inner()) + l.Render("│") + "\n")
}

func (f *frame) split(left string, lw int, right string) {
	l := f.th.lines()
	f.b.WriteString(l.Render("│") + fitTo(left, lw) + l.Render("│") + fitTo(right, f.inner()-lw-1) + l.Render("│") + "\n")
}

// rule is a line across, with junction where the split meets it; lw 0
// has no split.
func (f *frame) rule(lw int, junction string) {
	l := f.th.lines()
	if lw == 0 {
		f.b.WriteString(l.Render("├"+strings.Repeat("─", f.inner())+"┤") + "\n")
		return
	}
	f.b.WriteString(l.Render("├"+strings.Repeat("─", lw)+junction+strings.Repeat("─", f.inner()-lw-1)+"┤") + "\n")
}

func (f *frame) bottom() {
	f.b.WriteString(f.th.lines().Render("╰" + strings.Repeat("─", f.inner()) + "╯"))
}

// drawApp is the search line, the entries with the selected one beside
// them when there's room, and the keys or what was just done.
func (m *Model) drawApp() string {
	f := &frame{th: m.th, width: m.width}
	f.top("sesh")
	count := fmt.Sprintf("%d of %d", len(m.rows), m.total)
	if m.input.Value() == "" {
		count = fmt.Sprintf("%d %s", m.total, plural(m.total, "entry", "entries"))
	}
	countStyled := m.th.dimmed().Render(count) + " "
	icon := m.th.accented().Render(" ⌕ ")
	inputWidth := max(f.inner()-lipgloss.Width(icon)-lipgloss.Width(countStyled)-1, 4)
	m.input.SetWidth(inputWidth)
	f.row(icon + fitTo(m.input.View(), inputWidth+1) + countStyled)

	lw := 0
	if m.listWidth() < f.inner() {
		lw = m.listWidth()
	}
	f.rule(lw, "┬")
	h := m.listHeight()
	listWidth := f.inner()
	if lw > 0 {
		listWidth = lw
	}
	var body []string
	if m.showHelp {
		body = m.helpLines(h)
	} else {
		body = m.listLines(listWidth, h)
	}
	if lw > 0 {
		pane := m.previewLines(f.inner()-lw-1, h)
		for i := range h {
			f.split(body[i], lw, pane[i])
		}
	} else {
		for i := range h {
			f.row(body[i])
		}
	}
	f.rule(lw, "┴")
	f.row(m.footer(f.inner()))
	f.bottom()
	return f.b.String()
}

// listLines are the entries shown, h lines of width w.
func (m *Model) listLines(w, h int) []string {
	out := make([]string, h)
	if len(m.rows) == 0 {
		msg := "Nothing matches."
		if m.total == 0 {
			msg = "The vault is empty."
		}
		out[h/2] = lipgloss.PlaceHorizontal(w, lipgloss.Center, m.th.dimmed().Render(msg))
		return out
	}
	words := strings.Fields(strings.ToLower(m.input.Value()))
	now := m.opts.Now()
	for i := range h {
		n := m.top + i
		if n >= len(m.rows) {
			break
		}
		out[i] = m.listRow(&m.rows[n], n == m.sel, w, words, now)
	}
	return out
}

// listRow is one entry in the list: its kind's mark, its name with the
// letters matched picked out, and its username, or a TOTP entry's code.
func (m *Model) listRow(e *vault.Entry, selected bool, w int, words []string, now time.Time) string {
	th := m.th
	bg := func(s lipgloss.Style) lipgloss.Style {
		if selected {
			return s.Background(th.selBg)
		}
		return s
	}
	bar := bg(lipgloss.NewStyle()).Render(" ")
	if selected {
		bar = bg(th.accented()).Render("▌")
	}
	mark := bg(lipgloss.NewStyle().Foreground(th.kindColor(e.Kind))).Render(kindMark(e.Kind))
	nameStyle := bg(th.style())
	if selected {
		nameStyle = nameStyle.Bold(true)
	}
	nameHi := bg(th.accented().Bold(true).Underline(true))
	name := highlight(e.Service, words, &nameStyle, &nameHi)
	right := ""
	if e.Username != "" {
		userStyle, userHi := bg(th.dimmed()), bg(th.accented().Underline(true))
		right = highlight(e.Username, words, &userStyle, &userHi)
	}
	if e.Kind == vault.KindTOTP {
		if code, _, ok := m.code(e, now); ok {
			right = bg(lipgloss.NewStyle().Foreground(th.ok)).Render(groupCode(code))
		}
	}
	space := func(n int) string { return bg(lipgloss.NewStyle()).Render(strings.Repeat(" ", max(n, 0))) }
	left := bar + space(1) + mark + space(1) + name
	if room := w - lipgloss.Width(left) - 2; lipgloss.Width(right) > room {
		right = ansi.Truncate(right, max(room, 0), "…")
	}
	return fitTo(left+space(w-lipgloss.Width(left)-lipgloss.Width(right)-1)+right+space(1), w)
}

// countdown is a bar of the seconds a code has left, its colour warning as
// it runs out.
func (m *Model) countdown(left int, p totp.Params, w int) string {
	period := p.Period
	if period <= 0 {
		period = 30
	}
	c := m.th.ok
	switch {
	case left <= 5:
		c = m.th.bad
	case left <= 10:
		c = m.th.warn
	}
	filled := min(max(w*left/period, 0), w)
	return lipgloss.NewStyle().Foreground(c).Render(strings.Repeat("━", filled)) +
		lipgloss.NewStyle().Foreground(m.th.faint).Render(strings.Repeat("━", w-filled)) +
		m.th.dimmed().Render(fmt.Sprintf(" %2ds", left))
}

// helpLines are the keys, in place of the list.
func (m *Model) helpLines(h int) []string {
	th := m.th
	keys := [][2]string{
		{"type", "search names, usernames and sites"},
		{"↑ ↓", "move (or ctrl+p, ctrl+n)"},
		{"pgup pgdn", "move a page"},
		{"↵", "copy the secret, or the code"},
		{"tab", "reveal the password and secret fields (30s)"},
		{"ctrl+k", "actions: copy a value, earlier secrets, delete, the trash, lock"},
		{"ctrl+y", "copy the username"},
		{"ctrl+o", "open the URL in the browser"},
		{"shift ↑ ↓", "scroll the details on the right"},
		{"mouse", "click to select, wheel to move or scroll"},
		{"ctrl+w ctrl+u", "delete a word, or the search"},
		{"esc", "clear the search, or quit"},
		{"ctrl+c", "quit"},
		{"?", "close this help"},
	}
	out := make([]string, h)
	for i, k := range keys {
		if i+1 >= h {
			break
		}
		out[i+1] = "   " + th.accented().Render(fmt.Sprintf("%-15s", k[0])) + th.dimmed().Render(k[1])
	}
	return out
}

// footer is the keys, and what was just done, or went wrong.
func (m *Model) footer(w int) string {
	th := m.th
	keys := [][2]string{{"↵", "copy"}, {"^k", "actions"}, {"↑↓", "move"}, {"esc", "clear"}}
	if m.input.Value() == "" {
		keys = [][2]string{{"↵", "copy"}, {"^k", "actions"}, {"↑↓", "move"}, {"esc", "quit"}, {"?", "help"}}
	}
	now := m.opts.Now()
	if (m.status != "" && now.Before(m.statusUntil)) || now.Before(m.clipUntil) {
		// Room for what's said on the right: the keys used most.
		keys = keys[:2]
	}
	var parts []string
	for _, k := range keys {
		parts = append(parts, th.accented().Render(k[0])+" "+th.dimmed().Render(k[1]))
	}
	left := " " + strings.Join(parts, th.lines().Render("  ·  "))
	if m.status == "" || !now.Before(m.statusUntil) {
		if !now.Before(m.clipUntil) {
			return left
		}
		clip := th.dimmed().Render(fmt.Sprintf("◷ clipboard clears in %ds", int(m.clipUntil.Sub(now).Round(time.Second).Seconds())))
		if lipgloss.Width(left)+lipgloss.Width(clip)+3 > w {
			return left
		}
		return left + strings.Repeat(" ", w-lipgloss.Width(left)-lipgloss.Width(clip)-1) + clip
	}
	mark, c := "✓ ", th.ok
	if m.statusBad {
		mark, c = "✗ ", th.bad
	}
	status := lipgloss.NewStyle().Foreground(c).Render(mark + m.status)
	if lipgloss.Width(left)+lipgloss.Width(status)+3 > w {
		return " " + ansi.Truncate(status, w-2, "…")
	}
	return left + strings.Repeat(" ", w-lipgloss.Width(left)-lipgloss.Width(status)-1) + status
}

// drawLocked is the locked screen: a card in the middle saying why, with
// the password field, which shows nothing of what's typed.
func (m *Model) drawLocked() string {
	th := m.th
	w := min(60, m.width-4)
	sep := th.lines().Render("  ·  ")
	lines := []string{"", th.accented().Bold(true).Render("sesh is locked")}
	if m.lockedWhy != "" {
		whyStyle := th.dimmed()
		if m.lockedWhy == wrongPassword {
			whyStyle = lipgloss.NewStyle().Foreground(th.bad)
		}
		lines = append(lines, whyStyle.Width(w-6).Render(m.lockedWhy))
	}
	lines = append(lines, "", th.style().Render("Master password"))
	field := th.dimmed().Render("type it, then press ↵")
	switch {
	case m.unlocking:
		field = m.spin.View() + th.dimmed().Render(" Unlocking…")
	case len(m.password) > 0:
		field = th.accented().Render("▌") + th.dimmed().Render(" hidden as you type")
	}
	box := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(th.accent).Padding(0, 1).Width(w - 6)
	hint := th.accented().Render("↵") + th.dimmed().Render(" unlock") + sep + th.accented().Render("esc") + th.dimmed().Render(" quit")
	if m.opts.TouchID != nil {
		hint = th.accented().Render("↵") + th.dimmed().Render(" unlock, or with nothing typed, Touch ID") + sep + th.accented().Render("esc") + th.dimmed().Render(" quit")
	}
	lines = append(lines, box.Render(field), "", hint, "")
	card := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(th.border).Padding(0, 2).Width(w).
		Render(lipgloss.JoinVertical(lipgloss.Left, lines...))
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, card)
}

// code is a TOTP entry's code at t, and the seconds it has left; false
// while its key isn't held. A code is made once a period: making one
// copies the key where it can't be wiped.
func (m *Model) code(e *vault.Entry, t time.Time) (string, int, bool) {
	if m.keys[e.Key] == nil {
		return "", 0, false
	}
	period := int64(e.Settings.TOTP.Period)
	if period <= 0 {
		period = 30
	}
	shown, ok := m.codes[e.Key]
	if !ok || shown.period != t.Unix()/period {
		code, err := totp.CodeAt(m.keys[e.Key], e.Settings.TOTP, t)
		if err != nil {
			return "", 0, false
		}
		shown = shownCode{text: code, period: t.Unix() / period}
		m.codes[e.Key] = shown
	}
	return shown.text, totp.SecondsLeft(e.Settings.TOTP, t), true
}

// groupCode splits a code in two, as authenticator apps show it.
func groupCode(code string) string {
	half := len(code) / 2
	return code[:half] + " " + code[half:]
}

// spaced puts a space between a code's characters, to draw it large.
func spaced(code string) string {
	return strings.Join(strings.Split(code, ""), " ")
}

// badge is a kind of entry, as a small label in its colour.
func badge(th *theme, k vault.Kind) string {
	return lipgloss.NewStyle().Foreground(th.badgeText).Background(th.kindColor(k)).Bold(true).
		Padding(0, 1).Render(strings.ToUpper(kindWord(k)))
}

// kindMark marks a kind of entry in the list.
func kindMark(k vault.Kind) string {
	switch k {
	case vault.KindTOTP:
		return "◷"
	case vault.KindAPIKey:
		return "◆"
	case vault.KindNote:
		return "≡"
	}
	return "●"
}

// kindWord names a kind of entry.
func kindWord(k vault.Kind) string {
	switch k {
	case vault.KindAPIKey:
		return "api key"
	case vault.KindNote:
		return "note"
	}
	return string(k)
}

// highlight is s with the letters matching any of words (lower case)
// drawn in hi, the rest in base. strings.ToLower maps rune for rune, so
// the lower-case runes line up with s's.
func highlight(s string, words []string, base, hi *lipgloss.Style) string {
	runes := []rune(s)
	lower := []rune(strings.ToLower(s))
	marked := make([]bool, len(runes))
	for _, w := range words {
		wr := []rune(w)
		for i := 0; len(wr) > 0 && i+len(wr) <= len(lower); i++ {
			if string(lower[i:i+len(wr)]) == w {
				for j := range wr {
					marked[i+j] = true
				}
			}
		}
	}
	var b strings.Builder
	for i := 0; i < len(runes); {
		j := i
		for j < len(runes) && marked[j] == marked[i] {
			j++
		}
		style := base
		if marked[i] {
			style = hi
		}
		b.WriteString(style.Render(string(runes[i:j])))
		i = j
	}
	return b.String()
}

// ago says how long before now t was, in words.
func ago(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		n := int(d.Minutes())
		return fmt.Sprintf("%d %s ago", n, plural(n, "minute", "minutes"))
	case d < 24*time.Hour:
		n := int(d.Hours())
		return fmt.Sprintf("%d %s ago", n, plural(n, "hour", "hours"))
	case d < 30*24*time.Hour:
		n := int(d.Hours() / 24)
		return fmt.Sprintf("%d %s ago", n, plural(n, "day", "days"))
	}
	return t.Local().Format("2 Jan 2006")
}

// fitTo cuts or pads s, styled, to w columns.
func fitTo(s string, w int) string {
	if w <= 0 {
		return ""
	}
	s = ansi.Truncate(s, w, "…")
	return s + strings.Repeat(" ", max(w-lipgloss.Width(s), 0))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
