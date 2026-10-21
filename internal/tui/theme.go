package tui

import (
	"image/color"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/bashhack/sesh/internal/vault"
)

// theme is the app's colours, for a dark terminal or a light one, and the
// styles made from them.
type theme struct {
	accent, text, dim, faint, border, ok, warn, bad, selBg, badgeText, keyBg color.Color
}

func newTheme(dark bool) theme {
	c := lipgloss.LightDark(dark)
	return theme{
		// The logo's blue; for a dark terminal, a lighter blue of the same hue.
		accent:    c(lipgloss.Color("#1165B1"), lipgloss.Color("#63ADEE")),
		text:      c(lipgloss.Color("#1F2328"), lipgloss.Color("#E6EDF3")),
		dim:       c(lipgloss.Color("#59636E"), lipgloss.Color("#8B949E")),
		faint:     c(lipgloss.Color("#B7BDC8"), lipgloss.Color("#3D444D")),
		border:    c(lipgloss.Color("#D1D9E0"), lipgloss.Color("#3D444D")),
		ok:        c(lipgloss.Color("#1A7F37"), lipgloss.Color("#3FB950")),
		warn:      c(lipgloss.Color("#9A6700"), lipgloss.Color("#D29922")),
		bad:       c(lipgloss.Color("#CF222E"), lipgloss.Color("#F85149")),
		selBg:     c(lipgloss.Color("#EAF2FB"), lipgloss.Color("#13233A")),
		badgeText: c(lipgloss.Color("#FFFFFF"), lipgloss.Color("#0B1A2B")),
		keyBg:     c(lipgloss.Color("#E6EAEF"), lipgloss.Color("#262C36")),
	}
}

func (t *theme) style() lipgloss.Style  { return lipgloss.NewStyle().Foreground(t.text) }
func (t *theme) dimmed() lipgloss.Style { return lipgloss.NewStyle().Foreground(t.dim) }
func (t *theme) lines() lipgloss.Style  { return lipgloss.NewStyle().Foreground(t.border) }
func (t *theme) accented() lipgloss.Style {
	return lipgloss.NewStyle().Foreground(t.accent)
}

// key is a key's name drawn as a key: a small label.
func (t *theme) key(name string) string {
	return lipgloss.NewStyle().Foreground(t.accent).Background(t.keyBg).Bold(true).Padding(0, 1).Render(name)
}

// hints are keys and what they do, as a line: each a key's name and a
// word or two.
func (t *theme) hints(pairs ...[2]string) string {
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = t.key(p[0]) + " " + t.dimmed().Render(p[1])
	}
	return strings.Join(parts, "  ")
}

// field is content in a form's input: a bar beside it, in the accent
// colour while it's the one being typed in.
func (t *theme) field(focused bool, content string) string {
	c := t.faint
	if focused {
		c = t.accent
	}
	return lipgloss.NewStyle().Border(lipgloss.ThickBorder(), false, false, false, true).BorderForeground(c).
		PaddingLeft(1).MarginLeft(1).Render(content)
}

// behind is the app as drawn, dimmed, for a panel or a form to sit over.
func (t *theme) behind(app string) string {
	return lipgloss.NewStyle().Foreground(t.faint).Render(ansi.Strip(app))
}

// kindColor is the colour each kind of entry is marked with.
func (t *theme) kindColor(k vault.Kind) color.Color {
	switch k {
	case vault.KindTOTP:
		return t.ok
	case vault.KindAPIKey:
		return t.warn
	case vault.KindNote, vault.KindFile:
		return t.dim
	}
	return t.accent
}
