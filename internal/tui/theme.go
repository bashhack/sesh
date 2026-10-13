package tui

import (
	"image/color"

	"charm.land/lipgloss/v2"

	"github.com/bashhack/sesh/internal/vault"
)

// theme is the app's colours, for a dark terminal or a light one, and the
// styles made from them.
type theme struct {
	accent, text, dim, faint, border, ok, warn, bad, selBg, badgeText color.Color
}

func newTheme(dark bool) theme {
	c := lipgloss.LightDark(dark)
	return theme{
		accent:    c(lipgloss.Color("#6E40C9"), lipgloss.Color("#B392F0")),
		text:      c(lipgloss.Color("#1F2328"), lipgloss.Color("#E6EDF3")),
		dim:       c(lipgloss.Color("#59636E"), lipgloss.Color("#8B949E")),
		faint:     c(lipgloss.Color("#B7BDC8"), lipgloss.Color("#3D444D")),
		border:    c(lipgloss.Color("#D1D9E0"), lipgloss.Color("#3D444D")),
		ok:        c(lipgloss.Color("#1A7F37"), lipgloss.Color("#3FB950")),
		warn:      c(lipgloss.Color("#9A6700"), lipgloss.Color("#D29922")),
		bad:       c(lipgloss.Color("#CF222E"), lipgloss.Color("#F85149")),
		selBg:     c(lipgloss.Color("#F3EEFF"), lipgloss.Color("#2A2140")),
		badgeText: c(lipgloss.Color("#FFFFFF"), lipgloss.Color("#1B1325")),
	}
}

func (t *theme) style() lipgloss.Style  { return lipgloss.NewStyle().Foreground(t.text) }
func (t *theme) dimmed() lipgloss.Style { return lipgloss.NewStyle().Foreground(t.dim) }
func (t *theme) lines() lipgloss.Style  { return lipgloss.NewStyle().Foreground(t.border) }
func (t *theme) accented() lipgloss.Style {
	return lipgloss.NewStyle().Foreground(t.accent)
}

// kindColor is the colour each kind of entry is marked with.
func (t *theme) kindColor(k vault.Kind) color.Color {
	switch k {
	case vault.KindTOTP:
		return t.ok
	case vault.KindAPIKey:
		return t.warn
	case vault.KindNote:
		return t.dim
	}
	return t.accent
}
