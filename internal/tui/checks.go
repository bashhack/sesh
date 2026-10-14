package tui

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// Check is one of sesh doctor's results: its mark ("ok", "warn", "FAIL",
// "-"), what was checked, what was found, and any details.
type Check struct {
	Section string
	Mark    string
	Label   string
	Value   string
	Details []string
}

// Checks are sesh doctor's results, what to do about them, and a line
// summing them up.
type Checks struct {
	Summary string
	Checks  []Check
	ToDo    [][]string // each a step, then the commands it names
}

// checksMsg is the checks, run for the panel.
type checksMsg struct {
	err    error
	checks Checks
	epoch  int
}

// openChecks runs sesh doctor's checks and shows them in a panel over the
// settings.
func (m *Model) openChecks() tea.Cmd {
	m.ov = &overlay{kind: panelChecks, back: m.ov, title: "Checks", loading: true}
	if m.checking {
		return nil // the run already going fills this panel
	}
	m.checking = true
	epoch := m.epoch
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		c, err := v.Checks()
		return checksMsg{checks: c, err: err, epoch: epoch}
	})
}

// showChecks lists the checks in the open panel: a row each, with its
// details under it, then what to do.
func (m *Model) showChecks(c *Checks) {
	th, ov := m.th, m.ov
	ov.title = "Checks: " + c.Summary
	ov.items = nil
	markStyle := func(mark string) lipgloss.Style {
		switch mark {
		case "ok":
			return lipgloss.NewStyle().Foreground(th.ok)
		case "warn":
			return lipgloss.NewStyle().Foreground(th.warn)
		case "FAIL":
			return lipgloss.NewStyle().Foreground(th.bad).Bold(true)
		}
		return th.dimmed()
	}
	part := ""
	for _, ch := range c.Checks {
		it := item{label: markStyle(ch.Mark).Render(fitTo(ch.Mark, 5)) + " " + fitTo(ch.Label, 14) + " " + ch.Value, stay: true, run: func() tea.Cmd { return nil }}
		if ch.Section != part {
			it.rule = len(ov.items) > 0
			part = ch.Section
		}
		it.detail = ch.Label + ": " + strings.Join(append([]string{ch.Value}, ch.Details...), "\n")
		ov.items = append(ov.items, it)
	}
	for i, t := range c.ToDo {
		it := item{label: th.accented().Render("→") + " " + t[0], stay: true, run: func() tea.Cmd { return nil }, rule: i == 0}
		if len(t) > 1 {
			it.detail = "Run: " + strings.Join(t[1:], "\n     ")
		}
		ov.items = append(ov.items, it)
	}
}

// gotChecks fills the checks panel, when it's open.
func (m *Model) gotChecks(msg *checksMsg) tea.Cmd {
	if msg.epoch == m.epoch {
		m.checking = false
	}
	if msg.epoch != m.epoch || m.ov == nil || m.ov.kind != panelChecks {
		return nil
	}
	return m.loaded(msg.err, func() { m.showChecks(&msg.checks) })
}
