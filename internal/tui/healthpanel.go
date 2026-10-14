package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/bashhack/sesh/internal/health"
	"github.com/bashhack/sesh/internal/vault"
)

// healthMsg is the health report, or why it couldn't be made.
type healthMsg struct {
	err    error
	report health.Report
	epoch  int
}

// openHealth opens the health report, checked now.
func (m *Model) openHealth() tea.Cmd {
	m.ov = &overlay{kind: panelHealth, back: m.ov, title: "Health report", loading: true}
	epoch, now, oldAfter := m.epoch, m.opts.Now(), m.opts.OldAfter
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		r, err := v.Health(now, oldAfter)
		return healthMsg{report: r, err: err, epoch: epoch}
	})
}

// showHealth lists the report's problems in the open panel, each a row
// that goes to its entry to change it.
func (m *Model) showHealth(r *health.Report) {
	ov := m.ov
	checked := countOfKeys(r.Checked)
	if r.Problems() == 0 {
		ov.title = "Health report: no problems in " + checked
		return
	}
	ov.title = fmt.Sprintf("Health report: %d %s in %s", r.Problems(), plural(r.Problems(), "problem", "problems"), checked)
	group := func(rows []item) {
		if len(rows) > 0 && len(ov.items) > 0 {
			rows[0].rule = true
		}
		ov.items = append(ov.items, rows...)
	}
	var rows []item
	for _, k := range r.Weak {
		rows = append(rows, m.healthRow(k, "weak: easy to guess"))
	}
	group(rows)
	rows = nil
	for _, g := range r.Reused {
		for _, k := range g {
			var others []string
			for _, o := range g {
				if o != k {
					others = append(others, keyName(o))
				}
			}
			rows = append(rows, m.healthRow(k, "reused: same as "+strings.Join(others, ", ")))
		}
	}
	group(rows)
	rows = nil
	now := m.opts.Now()
	for _, a := range r.Old {
		rows = append(rows, m.healthRow(a.Key, "old: changed "+ago(now, a.Changed)))
	}
	group(rows)
	rows = nil
	for _, k := range r.Unreadable {
		rows = append(rows, item{label: kindName(k) + " · can't be read; sesh doctor says more", run: func() tea.Cmd { return nil }})
	}
	group(rows)
}

// countOfKeys is n passwords and API keys in words.
func countOfKeys(n int) string {
	if n == 1 {
		return "1 password or API key"
	}
	return fmt.Sprintf("%d passwords and API keys", n)
}

// healthRow is a row of the report about k, which goes to it to change it.
func (m *Model) healthRow(k vault.Key, why string) item {
	return item{label: keyName(k) + " · " + why, run: func() tea.Cmd { return m.goEdit(k) }}
}

// goEdit shows every entry, selects k, and opens its form once it's
// listed (and its notes are read): for a password, set to generate a new
// one.
func (m *Model) goEdit(k vault.Key) tea.Cmd {
	m.ov = nil
	m.input.SetValue("")
	m.filter = sideRow{kind: sideAll, label: "All"}
	m.selKey, m.editing = k, k
	return m.search()
}

// editWhenReady opens the form goEdit asked for, once its entry is
// selected and its notes held; listed says the list has just been read,
// so an entry not in it is gone.
func (m *Model) editWhenReady(listed bool) tea.Cmd {
	k := m.editing
	if k == (vault.Key{}) {
		return nil
	}
	e := m.selected()
	switch {
	case e == nil || e.Key != k:
		if listed {
			m.editing = vault.Key{}
			m.sayBad(keyName(k) + " isn't in the vault any more.")
		}
		return nil
	case hasNotes(e) && m.notes[k] == nil && m.notesFailed[k] == "":
		return nil // its notes are still being read
	}
	m.editing = vault.Key{}
	choice := ""
	if e.Kind == vault.KindPassword {
		choice = secretGenerate
	}
	return m.openEditWith(e, choice)
}
