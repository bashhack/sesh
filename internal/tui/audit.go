package tui

import (
	"errors"
	"fmt"
	"strconv"

	tea "charm.land/bubbletea/v2"
)

// auditShown is how many of the audit log's newest events its panel
// lists; sesh audit --limit 0 lists them all.
const auditShown = 500

// auditMsg is the audit log, read for its panel, and what a prune did.
type auditMsg struct {
	err   error
	said  string
	log   AuditLog
	epoch int
}

// openAudit shows the audit log's newest events in a panel over the
// settings, to read.
func (m *Model) openAudit() tea.Cmd {
	m.ov = &overlay{kind: panelAudit, back: m.ov, title: "Audit log", loading: true}
	epoch := m.epoch
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		log, err := v.AuditLog(auditShown)
		return auditMsg{log: log, err: err, epoch: epoch}
	})
}

// showAudit lists the events in the open panel, the newest first, each
// with its time, what was done, and to what.
func (m *Model) showAudit(log *AuditLog) {
	ov, th := m.ov, m.th
	ov.items, ov.filled = nil, true
	if log.Count == 0 {
		ov.title = "Audit log: no events"
		return
	}
	ov.title = fmt.Sprintf("Audit log: %s since %s", plural(int(log.Count), "1 event", fmt.Sprintf("%d events", log.Count)), log.Oldest.Local().Format("2006-01-02"))
	for _, e := range log.Events {
		when := e.When.Local().Format("2006-01-02 15:04")
		ov.items = append(ov.items, item{
			label:  th.dimmed().Render(when) + "  " + fitTo(e.Event, 6) + "  " + e.What,
			detail: e.When.Local().Format("2006-01-02 15:04:05") + " · " + e.Event + " · " + e.What,
			stay:   true,
			run:    func() tea.Cmd { return nil },
		})
	}
	more := log.Keep
	if n := int64(len(log.Events)); log.Count > n {
		more = fmt.Sprintf("The newest %d of %d are shown; sesh audit --limit 0 lists them all. ", n, log.Count) + more
	}
	if more != "" {
		ov.items = append(ov.items, item{label: th.dimmed().Render(more), detail: more, stay: true, rule: true, run: func() tea.Cmd { return nil }})
	}
}

// gotAudit fills the audit log's panel, when it's open.
func (m *Model) gotAudit(msg *auditMsg) tea.Cmd {
	if msg.epoch != m.epoch || m.ov == nil || m.ov.kind != panelAudit {
		return nil
	}
	if msg.err != nil && !errors.Is(msg.err, ErrLocked) && msg.log.Count > 0 {
		m.ov.loading, m.ov.err = false, msg.err.Error()
		m.showAudit(&msg.log)
		return nil
	}
	return m.loaded(msg.err, func() {
		m.showAudit(&msg.log)
		if msg.said != "" {
			m.say(msg.said)
		}
	})
}

// askPrune asks how old the events to delete are, then, after a yes,
// deletes them and lists what's left.
func (m *Model) askPrune() tea.Cmd {
	panel := m.ov
	return m.askOver(true, "Prune the audit log", "older than, in days", "", "0 deletes every event; audit.retention_days does this on its own", nil, func(typed string) (string, tea.Cmd) {
		days, err := strconv.Atoi(typed)
		if err != nil || days < 0 {
			return "A whole number of days: 0 or more.", nil
		}
		what := fmt.Sprintf("the audit log's events older than %s", plural(days, "1 day", fmt.Sprintf("%d days", days)))
		if days == 0 {
			what = "every event in the audit log"
		}
		m.ov = m.confirm(panel, "Prune the audit log", "Delete "+what+"? They can't be brought back.", func() tea.Cmd {
			m.ov = panel
			panel.loading = true
			epoch := m.epoch
			return m.read(func(v Vault, _ func() bool) tea.Msg {
				said, err := v.PruneAudit(days)
				if err != nil {
					// What's left, under why: a compact that failed may
					// follow a prune that went through.
					log, lerr := v.AuditLog(auditShown)
					if lerr != nil {
						return auditMsg{err: err, epoch: epoch}
					}
					return auditMsg{log: log, err: err, epoch: epoch}
				}
				log, err := v.AuditLog(auditShown)
				return auditMsg{log: log, err: err, said: said, epoch: epoch}
			})
		})
		m.ov.danger = true
		return "", nil
	})
}
