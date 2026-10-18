package tui

import (
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
)

// SyncHow is why the app syncs the vault with its sync folder.
type SyncHow int

// The reasons.
const (
	// SyncPull: as the app opens the vault, and every syncEvery after,
	// to take what changed on the other computers.
	SyncPull SyncHow = iota
	// SyncPush: to send a change made in the app, if there's one.
	SyncPush
	// SyncNow: asked for.
	SyncNow
)

// syncEvery is how often the app takes what changed on the other
// computers while it's open and unlocked (decided with the user), and
// pushEvery how often it looks for a change of its own to send.
const (
	syncEvery = 5 * time.Minute
	pushEvery = 3 * time.Second
)

// syncDue says whether a sync is due at now, and why: none while one is
// under way, or the vault doesn't sync.
func (m *Model) syncDue(now time.Time) (SyncHow, bool) {
	if m.opts.Sync == nil || m.syncing {
		return 0, false
	}
	switch {
	case m.lastPull.IsZero() || since(now, m.lastPull) >= syncEvery:
		m.lastPull, m.lastPush = now, now
		return SyncPull, true
	case since(now, m.lastPush) >= pushEvery:
		m.lastPush = now
		return SyncPush, true
	}
	return 0, false
}

// syncNow syncs the vault now, as asked.
func (m *Model) syncNow() tea.Cmd {
	if m.syncing {
		m.say("A sync is under way.")
		return nil
	}
	m.syncing = true
	now := m.opts.Now()
	m.lastPull, m.lastPush = now, now
	m.say("Syncing…")
	return m.checkAfter(SyncNow, true)
}

// checkAfter checks the vault, after syncing it as how says when sync is
// true: whether it can still be read, and whether it changed.
func (m *Model) checkAfter(how SyncHow, sync bool) tea.Cmd {
	epoch, run := m.epoch, m.opts.Sync
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		var said []string
		if sync {
			said = run(v, how)
		}
		changed, err := v.Check()
		return checkedMsg{changed: changed, err: err, epoch: epoch, synced: said, didSync: sync}
	})
}

// sayed says what a sync did, in one status line: as gone wrong when any
// of it is a warning or a problem.
func (m *Model) saySynced(lines []string) {
	if len(lines) == 0 {
		return
	}
	said := strings.Join(lines, " ")
	for _, l := range lines {
		if strings.HasPrefix(l, "⚠️") || strings.HasPrefix(l, "❌") {
			m.sayBad(said)
			return
		}
	}
	m.say(said)
}

// syncItem is the sesh menu's item syncing now, saying when the app last
// synced; nil when the vault doesn't sync.
func (m *Model) syncItem() *item {
	if m.opts.Sync == nil || m.opts.Syncing == nil || !m.opts.Syncing() {
		return nil
	}
	label := "sync now"
	if !m.lastSynced.IsZero() {
		label += " (last " + m.lastSynced.Local().Format("15:04") + ")"
	}
	return &item{key: "s", label: label, run: m.syncNow}
}
