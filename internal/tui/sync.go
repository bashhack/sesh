package tui

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
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
// An import being written or previewed holds the app's syncs till it ends.
func (m *Model) syncDue(now time.Time) (SyncHow, bool) {
	if m.opts.Sync == nil || m.syncing || m.importing != nil {
		return 0, false
	}
	how := SyncPush
	switch {
	case m.lastPull.IsZero() || since(now, m.lastPull) >= syncEvery:
		m.lastPull, m.lastPush, how = now, now, SyncPull
	case since(now, m.lastPush) >= pushEvery:
		m.lastPush = now
	default:
		return 0, false
	}
	if m.opts.AutoSync != nil && !m.opts.AutoSync() {
		return 0, false
	}
	return how, true
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
	if isSyncPanel(m.ov) {
		m.fillSync(nil)
	}
	return m.checkAfter(SyncNow, true)
}

// checkAfter checks the vault, after syncing it as how says when sync is
// true: whether it can still be read, and whether it changed.
func (m *Model) checkAfter(how SyncHow, sync bool) tea.Cmd {
	epoch, run := m.epoch, m.opts.Sync
	read := m.read(func(v Vault, _ func() bool) tea.Msg {
		var said, all []string
		var ran bool
		if sync {
			said, all, ran = run(v, how)
		}
		changed, err := v.Check()
		return checkedMsg{changed: changed, err: err, epoch: epoch, synced: said, all: all, didSync: sync, ran: ran}
	})
	// A vault closed before it ran (locked) still ends the sync, so the
	// next can run.
	return func() tea.Msg {
		if msg := read(); msg != nil || !sync {
			return msg
		}
		return checkedMsg{epoch: epoch, didSync: true}
	}
}

// saySynced says what a sync did, in one status line: as gone wrong when any
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
	switch {
	case m.syncing:
		label = "syncing…"
	case !m.lastSynced.IsZero():
		label += " (last " + m.lastSynced.Local().Format("15:04") + ")"
	}
	return &item{key: "s", label: label, run: m.syncNow}
}

// SyncState is the vault's syncing, as the sync row shows it.
type SyncState struct {
	// Said is its state in a few words: "off", or the sync folder.
	Said string
	// Lines are what sesh sync status says, line by line: a warning or a
	// problem starting ⚠️ or ❌.
	Lines []string
	// On says the vault syncs; KeyChanged, that the master password was
	// changed on another computer, and nothing syncs till it's taken.
	On, KeyChanged bool
}

// syncRow is the settings panel's row for syncing.
func (m *Model) syncRow(st SyncState) item {
	said := st.Said
	if st.On && !m.lastSynced.IsZero() {
		said += ", synced " + m.lastSynced.Local().Format("15:04")
	}
	detail := "Not syncing with other computers. sesh sync init <folder> makes a sync folder from this vault; on another computer, sesh sync join <folder>."
	does := "see how"
	if m.opts.StartSync != nil {
		detail = "Not syncing with other computers. Enter asks for a folder a sync tool keeps the same on your computers, and makes it this vault's sync folder, as sesh sync init does; on each other computer, sesh sync join it."
		does = "start syncing"
	}
	if st.On {
		detail = strings.Join(st.Lines, "\n")
		does = "see it"
	}
	return item{
		label:  fmt.Sprintf("%-25s %s", "Sync", said),
		detail: detail,
		does:   does,
		run:    func() tea.Cmd { return m.openSync(st) },
		stay:   true,
	}
}

// openSync shows the vault's syncing: what sesh sync status says, then
// syncing now and the last sync's results.
func (m *Model) openSync(st SyncState) tea.Cmd {
	if !st.On {
		if m.opts.StartSync == nil {
			m.say("Not syncing: sesh sync init <folder> makes a sync folder from this vault.")
			return nil
		}
		return m.startSync()
	}
	m.ov = &overlay{kind: panelMenu, back: m.ov, title: "Sync"}
	m.syncPanel = st
	m.fillSync(nil)
	return nil
}

// isSyncPanel says whether ov is the sync panel.
func isSyncPanel(ov *overlay) bool {
	return ov != nil && ov.kind == panelMenu && ov.title == "Sync"
}

// fillSync lists the open sync panel's rows: what the sync just run from
// it said (just), what sesh sync status says (m.syncPanel), then what can
// be done.
func (m *Model) fillSync(just []string) {
	ov, st := m.ov, m.syncPanel
	sel := ov.sel
	ov.items = nil
	for _, l := range just {
		ov.items = append(ov.items, m.lineItem(l))
	}
	for i, l := range st.Lines {
		it := m.lineItem(l)
		it.rule = i == 0 && len(just) > 0
		ov.items = append(ov.items, it)
	}
	if st.KeyChanged && m.opts.TakeKeyChange != nil {
		ov.items = append(ov.items, item{key: "p", label: "take the new master password…", rule: true, stay: true, run: m.takeKeyChange})
	}
	if it := m.syncItem(); it != nil {
		it.rule, it.stay = !st.KeyChanged || m.opts.TakeKeyChange == nil, true
		ov.items = append(ov.items, *it)
	}
	if it := m.resultsItem("r"); it != nil {
		ov.items = append(ov.items, *it)
	}
	if leave := m.opts.LeaveSync; leave != nil {
		settings := ov.back
		ov.items = append(ov.items, item{key: "x", label: "leave…", stay: true, run: func() tea.Cmd {
			m.ov = m.confirm(settings, "Sync", "Stop syncing with "+st.Said+"? This vault's entries stay as they are, and so does the folder for your other computers; sesh sync join joins it again, merging what changed meanwhile.", func() tea.Cmd {
				m.ov = settings
				return func() tea.Msg {
					said, err := leave()
					return syncSetMsg{said: said, err: err}
				}
			})
			m.ov.danger = true
			return nil
		}})
	}
	ov.sel = min(sel, max(len(ov.items)-1, 0))
}

// syncPanelMsg is what sesh sync status says after a sync run from the
// sync panel, and what that sync said.
type syncPanelMsg struct {
	just []string
	st   SyncState
}

// refreshSync reads the sync panel's status again after a sync, to show
// with what the sync said.
func (m *Model) refreshSync(just []string) tea.Cmd {
	get := m.opts.SyncState
	if get == nil {
		return nil
	}
	return func() tea.Msg {
		st, err := get()
		if err != nil {
			st.Lines = append(st.Lines, "❌ "+err.Error())
		}
		return syncPanelMsg{st: st, just: just}
	}
}

// takeKeyChange asks for this vault's master password and the new one,
// the other computers', and takes the change, as sesh sync does.
func (m *Model) takeKeyChange() tea.Cmd {
	note, epoch := m.opts.KeyChangeNote, m.epoch
	if note == nil {
		return m.keyChangeForm("")
	}
	m.say("Reading the master password change…")
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		return keyNoteMsg{note: note(v), epoch: epoch}
	})
}

// keyNoteMsg is what to know before taking a master password change.
type keyNoteMsg struct {
	note  string
	epoch int
}

// keyChangeForm is the form taking the master password change, saying
// note too.
func (m *Model) keyChangeForm(note string) tea.Cmd {
	current := &input{kind: inputSecret, label: "this vault's master password", prompt: "the one it opens with now"}
	next := &input{kind: inputSecret, label: "the new master password", prompt: "the one your other computers use"}
	f := &form{title: "Take the new master password", inputs: []*input{current, next}, row: -1, enterDone: "take it",
		working: "Taking the new master password…", quitting: "Quitting once the new master password is taken…"}
	f.note = "The master password was changed on another computer. This vault is re-encrypted under the new one, and syncs again."
	if note != "" {
		f.note += " " + note
	}
	f.submit = func() tea.Cmd {
		switch {
		case len(current.secret) == 0:
			f.err = "Type this vault's master password."
		case len(next.secret) == 0:
			f.err = "Type the new master password, the one your other computers use."
		default:
			return m.runChangeWith(m.opts.TakeKeyChange, bytes.Clone(current.secret), bytes.Clone(next.secret))
		}
		return nil
	}
	f.focusInput(0)
	m.form = f
	return nil
}

// syncSetMsg is syncing started or stopped: what was said, or why not.
type syncSetMsg struct {
	err  error
	said string
	lost bool // not run: the vault was closed first
}

// startSync asks for the folder to sync through, then makes it the
// vault's sync folder and syncs, as sesh sync init does.
func (m *Model) startSync() tea.Cmd {
	offer := ""
	if m.opts.SyncFolderOffer != nil {
		offer = m.opts.SyncFolderOffer()
	}
	start := m.opts.StartSync
	return m.askOver(true, "Start syncing", "Folder", offer, "A folder a sync tool keeps the same on your computers (iCloud Drive, Dropbox, Syncthing), as a full path or from ~/. It's made the sync folder of this vault; on each other computer, sesh sync join it.", nil, func(dir string) (string, tea.Cmd) {
		dir = strings.TrimSpace(dir)
		switch {
		case dir == "":
			return "Type the folder to sync through.", nil
		case !strings.HasPrefix(dir, "~/") && !strings.HasPrefix(dir, "/"):
			return "Type the folder as a full path, or one from ~/.", nil
		case m.syncing:
			return "A sync is under way; press Enter again in a moment.", nil
		}
		m.say("Making the sync folder…")
		// No sync of the app's own meanwhile: the first is this one.
		m.syncing = true
		read := m.read(func(v Vault, _ func() bool) tea.Msg {
			said, err := start(v, dir)
			return syncSetMsg{said: said, err: err}
		})
		// A vault closed before it ran (locked) still ends it, so the
		// app's syncs go on after.
		return "", func() tea.Msg {
			if msg := read(); msg != nil {
				return msg
			}
			return syncSetMsg{lost: true}
		}
	})
}

// gotSyncSet says what starting or stopping syncing did, and shows the
// settings again as they are now.
func (m *Model) gotSyncSet(msg syncSetMsg) tea.Cmd {
	m.syncing = false
	if msg.lost {
		return nil
	}
	if msg.err != nil {
		m.sayBad(msg.err.Error())
	} else {
		m.say(msg.said)
	}
	if m.ov != nil && m.ov.kind == panelSettings {
		return m.refreshSettings()
	}
	return nil
}

// lineItem is a line of what sync said, as a row: marked as gone wrong
// when it's a warning or a problem, the whole of it below while selected.
func (m *Model) lineItem(l string) item {
	label := l
	if strings.HasPrefix(l, "⚠️") || strings.HasPrefix(l, "❌") {
		label = lipgloss.NewStyle().Foreground(m.th.warn).Render(l)
	}
	// Whole below only when the row cuts it.
	return item{label: label, detail: l, cut: true, stay: true, run: func() tea.Cmd { return nil }}
}

// resultsItem opens what the last sync that said something said; nil
// when none has yet.
func (m *Model) resultsItem(key string) *item {
	if len(m.lastSaid) == 0 {
		return nil
	}
	return &item{key: key, label: "last sync's results (" + m.lastSaidAt.Local().Format("15:04") + ")…", stay: true, run: m.openResults}
}

// openResults lists every line the last sync that said something said,
// each one whole below it while selected.
func (m *Model) openResults() tea.Cmd {
	ov := &overlay{kind: panelMenu, back: m.ov, title: "Last sync's results, " + m.lastSaidAt.Local().Format("2006-01-02 15:04")}
	for _, l := range m.lastSaid {
		ov.items = append(ov.items, m.lineItem(l))
	}
	m.ov = ov
	return nil
}
