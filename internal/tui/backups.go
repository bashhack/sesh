package tui

import (
	"errors"
	"fmt"
	"time"

	tea "charm.land/bubbletea/v2"
)

// Backup is a backup of the vault, as the backups panel lists it.
type Backup struct {
	Made time.Time
	Name string // its file's name
	Path string
	Size string // as said: "1.2 MB"
	// Other is another vault's, with the same file name: it opens with
	// that vault's master password.
	Other bool
}

// Backups is the vault's backups, newest first, and the folder they're in.
type Backups struct {
	Dir  string // as said: "~/…/backups"
	List []Backup
}

// Messages from the backups panel.
type (
	backupsMsg struct {
		err     error
		backups Backups
	}
	// backedUpMsg is a backup made or deleted, said, or why not; the panel
	// is read again.
	backedUpMsg struct {
		err   error
		said  string
		to    string // the file a backup to one was asked for
		epoch int
	}
	restorePlanMsg struct {
		err      error
		question string
		path     string
		epoch    int
	}
	restoredMsg struct {
		err  error
		said string
	}
)

// openBackups opens the backups panel.
func (m *Model) openBackups() tea.Cmd {
	if m.opts.Backups == nil {
		m.sayBad("Backups can't be shown here.")
		return nil
	}
	m.ov = &overlay{kind: panelBackups, back: m.ov, title: "Backups", loading: true}
	return m.readBackups()
}

// readBackups reads the backups into the open panel.
func (m *Model) readBackups() tea.Cmd {
	read := m.opts.Backups
	return func() tea.Msg {
		b, err := read()
		return backupsMsg{backups: b, err: err}
	}
}

// backupsPanel is the backups panel, when it's open: on top, or under a
// question about it.
func (m *Model) backupsPanel() *overlay {
	for ov := m.ov; ov != nil; ov = ov.back {
		if ov.kind == panelBackups {
			return ov
		}
	}
	return nil
}

// gotBackups lists the backups in their panel, when it's open.
func (m *Model) gotBackups(msg *backupsMsg) tea.Cmd {
	panel := m.backupsPanel()
	if panel == nil {
		return nil
	}
	top := m.ov
	m.ov = panel
	cmd := m.loaded(msg.err, func() { m.showBackups(msg.backups) })
	if m.ov == panel {
		m.ov = top
	}
	return cmd
}

// showBackups lists b in the open panel.
func (m *Model) showBackups(b Backups) {
	ov := m.ov
	ov.title, ov.filled = "Backups in "+b.Dir, true
	ov.items, ov.backups = nil, b.List
	for _, bk := range b.List {
		other, detail := "", bk.Name+". Enter restores the vault from it, backing up the vault as it is first; n backs up now, f to a file, x deletes this one, a deletes this vault's and makes a fresh one."
		if bk.Other {
			other = "(another vault) "
			detail = bk.Name + " is another vault's backup, with the same file name: it opens with that vault's master password. Enter restores the vault from it, backing up the vault as it is first; x deletes it."
		}
		path := bk.Path
		ov.items = append(ov.items, item{
			label:  fmt.Sprintf("%s  %8s  %s%s", bk.Made.Local().Format("2006-01-02 15:04"), bk.Size, other, bk.Name),
			detail: detail,
			run:    func() tea.Cmd { return m.planRestore(path) },
			stay:   true,
		})
	}
	ov.sel = min(ov.sel, max(len(ov.items)-1, 0))
}

// backupsLetter is what the backups panel's letters do: back up now (n),
// to a file (f), delete the selected backup (x), or this vault's all, with
// a fresh one made (a).
func (m *Model) backupsLetter(k string) tea.Cmd {
	panel := m.ov
	switch k {
	case "n":
		return m.backUp("", false)
	case "f":
		return m.askOver(true, "Back up to a file", "file, or a folder", "", "~ is your home folder; in a folder, it's named as the backups folder names it", nil, func(to string) (string, tea.Cmd) {
			if to == "" {
				return "Type where to put it.", nil
			}
			return "", m.backUp(to, false)
		})
	case "x", "delete":
		if panel.sel >= len(panel.backups) {
			return nil
		}
		b := panel.backups[panel.sel]
		other := ""
		if b.Other {
			other = " It's another vault's."
		}
		m.ov = m.confirm(panel, "Delete a backup", "Delete the backup "+short(b.Name)+"?"+other+" It can't be brought back.", func() tea.Cmd {
			m.ov = panel
			return m.backupChange(func() (string, error) { return m.opts.DeleteBackup(b.Path) })
		})
		m.ov.danger = true
	case "a":
		if m.opts.RenewBackups == nil {
			return nil
		}
		m.ov = m.confirm(panel, "Delete the backups", "Delete this vault's backups and make a fresh one? The ones deleted can't be brought back: do this when an old master password or recovery key may have leaked, since they still open with it.", func() tea.Cmd {
			m.ov = panel
			return m.backupChange(m.opts.RenewBackups)
		})
		m.ov.danger = true
	}
	return nil
}

// backUp backs up the vault: into the backups folder when to is "", or to
// the file to names, replacing one there only when replace.
func (m *Model) backUp(to string, replace bool) tea.Cmd {
	back, epoch := m.opts.BackUp, m.epoch
	return func() tea.Msg {
		said, err := back(to, replace)
		return backedUpMsg{said: said, err: err, to: to, epoch: epoch}
	}
}

// backupChange runs a change to the backups, saying what it did.
func (m *Model) backupChange(change func() (string, error)) tea.Cmd {
	epoch := m.epoch
	return func() tea.Msg {
		said, err := change()
		return backedUpMsg{said: said, err: err, epoch: epoch}
	}
}

// backedUp says what a change to the backups did, asking first whether to
// replace a file a backup to one would; the list is read again.
func (m *Model) backedUp(msg *backedUpMsg) tea.Cmd {
	if msg.epoch != m.epoch || m.v == nil {
		return nil
	}
	switch {
	case errors.Is(msg.err, ErrExists) && m.backupsPanel() != nil:
		panel, to := m.backupsPanel(), msg.to
		m.ov = m.confirm(panel, "Back up to a file", msg.err.Error()+" Replace it with a backup of the vault now?", func() tea.Cmd {
			m.ov = panel
			return m.backUp(to, true)
		})
		m.ov.danger = true
		return nil
	case msg.err != nil:
		m.backupsSaid(msg.err.Error(), true)
	default:
		m.backupsSaid(msg.said, false)
	}
	return m.readBackups()
}

// backupsSaid says what happened to the backups: in their panel when it's
// open, a failure, and otherwise below.
func (m *Model) backupsSaid(said string, bad bool) {
	if p := m.backupsPanel(); p != nil && bad {
		p.err = said
		return
	}
	if bad {
		m.sayBad(said)
		return
	}
	m.say(said)
}

// planRestore says what restoring the vault from the backup at path will
// do, to ask.
func (m *Model) planRestore(path string) tea.Cmd {
	plan, epoch := m.opts.PlanRestore, m.epoch
	return func() tea.Msg {
		q, err := plan(path)
		return restorePlanMsg{question: q, err: err, path: path, epoch: epoch}
	}
}

// askRestore asks whether to restore the vault as planned.
func (m *Model) askRestore(msg *restorePlanMsg) tea.Cmd {
	panel := m.backupsPanel()
	if msg.epoch != m.epoch || m.v == nil || panel == nil {
		return nil
	}
	if msg.err != nil {
		m.backupsSaid("Not restored: "+msg.err.Error(), true)
		return nil
	}
	path := msg.path
	m.ov = m.confirm(panel, "Restore", msg.question+"\n\nsesh ui locks after, to be unlocked with the master password the backup had.", func() tea.Cmd {
		m.ov = panel
		return m.runRestore(path)
	})
	m.ov.danger = true
	return nil
}

// runRestore restores the vault from the backup at path. The vault the app
// has open changes under it, so nothing reads it meanwhile, as when the
// master password changes; then the app locks.
func (m *Model) runRestore(path string) tea.Cmd {
	m.changing = true
	m.checking = false
	clear(m.pending)
	clear(m.notesPending)
	m.epoch++
	if p := m.backupsPanel(); p != nil {
		p.loading, p.busy = true, "Restoring the vault…"
	}
	restore := m.opts.Restore
	return func() tea.Msg {
		said, err := restore(path)
		return restoredMsg{said: said, err: err}
	}
}

// restored locks the app on the vault restored, or says why it wasn't.
func (m *Model) restored(msg *restoredMsg) tea.Cmd {
	m.changing = false
	m.lastKey = m.opts.Now()
	if p := m.backupsPanel(); p != nil {
		p.loading, p.busy = false, ""
	}
	if m.quitAfter {
		m.afterword = msg.said
		if msg.err != nil {
			m.afterword = "The vault wasn't restored: " + msg.err.Error()
		}
		return tea.Quit
	}
	switch {
	case m.v == nil:
		return nil
	case errors.Is(msg.err, ErrLocked):
		return m.lock(lockedReason(msg.err))
	case msg.err != nil:
		m.backupsSaid("Not restored: "+msg.err.Error(), true)
		return tea.Batch(m.reread(), m.readBackups())
	}
	return m.lock(msg.said + " Unlock it with the master password the backup had.")
}
