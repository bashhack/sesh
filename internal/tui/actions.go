package tui

import (
	"errors"
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

// panel is what's shown over the app: the action menu, or what one of
// its actions opened.
type panel int

const (
	panelMenu     panel = iota + 1 // what can be done to the entry
	panelFields                    // which of its values to copy
	panelHistory                   // its earlier secrets
	panelTrash                     // the trash
	panelConfirm                   // a yes or no before a change
	panelHealth                    // what's wrong with the passwords and API keys
	panelSettings                  // settings and safety
	panelChecks                    // sesh doctor's checks
	panelNotice                    // what a change did, to read
	panelBackups                   // the vault's backups
	panelImport                    // what an import would do
)

// overlay is a panel over the app, about the entry k.
type overlay struct {
	opened   time.Time      // when a confirmation was asked
	yes      func() tea.Cmd // what a confirmation's yes does
	back     *overlay       // what Esc goes back to
	k        vault.Key
	question string // a confirmation's
	title    string
	err      string
	busy     string // said instead of "Loading…" while it waits
	items    []item
	versions []time.Time
	trash    []Trashed
	backups  []Backup // the backups panel's, as its rows list them
	kind     panel
	sel      int
	loading  bool
	danger   bool // a confirmation of something that can't be undone
	wide     bool // drawn as wide as the settings panel: a long question
	filled   bool // a report's rows are in, so none means nothing was found
}

// item is one line of a menu: a key that runs it, what it says, and what
// it does.
type item struct {
	run    func() tea.Cmd
	key    string
	label  string
	detail string // said below the rows while it's the one selected
	does   string // what Enter does to it, when not the panel's usual
	rule   bool   // a line between groups, before it
	stay   bool   // running it leaves the panel open
}

// Messages from the actions.
type (
	historyMsg struct {
		err      error
		k        vault.Key
		versions []time.Time
		epoch    int
	}
	trashMsg struct {
		err   error
		trash []Trashed
		epoch int
	}
	// doneMsg is a change made: what to say, and whether the list is to
	// be read again.
	doneMsg struct {
		err error
		// refilter is a folder or tag renamed from renamed: the sidebar's
		// filter follows it.
		refilter *sideRow
		what     string
		renamed  string
		forget   vault.Key   // an entry whose held values are stale now
		unmark   []vault.Key // marked entries acted on, or gone: unmarked after
		epoch    int
		closes   panel // a panel the change closes, when it's still open
		reread   bool
	}
	// agentLockedMsg is "lock now" having locked the agent, or not.
	agentLockedMsg struct{ err error }
)

// openMenu opens the action menu over the selected entry.
func (m *Model) openMenu() tea.Cmd {
	e := m.selected()
	if e == nil {
		m.ov = &overlay{kind: panelMenu, title: "Actions", items: m.globalItems()}
		return nil
	}
	// Each action is about the entry the menu was opened on, whatever is
	// selected by the time it runs.
	ek := *e
	var items []item
	items = append(items,
		item{key: "e", label: "edit…", run: func() tea.Cmd { return m.openEdit(&ek) }},
		item{key: "f", label: "copy a value…", run: func() tea.Cmd { return m.openFields(&ek) }},
	)
	if e.Username != "" {
		items = append(items, item{key: "u", label: "copy the username", run: func() tea.Cmd { return m.copyUsername(&ek) }})
	}
	if e.URL != "" {
		items = append(items, item{key: "o", label: "open the URL", run: func() tea.Cmd { return m.openURL(&ek) }})
	}
	items = append(items,
		item{key: "h", label: "earlier secrets…", run: func() tea.Cmd { return m.openHistory(&ek) }},
		item{key: "d", label: "move to the trash", run: func() tea.Cmd { return m.confirmDelete(&ek) }},
	)
	g := m.globalItems()
	g[0].rule = true
	m.ov = &overlay{kind: panelMenu, title: entryName(e), k: e.Key, items: append(items, g...)}
	return nil
}

// globalItems are the menu's actions that aren't about one entry.
func (m *Model) globalItems() []item {
	return []item{
		{key: "a", label: "add an entry…", run: m.openAdd},
		{key: "t", label: "the trash…", run: m.openTrash},
		{key: "b", label: "backups…", run: m.openBackups},
		{key: "i", label: "import and export…", run: m.openTransfer},
		{key: "r", label: "health report…", run: m.openHealth},
		{key: ",", label: "settings and safety…", run: m.openSettings},
		{key: "l", label: "lock sesh", run: m.lockNow},
	}
}

// overlayKey handles a key while a panel is open.
func (m *Model) overlayKey(msg tea.KeyPressMsg) tea.Cmd {
	m.lastKey = m.opts.Now()
	ov := m.ov
	k := msg.String()
	switch k {
	case "ctrl+c":
		return tea.Quit
	case "esc":
		if ov.kind == panelImport {
			if m.importing != nil && m.importing.applying {
				// The import under way carries on to the end.
				return nil
			}
			// What the import read is let go, and wiped.
			m.ov = ov.back
			return m.endImport()
		}
		m.ov = ov.back
		return nil
	}
	if m.width < minWidth || m.height < minHeight {
		// The panel isn't on screen: nothing is done unseen.
		return nil
	}
	if ov.kind == panelNotice {
		if k == "enter" {
			m.ov = ov.back
		}
		return nil
	}
	if ov.kind == panelConfirm {
		// Only y is a yes, as sesh's prompts have it (Enter isn't), and
		// not one typed in the same breath as the key that asked: a word
		// typed after Ctrl-K by habit mustn't delete anything.
		switch {
		case k == "y" && m.opts.Now().Sub(ov.opened) >= confirmAfter:
			m.ov = nil
			return ov.yes()
		case k == "n":
			m.ov = ov.back
		}
		return nil
	}
	if ov.loading {
		return nil
	}
	if ov.len() > 0 {
		ov.err = "" // said once; the rows it was about are acted on again
	}
	switch k {
	case "up", "ctrl+p", "k":
		ov.sel--
	case "down", "ctrl+n", "j":
		ov.sel++
	case "enter":
		return m.choose(ov.sel)
	default:
		if ov.kind == panelMenu || ov.kind == panelFields {
			for i, it := range ov.items {
				if it.key == k {
					return m.choose(i)
				}
			}
		}
		return m.panelLetter(k)
	}
	ov.sel = max(min(ov.sel, ov.len()-1), 0)
	return nil
}

// len is how many lines the panel's choice is among.
func (ov *overlay) len() int {
	switch ov.kind {
	case panelHistory:
		return len(ov.versions)
	case panelTrash:
		return len(ov.trash)
	}
	return len(ov.items)
}

// choose does what line i of the open panel does.
func (m *Model) choose(i int) tea.Cmd {
	ov := m.ov
	if i < 0 || i >= ov.len() {
		return nil
	}
	switch ov.kind {
	case panelHistory:
		return m.copyVersion(ov.k, i+2)
	case panelTrash:
		return m.restoreFromTrash(ov.trash[i].ID)
	case panelImport:
		return nil // the summary's lines, to read
	}
	// An action that opens a panel puts it over this one, to go back to;
	// any other closes it.
	cmd := ov.items[i].run()
	if m.ov == ov && !ov.items[i].stay {
		m.ov = nil
	}
	return cmd
}

// panelLetter is what a panel's own letters do: restoring an earlier
// secret, or deleting from the trash for good.
func (m *Model) panelLetter(k string) tea.Cmd {
	ov := m.ov
	switch {
	case ov.kind == panelHistory && k == "r" && ov.sel < len(ov.versions):
		n, key := ov.sel+2, ov.k
		m.ov = m.confirm(ov, "Restore",
			fmt.Sprintf("Make version %d the secret for %s again? The current one is kept as an earlier secret.", n, short(keyName(key))),
			func() tea.Cmd { return m.restoreVersion(key, n) })
	case ov.kind == panelBackups:
		return m.backupsLetter(k)
	case ov.kind == panelImport:
		return m.importLetter(k)
	case ov.kind == panelTrash && (k == "x" || k == "delete") && ov.sel < len(ov.trash):
		id, k := ov.trash[ov.sel].ID, ov.trash[ov.sel].Key
		m.ov = m.confirm(ov, "Delete for good",
			fmt.Sprintf("Delete %s for good? It can't be brought back.", short(kindName(k))),
			func() tea.Cmd { return m.removeFromTrash(id, k) })
		m.ov.danger = true
	}
	return nil
}

// confirm is a yes or no, asked now, over back.
func (m *Model) confirm(back *overlay, title, question string, yes func() tea.Cmd) *overlay {
	return &overlay{kind: panelConfirm, back: back, title: title, question: question, yes: yes, opened: m.opts.Now()}
}

// short is a name cut to fit a question that must stay on screen with
// its keys.
func short(name string) string { return ansi.Truncate(name, 40, "…") }

// confirmAfter is how long after a confirmation is asked a y counts.
const confirmAfter = 400 * time.Millisecond

// openFields lists e's values to copy: its secret, its username and URL,
// and its fields.
func (m *Model) openFields(e *vault.Entry) tea.Cmd {
	ek := *e
	var items []item
	add := func(label string, run func() tea.Cmd) {
		key := ""
		if n := len(items); n < 9 {
			key = fmt.Sprint(n + 1)
		}
		items = append(items, item{key: key, label: label, run: run})
	}
	// Its secret first: the password, key or code, or a secure note's text.
	add(secretWord(ek.Kind), func() tea.Cmd { return m.copySecret(&ek) })
	if notes := m.notes[ek.Key]; ek.Kind != vault.KindNote && len(notes) > 0 {
		// The notes as shown beside the list, which the app holds.
		add("notes", func() tea.Cmd { return m.copyPlain(&ek, "notes", string(m.notes[ek.Key])) })
	}
	if ek.Username != "" {
		add("username", func() tea.Cmd { return m.copyUsername(&ek) })
	}
	if ek.URL != "" {
		add("URL", func() tea.Cmd { return m.copyPlain(&ek, "URL", ek.URL) })
	}
	for _, f := range ek.Fields {
		name := f.Name
		if !f.Secret {
			value := string(f.Value)
			add(name, func() tea.Cmd { return m.copyPlain(&ek, name, value) })
			continue
		}
		add(name+" (secret)", func() tea.Cmd { return m.copyField(&ek, name) })
	}
	m.ov = &overlay{kind: panelFields, back: m.ov, title: "Copy from " + entryName(&ek), items: items}
	return nil
}

// copyPlain copies a value that isn't secret.
func (m *Model) copyPlain(e *vault.Entry, what, value string) tea.Cmd {
	name, opts, epoch := entryName(e), m.opts, m.epoch
	return func() tea.Msg {
		if err := opts.Copy(value); err != nil {
			return copiedMsg{what: "Couldn't copy: " + err.Error(), epoch: epoch, bad: true}
		}
		return copiedMsg{what: copied("the "+what+" for "+name, opts.ClearAfter), epoch: epoch}
	}
}

// copyField copies a secret field's value: a read the audit log records.
func (m *Model) copyField(e *vault.Entry, field string) tea.Cmd {
	k, name, opts, epoch := e.Key, entryName(e), m.opts, m.epoch
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		value, err := v.Field(k, field)
		if err != nil {
			return copiedMsg{err: err, epoch: epoch}
		}
		defer secure.SecureZeroBytes(value)
		if err := opts.Copy(string(value)); err != nil {
			return copiedMsg{what: "Couldn't copy: " + err.Error(), epoch: epoch, bad: true}
		}
		return copiedMsg{what: copied("the "+field+" for "+name, opts.ClearAfter), epoch: epoch}
	})
}

// copied says what was copied, and when the clipboard clears.
func copied(what string, clearAfter time.Duration) string {
	if clearAfter > 0 {
		return "Copied " + what + " · clears in " + spoken(clearAfter)
	}
	return "Copied " + what
}

// openHistory lists e's earlier secrets.
func (m *Model) openHistory(e *vault.Entry) tea.Cmd {
	k, epoch := e.Key, m.epoch
	m.ov = &overlay{kind: panelHistory, back: m.ov, title: "Earlier secrets of " + entryName(e), k: k, loading: true}
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		versions, err := v.History(k)
		return historyMsg{k: k, versions: versions, err: err, epoch: epoch}
	})
}

// copyVersion copies k's version n: a read the audit log records.
func (m *Model) copyVersion(k vault.Key, n int) tea.Cmd {
	opts, epoch := m.opts, m.epoch
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		secret, err := v.ReadVersion(k, n)
		if err != nil {
			return copiedMsg{err: err, epoch: epoch}
		}
		defer secure.SecureZeroBytes(secret)
		if err := opts.Copy(string(secret)); err != nil {
			return copiedMsg{what: "Couldn't copy: " + err.Error(), epoch: epoch, bad: true}
		}
		return copiedMsg{what: copied(fmt.Sprintf("an earlier secret (version %d) for %s", n, keyName(k)), opts.ClearAfter), epoch: epoch}
	})
}

// restoreVersion makes k's version n its secret again.
func (m *Model) restoreVersion(k vault.Key, n int) tea.Cmd {
	epoch := m.epoch
	m.forget(k)
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		err := v.RestoreVersion(k, n)
		return doneMsg{what: fmt.Sprintf("Restored an earlier secret for %s; the one it replaced is kept", keyName(k)), err: err, epoch: epoch, reread: true, forget: k}
	})
}

// confirmDelete asks before moving e to the trash.
func (m *Model) confirmDelete(e *vault.Entry) tea.Cmd {
	k := e.Key
	m.ov = m.confirm(m.ov, "Delete",
		fmt.Sprintf("Move %s to the trash? It can be put back from there.", short(entryName(e))),
		func() tea.Cmd {
			epoch := m.epoch
			return m.read(func(v Vault, _ func() bool) tea.Msg {
				return doneMsg{what: "Moved " + kindName(k) + " to the trash", err: v.Delete(k), epoch: epoch, reread: true, forget: k}
			})
		})
	return nil
}

// forget wipes what the app holds of k: its TOTP key and codes, its
// notes, and its secrets if they're revealed. They're read again when
// next shown.
func (m *Model) forget(k vault.Key) {
	secure.SecureZeroBytes(m.keys[k])
	secure.SecureZeroBytes(m.notes[k])
	delete(m.keys, k)
	delete(m.pending, k)
	delete(m.codes, k)
	delete(m.notes, k)
	delete(m.notesPending, k)
	delete(m.notesFailed, k)
	clear(m.wraps)
	if m.shown != nil && m.shown.k == k {
		m.hide()
	}
}

// openTrash lists the trash.
func (m *Model) openTrash() tea.Cmd {
	epoch := m.epoch
	m.ov = &overlay{kind: panelTrash, back: m.ov, title: "The trash", loading: true}
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		trash, err := v.Trash()
		return trashMsg{trash: trash, err: err, epoch: epoch}
	})
}

// restoreFromTrash puts the trash's entry id back.
func (m *Model) restoreFromTrash(id int64) tea.Cmd {
	epoch := m.epoch
	m.ov.loading = true // no second Enter while this one is put back
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		k, err := v.RestoreFromTrash(id)
		return doneMsg{what: "Restored " + kindName(k) + " from the trash", err: err, epoch: epoch, reread: true, closes: panelTrash}
	})
}

// removeFromTrash deletes the trash's entry id, k, for good.
func (m *Model) removeFromTrash(id int64, k vault.Key) tea.Cmd {
	epoch := m.epoch
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		return doneMsg{what: "Deleted " + kindName(k) + " for good", err: v.RemoveFromTrash(id), epoch: epoch, reread: true}
	})
}

// lockNow locks the app, and the agent with it.
func (m *Model) lockNow() tea.Cmd {
	lockAgent := m.opts.LockAgent
	closing := m.lock("You locked it.")
	if lockAgent == nil {
		return closing
	}
	return tea.Batch(closing, func() tea.Msg { return agentLockedMsg{err: lockAgent()} })
}

// actionResult handles what an action's command came back with.
func (m *Model) actionResult(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case historyMsg:
		if msg.epoch != m.epoch || m.ov == nil || m.ov.kind != panelHistory || m.ov.k != msg.k {
			return nil
		}
		return m.loaded(msg.err, func() { m.ov.versions = msg.versions })
	case trashMsg:
		if msg.epoch != m.epoch || m.ov == nil || m.ov.kind != panelTrash {
			return nil
		}
		return m.loaded(msg.err, func() { m.ov.trash = msg.trash })
	case healthMsg:
		if msg.epoch != m.epoch || m.ov == nil || m.ov.kind != panelHealth {
			return nil
		}
		return m.loaded(msg.err, func() { m.showHealth(&msg.report) })
	case doneMsg:
		if msg.epoch != m.epoch || m.v == nil {
			return nil
		}
		for _, k := range msg.unmark {
			delete(m.marked, k)
		}
		switch {
		case errors.Is(msg.err, ErrLocked):
			return m.lock(lockedReason(msg.err))
		case msg.err != nil && m.ov != nil && m.ov.kind == msg.closes:
			// Said in the panel, which has room for it, and stays open.
			m.ov.err, m.ov.loading = msg.err.Error(), false
			return nil
		case msg.err != nil:
			m.sayBad(msg.err.Error())
		default:
			m.say(msg.what)
			if m.ov != nil && m.ov.kind == msg.closes {
				m.ov = nil
			}
			if msg.forget != (vault.Key{}) {
				m.forget(msg.forget)
			}
			if r := msg.refilter; r != nil && m.filter.kind == r.kind && m.filter.name == msg.renamed {
				m.filter.name = r.name
			}
			// The sidebar's cursor stays on the row renamed.
			if r := msg.refilter; r != nil && m.sideSel < len(m.side) && m.side[m.sideSel].kind == r.kind && m.side[m.sideSel].name == msg.renamed {
				m.side[m.sideSel].name = r.name
			}
		}
		if msg.reread {
			return m.reread()
		}
	}
	return nil
}

// loaded fills a panel with what was read, or says why it couldn't be.
func (m *Model) loaded(err error, fill func()) tea.Cmd {
	m.ov.loading = false
	switch {
	case errors.Is(err, ErrLocked):
		return m.lock(lockedReason(err))
	case err != nil:
		m.ov.err = err.Error()
	default:
		fill()
	}
	return nil
}

// window is the rows [first, last) of n shown when only room fit, the
// selected one among them.
func window(sel, n, room int) (first, last int) {
	if n <= room {
		return 0, n
	}
	first = min(max(sel-room/2, 0), n-room)
	return first, first + room
}

// drawOverlay draws the open panel as a card over the app, base.
func (m *Model) drawOverlay(base string) string {
	th := m.th
	ov := m.ov
	w := min(64, m.width-6)
	if ov.kind == panelSettings || ov.kind == panelChecks || ov.kind == panelBackups || ov.kind == panelImport || ov.wide {
		w = min(96, m.width-6)
	}
	// The rows that fit: the screen less the card's border, title, hint
	// and the blank lines between.
	room := max(m.height-8, 1)
	var lines []string
	row := func(i int, key, text string) string {
		k := "   "
		if key != "" {
			k = th.key(key)
		}
		if i == ov.sel {
			return lipgloss.NewStyle().Background(th.selBg).Render(th.accented().Render("▌") + " " + fitTo(th.style().Bold(true).Render(text), w-12) + " " + k)
		}
		return "  " + fitTo(th.style().Render(text), w-12) + " " + k
	}
	// The selected row's details go below the rows, cut to leave two of
	// those beside them; with less room than that, they're left out.
	var detail string
	itemRoom := room
	if ov.sel < len(ov.items) && ov.items[ov.sel].detail != "" && !ov.loading && room >= 5 {
		said := strings.Split(th.dimmed().Width(w-6).Render(ov.items[ov.sel].detail), "\n")
		if most := room - 3; len(said) > most {
			cut := len(said) - most + 1
			said = append(said[:most-1], th.dimmed().Render(fmt.Sprintf("… and %d more %s", cut, plural(cut, "line", "lines"))))
		}
		detail = strings.Join(said, "\n")
		itemRoom = room - len(said) - 1
	}
	switch {
	case ov.kind == panelConfirm || ov.kind == panelNotice:
		// Its end is cut to fit, keeping the keys that answer it on screen.
		said := strings.Split(th.style().Width(w-6).Render(ov.question), "\n")
		if len(said) > room {
			said = append(said[:max(room-1, 0)], th.dimmed().Render("… (a bigger window shows the rest)"))
		}
		lines = append(lines, "")
		lines = append(lines, said...)
	case ov.loading && ov.busy != "":
		lines = append(lines, "", th.dimmed().Render(ov.busy))
	case ov.loading:
		lines = append(lines, "", th.dimmed().Render("Loading…"))
	case ov.err != "" && ov.len() == 0:
		lines = append(lines, "", lipgloss.NewStyle().Foreground(th.bad).Width(w-6).Render(ov.err))
	case ov.kind == panelBackups && ov.filled && len(ov.items) == 0:
		lines = append(lines, "", th.dimmed().Width(w-6).Render("No backups yet: n backs the vault up now."))
	case ov.kind == panelHealth && ov.filled && len(ov.items) == 0:
		lines = append(lines, "", th.dimmed().Width(w-6).Render("Nothing is weak, used twice, or old."))
	case ov.kind == panelHistory:
		now := m.opts.Now()
		if len(ov.versions) == 0 {
			lines = append(lines, "", th.dimmed().Width(w-6).Render("No earlier secrets: each time this one changes, the one it replaces is kept here."))
		}
		first, last := window(ov.sel, len(ov.versions), room)
		for i := first; i < last; i++ {
			when := "replaced at an unknown time"
			if at := ov.versions[i]; !at.IsZero() {
				when = "replaced " + ago(now, at)
			}
			lines = append(lines, row(i, "", fmt.Sprintf("version %d  %s", i+2, when)))
		}
	case ov.kind == panelTrash:
		now := m.opts.Now()
		if len(ov.trash) == 0 {
			lines = append(lines, "", th.dimmed().Render("The trash is empty."))
		}
		first, last := window(ov.sel, len(ov.trash), room)
		for i := first; i < last; i++ {
			t := ov.trash[i]
			lines = append(lines, row(i, "", fmt.Sprintf("%s  %s", keyName(t.Key), th.dimmed().Render(fmt.Sprintf("%s · deleted %s · id %d", kindLabel(t.Key.Kind), ago(now, t.DeletedAt), t.ID)))))
		}
	default:
		first, last := window(ov.sel, len(ov.items), itemRoom)
		// The lines between groups take room too.
		for range 3 {
			rules := 0
			for i := first + 1; i < last; i++ {
				if ov.items[i].rule {
					rules++
				}
			}
			if last-first+rules <= itemRoom {
				break
			}
			first, last = window(ov.sel, len(ov.items), max(itemRoom-rules, 1))
		}
		for i := first; i < last; i++ {
			it := ov.items[i]
			if it.rule && i > first {
				lines = append(lines, th.lines().Render(strings.Repeat("─", w-6)))
			}
			lines = append(lines, row(i, it.key, it.label))
		}
	}
	if detail != "" {
		lines = append(lines, "", detail)
	}
	if ov.err != "" && ov.len() > 0 && !ov.loading {
		// Above the rows, which stay, since the keys still act on them.
		said := lipgloss.NewStyle().Foreground(th.bad).Width(w - 6).Render(ov.err)
		room = max(room-lipgloss.Height(said)-1, 1)
		lines = append([]string{said, ""}, lines[max(len(lines)-room, 0):]...)
	}
	var hint string
	edge, titleStyle := th.accent, th.accented().Bold(true)
	switch ov.kind {
	case panelHistory:
		hint = th.hints([2]string{"↵", "copy"}, [2]string{"r", "restore"}, [2]string{"esc", "back"})
	case panelTrash:
		hint = th.hints([2]string{"↵", "put back"}, [2]string{"x", "delete for good"}, [2]string{"esc", "back"})
		if len(ov.trash) == 0 {
			hint = th.hints([2]string{"esc", "back"})
		}
	case panelSettings:
		does := "change it"
		if ov.sel < len(ov.items) && ov.items[ov.sel].does != "" {
			does = ov.items[ov.sel].does
		}
		hint = th.hints([2]string{"↵", does}, [2]string{"esc", "back"})
	case panelChecks:
		hint = th.hints([2]string{"↑↓", "read"}, [2]string{"esc", "back"})
	case panelHealth:
		hint = th.hints([2]string{"↵", "change it"}, [2]string{"esc", "back"})
		switch {
		case len(ov.items) == 0:
			hint = th.hints([2]string{"esc", "back"})
		case ov.sel < len(ov.items) && ov.items[ov.sel].stay:
			hint = th.hints([2]string{"↵", "why"}, [2]string{"esc", "back"})
		}
	case panelConfirm:
		hint = th.hints([2]string{"y", "yes"}, [2]string{"n", "no"}, [2]string{"esc", "cancel"})
		if ov.danger {
			edge, titleStyle = th.bad, lipgloss.NewStyle().Foreground(th.bad).Bold(true)
		}
	case panelNotice:
		hint = th.hints([2]string{"↵", "ok"})
	case panelImport:
		hint = m.importHint(w - 6)
	case panelBackups:
		hint = th.hints([2]string{"↵", "restore"}, [2]string{"n", "back up now"}, [2]string{"f", "to a file"}, [2]string{"x", "delete"}, [2]string{"a", "delete all"}, [2]string{"esc", "back"})
		// Narrower, the letters alone, which the selected backup's detail
		// spells out; then only Enter's.
		for _, h := range []string{th.hints([2]string{"↵", "restore"}, [2]string{"n f x a", ""}, [2]string{"esc", "back"}), th.hints([2]string{"↵", "restore"}, [2]string{"esc", "back"})} {
			if lipgloss.Width(hint) > w-6 {
				hint = h
			}
		}
		if len(ov.items) == 0 {
			hint = th.hints([2]string{"n", "back up now"}, [2]string{"f", "to a file"}, [2]string{"esc", "back"})
			if lipgloss.Width(hint) > w-6 {
				hint = th.hints([2]string{"n", "back up"}, [2]string{"esc", "back"})
			}
		}
		if ov.loading && ov.busy != "" {
			hint = th.hints([2]string{"ctrl+c", "quit once it's done"})
		}
	default:
		hint = th.hints([2]string{"↵", "choose, or press its key"}, [2]string{"esc", "back"})
	}
	lines = append(lines, "", hint)
	title := titleStyle.Render(ansi.Truncate(ov.title, w-8, "…"))
	card := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(edge).Padding(0, 2).Width(w).
		Render(lipgloss.JoinVertical(lipgloss.Left, append([]string{title, th.lines().Render(strings.Repeat("─", w-6))}, lines...)...))
	x := max((m.width-lipgloss.Width(card))/2, 0)
	y := max(min((m.height-lipgloss.Height(card))/3, m.height-lipgloss.Height(card)), 0)
	return lipgloss.NewCompositor(lipgloss.NewLayer(th.behind(base)), lipgloss.NewLayer(card).X(x).Y(y).Z(1)).Render()
}
