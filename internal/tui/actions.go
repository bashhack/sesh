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
	panelMenu    panel = iota + 1 // what can be done to the entry
	panelFields                   // which of its values to copy
	panelHistory                  // its earlier secrets
	panelTrash                    // the trash
	panelConfirm                  // a yes or no before a change
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
	items    []item
	versions []time.Time
	trash    []Trashed
	kind     panel
	sel      int
	loading  bool
}

// item is one line of a menu: a key that runs it, what it says, and what
// it does.
type item struct {
	run   func() tea.Cmd
	key   string
	label string
	rule  bool // a line between groups, before it
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
		err    error
		what   string
		forget vault.Key // an entry whose held values are stale now
		epoch  int
		closes panel // a panel the change closes, when it's still open
		reread bool
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
	items = append(items, item{key: "f", label: "copy a value…", run: func() tea.Cmd { return m.openFields(&ek) }})
	if e.Username != "" {
		items = append(items, item{key: "u", label: "copy the username", run: func() tea.Cmd { return m.copyUsername(&ek) }})
	}
	if e.URL != "" {
		items = append(items, item{key: "o", label: "open the URL", run: func() tea.Cmd { return m.openURL(&ek) }})
	}
	items = append(items,
		item{key: "h", label: "earlier secrets…", run: func() tea.Cmd { return m.openHistory(&ek) }},
		item{key: "d", label: "delete (to the trash)", run: func() tea.Cmd { return m.confirmDelete(&ek) }},
	)
	g := m.globalItems()
	g[0].rule = true
	m.ov = &overlay{kind: panelMenu, title: entryName(e), k: e.Key, items: append(items, g...)}
	return nil
}

// globalItems are the menu's actions that aren't about one entry.
func (m *Model) globalItems() []item {
	lockLabel := "lock now"
	if m.opts.LockAgent != nil {
		lockLabel = "lock now, and sesh's agent"
	}
	return []item{
		{key: "t", label: "the trash…", run: m.openTrash},
		{key: "l", label: lockLabel, run: m.lockNow},
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
		m.ov = ov.back
		return nil
	}
	if m.width < minWidth || m.height < minHeight {
		// The panel isn't on screen: nothing is done unseen.
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
	}
	// An action that opens a panel puts it over this one, to go back to;
	// any other closes it.
	cmd := ov.items[i].run()
	if m.ov == ov {
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
			fmt.Sprintf("Make version %d %s's secret again? The secret it replaces is kept.", n, key),
			func() tea.Cmd { return m.restoreVersion(key, n) })
	case ov.kind == panelTrash && (k == "x" || k == "delete") && ov.sel < len(ov.trash):
		id, k := ov.trash[ov.sel].ID, ov.trash[ov.sel].Key
		m.ov = m.confirm(ov, "Delete for good",
			fmt.Sprintf("Delete %s for good? It can't be brought back.", k),
			func() tea.Cmd { return m.removeFromTrash(id, k) })
	}
	return nil
}

// confirm is a yes or no, asked now, over back.
func (m *Model) confirm(back *overlay, title, question string, yes func() tea.Cmd) *overlay {
	return &overlay{kind: panelConfirm, back: back, title: title, question: question, yes: yes, opened: m.opts.Now()}
}

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
	if ek.Kind != vault.KindNote {
		add(secretWord(ek.Kind), func() tea.Cmd { return m.copySecret(&ek) })
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
		return copiedMsg{what: copied(name+"'s "+what, opts.ClearAfter), epoch: epoch}
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
		return copiedMsg{what: copied(name+"'s "+field, opts.ClearAfter), epoch: epoch}
	})
}

// copied says what was copied, and when the clipboard clears.
func copied(what string, clearAfter time.Duration) string {
	if clearAfter > 0 {
		return fmt.Sprintf("Copied %s · clears in %s", what, clearAfter)
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
		return copiedMsg{what: copied(fmt.Sprintf("version %d of %s", n, k), opts.ClearAfter), epoch: epoch}
	})
}

// restoreVersion makes k's version n its secret again.
func (m *Model) restoreVersion(k vault.Key, n int) tea.Cmd {
	epoch := m.epoch
	m.forget(k)
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		err := v.RestoreVersion(k, n)
		return doneMsg{what: fmt.Sprintf("Restored an earlier secret of %s; the one it replaced is kept", k), err: err, epoch: epoch, reread: true, forget: k}
	})
}

// confirmDelete asks before moving e to the trash.
func (m *Model) confirmDelete(e *vault.Entry) tea.Cmd {
	k := e.Key
	m.ov = m.confirm(m.ov, "Delete",
		fmt.Sprintf("Move %s to the trash? It can be put back from there.", entryName(e)),
		func() tea.Cmd {
			epoch := m.epoch
			return m.read(func(v Vault, _ func() bool) tea.Msg {
				return doneMsg{what: "Moved " + k.String() + " to the trash", err: v.Delete(k), epoch: epoch, reread: true, forget: k}
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
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		k, err := v.RestoreFromTrash(id)
		return doneMsg{what: "Put " + k.String() + " back from the trash", err: err, epoch: epoch, reread: true, closes: panelTrash}
	})
}

// removeFromTrash deletes the trash's entry id, k, for good.
func (m *Model) removeFromTrash(id int64, k vault.Key) tea.Cmd {
	epoch := m.epoch
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		return doneMsg{what: "Deleted " + k.String() + " for good", err: v.RemoveFromTrash(id), epoch: epoch, reread: true}
	})
}

// lockNow locks the app, and the agent with it.
func (m *Model) lockNow() tea.Cmd {
	lockAgent := m.opts.LockAgent
	closing := m.lock("Locked.")
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
	case doneMsg:
		if msg.epoch != m.epoch || m.v == nil {
			return nil
		}
		switch {
		case errors.Is(msg.err, ErrLocked):
			return m.lock(lockedReason(msg.err))
		case msg.err != nil && m.ov != nil && m.ov.kind == msg.closes:
			// Said in the panel, which has room for it, and stays open.
			m.ov.err = msg.err.Error()
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
		}
		if msg.reread {
			return m.search()
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
	// The rows that fit: the screen less the card's border, title, hint
	// and the blank lines between.
	room := max(m.height-8, 1)
	var lines []string
	row := func(i int, key, text string) string {
		k := th.accented().Render(fmt.Sprintf("%-2s", key))
		if i == ov.sel {
			return lipgloss.NewStyle().Background(th.selBg).Render(th.accented().Render("▌") + " " + fitTo(th.style().Bold(true).Render(text), w-12) + " " + k)
		}
		return "  " + fitTo(th.style().Render(text), w-12) + " " + k
	}
	switch {
	case ov.kind == panelConfirm:
		lines = append(lines, "", th.style().Width(w-6).Render(ov.question), "",
			th.accented().Render("y")+th.dimmed().Render(" yes")+th.lines().Render("  ·  ")+th.accented().Render("n")+th.dimmed().Render(" no"))
	case ov.loading:
		lines = append(lines, "", th.dimmed().Render("Reading…"))
	case ov.err != "":
		lines = append(lines, "", lipgloss.NewStyle().Foreground(th.bad).Width(w-6).Render(ov.err))
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
			lines = append(lines, row(i, "", fmt.Sprintf("%s  %s", t.Key, th.dimmed().Render(fmt.Sprintf("trash id %d, deleted %s", t.ID, ago(now, t.DeletedAt))))))
		}
	default:
		first, last := window(ov.sel, len(ov.items), room)
		for i := first; i < last; i++ {
			it := ov.items[i]
			if it.rule && i > first {
				lines = append(lines, th.lines().Render(strings.Repeat("─", w-6)))
			}
			lines = append(lines, row(i, it.key, it.label))
		}
	}
	var hint string
	switch ov.kind {
	case panelHistory:
		hint = "↵ copy  ·  r restore  ·  esc back"
	case panelTrash:
		hint = "↵ put back  ·  x delete for good  ·  esc back"
	case panelConfirm:
		hint = "esc cancel"
	default:
		hint = "↵ or a key  ·  esc close"
	}
	lines = append(lines, "", th.dimmed().Render(hint))
	title := th.accented().Bold(true).Render(ansi.Truncate(ov.title, w-8, "…"))
	card := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(th.accent).Padding(0, 2).Width(w).
		Render(lipgloss.JoinVertical(lipgloss.Left, append([]string{title}, lines...)...))
	x := max((m.width-lipgloss.Width(card))/2, 0)
	y := max(min((m.height-lipgloss.Height(card))/3, m.height-lipgloss.Height(card)), 0)
	return lipgloss.NewCompositor(lipgloss.NewLayer(base), lipgloss.NewLayer(card).X(x).Y(y).Z(1)).Render()
}
