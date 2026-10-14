package tui

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/bashhack/sesh/internal/vault"
)

// focus is where keys go: typing into the search, moving in the list
// (where Space marks), or picking a folder or tag in the sidebar.
type focus int

const (
	focusSearch focus = iota
	focusList
	focusSide
)

// sideKind is what a sidebar row picks.
type sideKind int

const (
	sideAll    sideKind = iota
	sideFolder          // name "" is the entries in no folder
	sideTag
)

// sideRow is a row of the sidebar: every entry, a folder, or a tag.
type sideRow struct {
	name  string // the folder's path, or the tag
	label string // as drawn: a folder's last part, a tag after #
	kind  sideKind
	count int
	depth int // how far a folder is inside others
}

// filterName is the row as the search line names it: "work/aws", "#prod".
func (r *sideRow) filterName() string {
	switch {
	case r.kind == sideTag:
		return "#" + r.name
	case r.kind == sideFolder && r.name == "":
		return "no folder"
	}
	return r.name
}

// sideFrom is the width from which the sidebar is shown.
const sideFrom = 110

// filingMsg is the vault's folders and tags, for the sidebar and the
// form's suggestions.
type filingMsg struct {
	err     error
	folders []Folder
	tags    []Tag
	epoch   int
}

// refile reads the folders and tags again.
func (m *Model) refile() tea.Cmd {
	epoch := m.epoch
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		folders, tags, err := v.Filing()
		return filingMsg{folders: folders, tags: tags, err: err, epoch: epoch}
	})
}

// reread reads the entries, folders and tags again, after the vault changed.
func (m *Model) reread() tea.Cmd { return tea.Batch(m.search(), m.refile()) }

func (m *Model) gotFiling(msg *filingMsg) tea.Cmd {
	if msg.epoch != m.epoch || m.v == nil {
		return nil
	}
	if msg.err != nil {
		if errors.Is(msg.err, ErrLocked) {
			return m.lock(lockedReason(msg.err))
		}
		// The sidebar keeps what it had; the entries still show.
		return nil
	}
	m.folders, m.tags = msg.folders, msg.tags
	m.buildSide()
	return nil
}

// buildSide lays out the sidebar from the folders and tags held, keeping
// its cursor, and the filter, on the rows they were on. A filter whose
// folder or tag is gone goes back to every entry.
func (m *Model) buildSide() {
	var was sideRow
	if m.sideSel >= 0 && m.sideSel < len(m.side) {
		was = m.side[m.sideSel]
	}
	rows := []sideRow{{kind: sideAll, label: "All"}}
	none := 0
	for _, f := range m.folders {
		if f.Name == "" {
			none = f.Entries
			continue
		}
		label := f.Name[strings.LastIndex(f.Name, "/")+1:]
		rows = append(rows, sideRow{kind: sideFolder, name: f.Name, label: label, count: f.Total, depth: strings.Count(f.Name, "/")})
	}
	if none > 0 && len(rows) > 1 {
		rows = append(rows, sideRow{kind: sideFolder, label: "No folder", count: none})
	}
	for _, t := range m.tags {
		rows = append(rows, sideRow{kind: sideTag, name: t.Name, label: "#" + t.Name, count: t.Entries})
	}
	m.side = rows
	same := func(a, b *sideRow) bool { return a.kind == b.kind && a.name == b.name }
	m.sideSel = max(slices.IndexFunc(rows, func(r sideRow) bool { return same(&r, &was) }), 0)
	if !slices.ContainsFunc(rows, func(r sideRow) bool { return same(&r, &m.filter) }) {
		m.filter = sideRow{kind: sideAll, label: "All"}
		m.showFound()
	}
}

// filtered is rows in the folder or with the tag the sidebar picked.
func (m *Model) filtered(rows []vault.Entry) []vault.Entry {
	switch m.filter.kind {
	case sideFolder:
		return slices.DeleteFunc(slices.Clone(rows), func(e vault.Entry) bool { return !vault.InFolder(e.Folder, m.filter.name) })
	case sideTag:
		return slices.DeleteFunc(slices.Clone(rows), func(e vault.Entry) bool { return !slices.Contains(e.Tags, m.filter.name) })
	}
	return rows
}

// showFound shows the entries found that the filter lets through, keeping
// the selection on the entry it was on.
func (m *Model) showFound() {
	m.rows = m.filtered(m.found)
	for i := range m.rows {
		if m.selKey != (vault.Key{}) && m.rows[i].Key == m.selKey {
			m.sel = i
			break
		}
	}
	m.scroll()
}

// pick filters the list to the sidebar's row i.
func (m *Model) pick(i int) tea.Cmd {
	if i < 0 || i >= len(m.side) {
		return nil
	}
	m.sideSel, m.filter = i, m.side[i]
	m.sel, m.top, m.selKey = 0, 0, vault.Key{}
	m.showFound()
	m.scrollSide()
	return m.moved()
}

// sideWidth is the sidebar's width inside the frame, 0 when it isn't shown.
func (m *Model) sideWidth() int {
	if m.width < sideFrom || m.showHelp {
		return 0
	}
	w := 12
	for _, r := range m.side {
		w = max(w, 2*r.depth+ansi.StringWidth(r.label)+len(fmt.Sprint(r.count))+5)
	}
	return min(w, 26)
}

// mainWidth is the room inside the frame beside the sidebar.
func (m *Model) mainWidth() int {
	if sw := m.sideWidth(); sw > 0 {
		return m.width - 2 - sw - 1
	}
	return m.width - 2
}

// listX is the screen column of the list's first cell.
func (m *Model) listX() int {
	if sw := m.sideWidth(); sw > 0 {
		return 1 + sw + 1
	}
	return 1
}

// scrollSide keeps the sidebar's cursor on screen.
func (m *Model) scrollSide() {
	h := m.listHeight()
	switch {
	case m.sideSel < m.sideTop:
		m.sideTop = m.sideSel
	case m.sideSel >= m.sideTop+h:
		m.sideTop = m.sideSel - h + 1
	}
	m.sideTop = max(min(m.sideTop, len(m.side)-h), 0)
}

// sideLines draws the sidebar, w wide and h high.
func (m *Model) sideLines(w, h int) []string {
	th := m.th
	out := make([]string, h)
	for i := range h {
		n := m.sideTop + i
		if n >= len(m.side) {
			break
		}
		r := m.side[n]
		count := r.count
		if r.kind == sideAll {
			count = m.total
		}
		cursor := m.focus == focusSide && n == m.sideSel
		on := r.kind == m.filter.kind && r.name == m.filter.name
		bg := func(s lipgloss.Style) lipgloss.Style {
			if cursor {
				return s.Background(th.selBg)
			}
			return s
		}
		bar := bg(lipgloss.NewStyle()).Render(" ")
		if cursor {
			bar = bg(th.accented()).Render("▌")
		}
		labelStyle := bg(th.style())
		switch {
		case on:
			labelStyle = bg(th.accented()).Bold(true)
		case r.kind == sideTag:
			labelStyle = bg(lipgloss.NewStyle().Foreground(th.kindColor(vault.KindTOTP)))
		}
		indent := bg(lipgloss.NewStyle()).Render(strings.Repeat(" ", 2*r.depth))
		num := bg(th.dimmed()).Render(fmt.Sprint(count))
		label := labelStyle.Render(ansi.Truncate(r.label, max(w-2*r.depth-lipgloss.Width(num)-4, 1), "…"))
		left := bar + bg(lipgloss.NewStyle()).Render(" ") + indent + label
		gap := bg(lipgloss.NewStyle()).Render(strings.Repeat(" ", max(w-lipgloss.Width(left)-lipgloss.Width(num)-1, 1)))
		out[i] = fitTo(left+gap+num+bg(lipgloss.NewStyle()).Render(" "), w)
	}
	return out
}

// sideAt is the sidebar row at a point on the screen.
func (m *Model) sideAt(x, y int) (int, bool) {
	const firstRow = 3
	n := m.sideTop + y - firstRow
	sw := m.sideWidth()
	if sw == 0 || x < 1 || x > sw || y < firstRow || y >= firstRow+m.listHeight() || n >= len(m.side) {
		return 0, false
	}
	return n, true
}

// sideKey handles a key while the sidebar has the focus: ↑↓ pick a
// folder or tag, Enter, → or Esc go back to the list, Ctrl-K renames
// what's picked, and typing goes back to the search.
func (m *Model) sideKey(msg tea.KeyPressMsg) tea.Cmd {
	switch msg.String() {
	case "up", "ctrl+p":
		return m.pick(max(m.sideSel-1, 0))
	case "down", "ctrl+n":
		return m.pick(min(m.sideSel+1, len(m.side)-1))
	case "enter", "right", "esc":
		m.focus = focusList
		return nil
	case "ctrl+k":
		return m.openSideMenu()
	case "ctrl+c":
		return tea.Quit
	}
	if msg.Text != "" && msg.Mod&(tea.ModCtrl|tea.ModAlt) == 0 {
		m.focusSearch()
		return m.typed(msg)
	}
	return nil
}

// focusSearch moves the focus to the search, its cursor shown.
func (m *Model) focusSearch() {
	m.focus = focusSearch
	m.input.Focus()
}

// focusOn moves the focus to the list or the sidebar, the search's
// cursor hidden.
func (m *Model) focusOn(f focus) {
	m.focus = f
	m.input.Blur()
}

// toggleMark marks the selected entry, or unmarks it, and moves on to
// the next.
func (m *Model) toggleMark() {
	e := m.selected()
	if e == nil {
		return
	}
	if m.marked[e.Key] {
		delete(m.marked, e.Key)
	} else {
		m.marked[e.Key] = true
	}
	if m.sel < len(m.rows)-1 {
		m.sel++
		m.scroll()
	}
}

// markedKeys are the entries marked, in the order the list shows them,
// then any not shown.
func (m *Model) markedKeys() []vault.Key {
	var keys []vault.Key
	for i := range m.found {
		if k := m.found[i].Key; m.marked[k] {
			keys = append(keys, k)
		}
	}
	for k := range m.marked {
		if !slices.Contains(keys, k) {
			keys = append(keys, k)
		}
	}
	return keys
}

// countOf is n entries in words: "1 entry", "3 entries".
func countOf(n int) string { return fmt.Sprintf("%d %s", n, plural(n, "entry", "entries")) }

// openMarkedMenu opens the actions on the entries marked.
func (m *Model) openMarkedMenu() tea.Cmd {
	keys := m.markedKeys()
	n := countOf(len(keys))
	items := []item{
		{key: "m", label: "move to a folder…", run: func() tea.Cmd { return m.askFolder(keys) }},
		{key: "+", label: "add a tag…", run: func() tea.Cmd { return m.askTag(keys, true) }},
		{key: "-", label: "remove a tag…", run: func() tea.Cmd { return m.askTag(keys, false) }},
		{key: "d", label: "move to the trash", run: func() tea.Cmd { return m.confirmDeleteMany(keys) }},
		{key: "u", label: "unmark them", run: func() tea.Cmd {
			clear(m.marked)
			m.ov = nil
			return nil
		}},
	}
	g := m.globalItems()
	g[0].rule = true
	m.ov = &overlay{kind: panelMenu, title: n + " marked", items: append(items, g...)}
	return nil
}

// ask opens a one-line form: label, at first value, with offers to pick
// from; done gets what was typed, and says what's wrong with it, if
// anything, or runs the change.
func (m *Model) ask(title, label, value, hint string, offers []string, done func(string) (string, tea.Cmd)) tea.Cmd {
	in := m.textInput(label, value)
	in.hint, in.offers = hint, offers
	f := &form{title: title, inputs: []*input{in}, row: -1}
	f.submit = func() tea.Cmd {
		bad, cmd := done(in.value())
		if bad != "" {
			f.err = bad
			return nil
		}
		m.form, m.ov = nil, nil
		return cmd
	}
	f.focusInput(0)
	m.form = f
	return nil
}

// change runs a change to the entries marked and says what it did: what
// is how it's said, given how many entries changed. They're unmarked
// after.
func (m *Model) change(run func(v Vault) (int, error), what func(n int) string) tea.Cmd {
	epoch := m.epoch
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		n, err := run(v)
		return doneMsg{what: what(n), err: err, epoch: epoch, reread: true, unmark: true}
	})
}

// askFolder asks for the folder to move the entries keys to.
func (m *Model) askFolder(keys []vault.Key) tea.Cmd {
	return m.ask("Move "+countOf(len(keys))+" to a folder", "folder", "", "empty takes them out of their folders; / puts one inside another (work/aws)",
		m.folderNames(), func(folder string) (string, tea.Cmd) {
			if err := vault.CheckFolder(folder); err != nil {
				return err.Error(), nil
			}
			return "", m.change(func(v Vault) (int, error) { return v.MoveToFolder(keys, folder) }, func(n int) string {
				if folder == "" {
					return "Took " + countOf(n) + " out of their folders"
				}
				return "Moved " + countOf(n) + " to " + folder
			})
		})
}

// askTag asks for the tag to put on the entries keys, or take off them.
func (m *Model) askTag(keys []vault.Key, add bool) tea.Cmd {
	title, offers := "Tag "+countOf(len(keys)), m.tagNames()
	if !add {
		title, offers = "Untag "+countOf(len(keys)), m.tagsOn(keys)
	}
	return m.ask(title, "tag", "", "", offers, func(tag string) (string, tea.Cmd) {
		if err := vault.CheckTag(tag); err != nil {
			return err.Error(), nil
		}
		if add {
			return "", m.change(func(v Vault) (int, error) { return v.AddTag(keys, tag) },
				func(n int) string { return "Tagged " + countOf(n) + " #" + tag })
		}
		return "", m.change(func(v Vault) (int, error) { return v.RemoveTag(keys, tag) },
			func(n int) string { return "Took #" + tag + " off " + countOf(n) })
	})
}

// confirmDeleteMany asks before moving the entries keys to the trash.
func (m *Model) confirmDeleteMany(keys []vault.Key) tea.Cmd {
	m.ov = m.confirm(m.ov, "Delete", "Move "+countOf(len(keys))+" to the trash? They can be put back from there.", func() tea.Cmd {
		for _, k := range keys {
			m.forget(k)
		}
		return m.change(func(v Vault) (int, error) { return len(keys), v.DeleteMany(keys) },
			func(n int) string { return "Moved " + countOf(n) + " to the trash" })
	})
	m.ov.danger = true
	return nil
}

// openSideMenu opens the actions on the folder or tag the sidebar's
// cursor is on.
func (m *Model) openSideMenu() tea.Cmd {
	if m.sideSel <= 0 || m.sideSel >= len(m.side) || m.side[m.sideSel].name == "" {
		return nil // All, and No folder, have nothing to rename
	}
	r := m.side[m.sideSel]
	what, rename := "folder "+r.name, m.askRenameFolder
	if r.kind == sideTag {
		what, rename = "tag #"+r.name, m.askRenameTag
	}
	m.ov = &overlay{kind: panelMenu, title: "The " + what, items: []item{
		{key: "r", label: "rename…", run: func() tea.Cmd { return rename(r.name) }},
	}}
	return nil
}

// askRenameFolder asks for folder from's new name.
func (m *Model) askRenameFolder(from string) tea.Cmd {
	return m.ask("Rename the folder "+from, "new name", from, "the folders inside it move with it", nil, func(to string) (string, tea.Cmd) {
		if err := vault.CheckFolder(to); err != nil || to == "" || to == from {
			if to == "" || to == from {
				return "Type its new name.", nil
			}
			return err.Error(), nil
		}
		epoch := m.epoch
		return "", m.read(func(v Vault, _ func() bool) tea.Msg {
			n, merged, err := v.RenameFolder(from, to)
			what := "Renamed the folder " + from + " to " + to + " (" + countOf(n) + ")"
			if merged {
				what = "Moved the folder " + from + " into " + to + ", which was there already (" + countOf(n) + ")"
			}
			return doneMsg{what: what, err: err, epoch: epoch, reread: true, refilter: &sideRow{kind: sideFolder, name: to}, renamed: from}
		})
	})
}

// askRenameTag asks for tag from's new name.
func (m *Model) askRenameTag(from string) tea.Cmd {
	return m.ask("Rename the tag #"+from, "new name", from, "", nil, func(to string) (string, tea.Cmd) {
		if err := vault.CheckTag(to); err != nil || to == from {
			if to == from {
				return "Type its new name.", nil
			}
			return err.Error(), nil
		}
		epoch := m.epoch
		return "", m.read(func(v Vault, _ func() bool) tea.Msg {
			n, merged, err := v.RenameTag(from, to)
			what := "Renamed #" + from + " to #" + to + " (" + countOf(n) + ")"
			if merged {
				what = "Merged #" + from + " into #" + to + " (" + countOf(n) + ")"
			}
			return doneMsg{what: what, err: err, epoch: epoch, reread: true, refilter: &sideRow{kind: sideTag, name: to}, renamed: from}
		})
	})
}

// folderNames are the folders there are, for the form's suggestions.
func (m *Model) folderNames() []string {
	var out []string
	for _, f := range m.folders {
		if f.Name != "" {
			out = append(out, f.Name)
		}
	}
	return out
}

// tagNames are the tags there are.
func (m *Model) tagNames() []string {
	out := make([]string, 0, len(m.tags))
	for _, t := range m.tags {
		out = append(out, t.Name)
	}
	return out
}

// tagsOn are the tags any of the entries keys have, as the list holds them.
func (m *Model) tagsOn(keys []vault.Key) []string {
	var out []string
	for i := range m.found {
		if e := &m.found[i]; slices.Contains(keys, e.Key) {
			for _, t := range e.Tags {
				if !slices.Contains(out, t) {
					out = append(out, t)
				}
			}
		}
	}
	slices.Sort(out)
	return out
}
