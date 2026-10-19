package tui

import (
	"errors"
	"fmt"
	"slices"
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
	panelAudit                     // the audit log
	panelFiling                    // the folders and tags, as the sidebar lists them
	panelQR                        // a TOTP key as a QR code, for a phone
)

// overlay is a panel over the app, about the entry k.
type overlay struct {
	opened   time.Time      // when a confirmation was asked
	until    time.Time      // when a QR code shown closes
	yes      func() tea.Cmd // what a confirmation's yes does
	back     *overlay       // what Esc goes back to
	k        vault.Key
	question string // a confirmation's
	title    string
	err      string
	busy     string // said instead of "Loading…" while it waits
	items    []item
	versions []Version
	trash    []Trashed
	marked   map[int64]bool // the trash's entries marked, by trash id
	backups  []Backup       // the backups panel's, as its rows list them
	link     string         // the otpauth:// link the QR code draws
	qr       []string       // a TOTP key's QR code, a line each
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
	// cut says detail is the row's text whole: said only when the row
	// cuts it.
	cut bool
}

// Messages from the actions.
type (
	historyMsg struct {
		err      error
		k        vault.Key
		said     string // what a change to them did, to say
		versions []Version
		epoch    int
	}
	trashMsg struct {
		err   error
		said  string // what a change to it did, to say
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
		// No entry to act on: what there is to do is sesh's.
		return m.openSeshMenu()
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
	if e.Kind == vault.KindTOTP {
		items = append(items, item{key: "q", label: "show the key as a QR code…", run: func() tea.Cmd { return m.openQR(&ek) }})
	}
	if isAWSEntry(e) && m.opts.AWSSignIn != nil {
		items = append(items, item{key: "a", label: "sign in to AWS and open a shell", run: func() tea.Cmd { return m.awsSignIn(&ek) }})
	}
	if e.Kind == vault.KindFile {
		items = append(items, item{key: "s", label: "save to a file…", run: func() tea.Cmd { return m.askSaveFile(&ek) }})
	}
	items = append(items,
		item{key: "h", label: "earlier secrets…", run: func() tea.Cmd { return m.openHistory(&ek) }},
		item{key: "d", label: "move to the trash", run: func() tea.Cmd { return m.confirmDelete(&ek) }},
		item{key: "x", label: "delete for good", run: func() tea.Cmd { return m.confirmPurge([]vault.Key{ek.Key}, false) }},
		// Ctrl-G's menu, where a terminal (zellij's) takes Ctrl-G.
		item{key: "g", label: "sesh's actions…", rule: true, run: m.openSeshMenu},
	)
	m.ov = &overlay{kind: panelMenu, title: entryName(e), k: e.Key, items: items}
	return nil
}

// openSeshMenu opens the menu of what isn't about one entry.
func (m *Model) openSeshMenu() tea.Cmd {
	if m.width < minWidth || m.height < minHeight {
		// It wouldn't be on screen.
		return nil
	}
	// Opened from Ctrl-K's menu, it goes back to it.
	m.ov = &overlay{kind: panelMenu, title: "sesh", back: m.ov, items: m.seshItems()}
	return nil
}

// seshItems are the actions that aren't about one entry.
func (m *Model) seshItems() []item {
	items := []item{
		{key: "a", label: "add an entry…", run: m.openAdd},
		{key: "p", label: "generate a password…", run: m.openGenerator},
		{key: "f", label: "folders and tags…", run: m.openFiling},
		{key: "t", label: "the trash…", run: m.openTrash},
		{key: "b", label: "backups…", run: m.openBackups},
		{key: "i", label: "import and export…", run: m.openTransfer},
		{key: "r", label: "health report…", run: m.openHealth},
		{key: ",", label: "settings and safety…", run: m.openSettings},
		{key: "l", label: "lock sesh", run: m.lockNow},
	}
	if s := m.syncItem(); s != nil {
		items = append(items, *s)
	}
	if r := m.resultsItem("y"); r != nil {
		items = append(items, *r)
	}
	return items
}

// overlayKey handles a key while a panel is open.
func (m *Model) overlayKey(msg tea.KeyPressMsg) tea.Cmd {
	m.lastKey = m.opts.Now()
	ov := m.ov
	k := msg.String()
	switch k {
	case "ctrl+c":
		if ov.kind == panelImport && m.importing != nil && m.importing.applying {
			// It quits once the import is written, saying what it did.
			m.quitAfter = true
			ov.busy = "Quitting once the import is written…"
			return nil
		}
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

// listTrash lists trash in the trash panel, keeping the marks on entries
// still in it.
func (ov *overlay) listTrash(trash []Trashed) {
	for id := range ov.marked {
		if !slices.ContainsFunc(trash, func(t Trashed) bool { return t.ID == id }) {
			delete(ov.marked, id)
		}
	}
	ov.trash = trash
	ov.sel = max(min(ov.sel, len(trash)-1), 0)
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
		return m.copyVersion(ov.k, i+2, ov.versions[i])
	case panelTrash:
		t := ov.trash[i]
		return m.restoreFromTrash(&t, vault.Key{})
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
// secret, or deleting one for good; putting an entry back from the trash
// under another name, deleting one for good, or emptying it.
func (m *Model) panelLetter(k string) tea.Cmd {
	ov := m.ov
	switch {
	case ov.kind == panelQR && k == "c" && ov.link != "":
		return m.copyLink(ov)
	case ov.kind == panelHistory && k == "r" && ov.sel < len(ov.versions):
		n, key, v := ov.sel+2, ov.k, ov.versions[ov.sel]
		m.ov = m.confirm(ov, "Restore",
			fmt.Sprintf("Make version %d the secret for %s again? The current one is kept as an earlier secret.", n, short(keyName(key))),
			func() tea.Cmd { m.ov = ov; return m.restoreVersion(key, v) })
	case ov.kind == panelHistory && (k == "x" || k == "delete") && ov.sel < len(ov.versions):
		n, key, v := ov.sel+2, ov.k, ov.versions[ov.sel]
		m.ov = m.confirm(ov, "Delete for good",
			fmt.Sprintf("Delete version %d of %s for good? It can't be brought back; the versions after it move up a number.", n, short(keyName(key))),
			func() tea.Cmd { m.ov = ov; return m.forgetVersion(key, n, v) })
		m.ov.danger = true
	case ov.kind == panelTrash && k == "space" && ov.sel < len(ov.trash):
		if ov.marked == nil {
			ov.marked = map[int64]bool{}
		}
		id := ov.trash[ov.sel].ID
		if ov.marked[id] {
			delete(ov.marked, id)
		} else {
			ov.marked[id] = true
		}
		ov.sel = min(ov.sel+1, len(ov.trash)-1)
	case ov.kind == panelTrash && (k == "x" || k == "delete") && len(ov.marked) > 0:
		var marked []Trashed
		for _, t := range ov.trash {
			if ov.marked[t.ID] {
				marked = append(marked, t)
			}
		}
		m.ov = m.confirm(ov, "Delete for good",
			fmt.Sprintf("Delete the %d entries marked for good? They can't be brought back.", len(marked)),
			func() tea.Cmd { m.ov = ov; return m.removeMarked(marked) })
		m.ov.danger = true
	case ov.kind == panelTrash && k == "a" && ov.sel < len(ov.trash):
		return m.askRestoreAs(&ov.trash[ov.sel])
	case ov.kind == panelTrash && k == "e" && len(ov.trash) > 0:
		// What's listed, and only that: an entry trashed since is left.
		listed := slices.Clone(ov.trash)
		m.ov = m.confirm(ov, "Empty the trash",
			fmt.Sprintf("Delete %s in the trash for good? They can't be brought back.", plural(len(listed), "the 1 entry", fmt.Sprintf("all %d entries", len(listed)))),
			func() tea.Cmd { m.ov = ov; return m.emptyTrash(listed) })
		m.ov.danger = true
	case ov.kind == panelBackups:
		return m.backupsLetter(k)
	case ov.kind == panelAudit && k == "p" && !ov.loading:
		return m.askPrune()
	case ov.kind == panelFiling && k == "r" && ov.sel < len(m.side) && m.side[ov.sel].name != "":
		r := m.side[ov.sel]
		if r.kind == sideTag {
			return m.askRenameTag(r.name)
		}
		return m.askRenameFolder(r.name)
	case ov.kind == panelImport:
		return m.importLetter(k)
	case ov.kind == panelTrash && (k == "x" || k == "delete") && ov.sel < len(ov.trash):
		t := ov.trash[ov.sel]
		m.ov = m.confirm(ov, "Delete for good",
			fmt.Sprintf("Delete %s for good? It can't be brought back.", short(kindName(t.Key))),
			func() tea.Cmd { return m.removeFromTrash(&t) })
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
	if ek.Kind == vault.KindTOTP {
		// The key the codes are made from, to move it to another app.
		add("TOTP key", func() tea.Cmd { return m.copyTOTPKey(&ek) })
	}
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

// copyTOTPKey copies the TOTP entry e's key: a read the audit log records.
func (m *Model) copyTOTPKey(e *vault.Entry) tea.Cmd {
	k, name, opts, epoch := e.Key, entryName(e), m.opts, m.epoch
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		key, err := v.Secret(k, "in sesh ui, to copy its key")
		if err != nil {
			return copiedMsg{err: err, epoch: epoch}
		}
		defer secure.SecureZeroBytes(key)
		if err := opts.Copy(string(key)); err != nil {
			return copiedMsg{what: "Couldn't copy: " + err.Error(), epoch: epoch, bad: true}
		}
		return copiedMsg{what: copied("the TOTP key for "+name, opts.ClearAfter), epoch: epoch}
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

// copyVersion copies k's earlier secret ver, listed as version n: a read
// the audit log records.
func (m *Model) copyVersion(k vault.Key, n int, ver Version) tea.Cmd {
	opts, epoch := m.opts, m.epoch
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		secret, err := v.ReadVersion(k, ver)
		if errors.Is(err, ErrHistoryChanged) {
			versions, _ := v.History(k) //nolint:errcheck // the list as it is, under the error said
			return historyMsg{k: k, versions: versions, err: err, epoch: epoch}
		}
		if err != nil {
			return copiedMsg{err: err, epoch: epoch}
		}
		defer secure.SecureZeroBytes(secret)
		if k.Kind == vault.KindFile && !vault.IsText(secret) {
			return copiedMsg{what: fmt.Sprintf("Version %d of %s is a binary file, which the clipboard can't hold", n, short(keyName(k))), epoch: epoch, bad: true}
		}
		if err := opts.Copy(string(secret)); err != nil {
			return copiedMsg{what: "Couldn't copy: " + err.Error(), epoch: epoch, bad: true}
		}
		return copiedMsg{what: copied(fmt.Sprintf("an earlier secret (version %d) for %s", n, keyName(k)), opts.ClearAfter), epoch: epoch}
	})
}

// restoreVersion makes k's earlier secret ver its secret again, closing
// the history; if it's no longer there, the history stays, listed as it
// is now.
func (m *Model) restoreVersion(k vault.Key, ver Version) tea.Cmd {
	epoch := m.epoch
	m.forget(k)
	m.ov.loading = true
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		err := v.RestoreVersion(k, ver)
		if errors.Is(err, ErrHistoryChanged) {
			versions, _ := v.History(k) //nolint:errcheck // the list as it is, under the error said
			return historyMsg{k: k, versions: versions, err: err, epoch: epoch}
		}
		return doneMsg{what: fmt.Sprintf("Restored an earlier secret for %s; the one it replaced is kept", keyName(k)), err: err, epoch: epoch, reread: true, forget: k, closes: panelHistory}
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
				return doneMsg{what: "Moved " + kindName(k) + " to the trash", err: v.Delete(k), epoch: epoch, reread: true, forget: k, unmark: []vault.Key{k}}
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

// restoreFromTrash puts the trash's entry t back: under its own name, or
// as the entry as names when it isn't zero.
func (m *Model) restoreFromTrash(t *Trashed, as vault.Key) tea.Cmd {
	epoch := m.epoch
	m.ov.loading = true // no second Enter while this one is put back
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		k, err := v.RestoreFromTrash(t, as)
		if errors.Is(err, ErrTrashChanged) {
			trash, _ := v.Trash() //nolint:errcheck // the list as it is, under the error said
			return trashMsg{trash: trash, err: err, epoch: epoch}
		}
		if errors.Is(err, ErrNameTaken) {
			if as == (vault.Key{}) {
				err = errors.New("another entry has its name: a puts it back under another")
			} else {
				err = errors.New("another entry has that name too: a, to choose another")
			}
		}
		return doneMsg{what: "Restored " + kindName(k) + " from the trash", err: err, epoch: epoch, reread: true, closes: panelTrash}
	})
}

// askRestoreAs asks for the name to put t back from the trash under: its
// ID, as sesh trash restore --as takes it.
func (m *Model) askRestoreAs(t *Trashed) tea.Cmd {
	listed, own := *t, t.Key
	return m.askOver(true, "Put back as", "entry ID", own.String(), "kind/name or kind/name/username, as sesh list's ID column has it: "+string(own.Kind)+"/…", nil, func(typed string) (string, tea.Cmd) {
		as, err := vault.ParseKey(strings.TrimSpace(typed))
		switch {
		case err != nil:
			return err.Error(), nil
		case as == own:
			return "That's its own name: Enter in the trash puts it back under it.", nil
		case as.Kind != own.Kind:
			return "It comes back as the kind it is: " + string(own.Kind) + "/…", nil
		}
		return "", m.restoreFromTrash(&listed, as)
	})
}

// removeMarked deletes the trash's entries marked, as listed, for good,
// and lists what's left.
func (m *Model) removeMarked(listed []Trashed) tea.Cmd {
	epoch := m.epoch
	m.ov.loading = true
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		n, err := v.RemoveFromTrash(listed...)
		trash, terr := v.Trash()
		if err == nil {
			err = terr
		}
		return trashMsg{trash: trash, err: err, said: "Deleted " + countOf(n) + " in the trash for good", epoch: epoch}
	})
}

// confirmPurge asks before deleting the entries keys for good, skipping
// the trash: the entry the menu was opened on, or those marked. Marked
// ones another command has deleted or renamed meanwhile are left out, and
// said to be, as moving them to the trash does.
func (m *Model) confirmPurge(keys []vault.Key, marked bool) tea.Cmd {
	what := countOf(len(keys))
	if len(keys) == 1 {
		what = short(kindName(keys[0]))
	}
	question := "Delete " + what + " for good? It skips the trash, so it can't be brought back, nor its earlier secrets."
	if h := m.hiddenMarks(); marked && h > 0 {
		question = fmt.Sprintf("Delete %s for good, %d of them not shown in the list now? It skips the trash, so they can't be brought back, nor their earlier secrets.", what, h)
		if len(keys) == 1 {
			question = "Delete " + what + " for good? It's marked, but not shown in the list now. It skips the trash, so it can't be brought back, nor its earlier secrets."
		}
	}
	m.ov = m.confirm(m.ov, "Delete for good", question, func() tea.Cmd {
		for _, k := range keys {
			m.forget(k)
		}
		if !marked {
			epoch := m.epoch
			return m.read(func(v Vault, _ func() bool) tea.Msg {
				return doneMsg{what: "Deleted " + what + " for good", err: v.Purge(keys), epoch: epoch, reread: true, unmark: keys}
			})
		}
		return m.change(keys, func(v Vault, keys []vault.Key) (int, error) { return len(keys), v.Purge(keys) },
			func(n int) string {
				if n == 1 && len(keys) == 1 {
					return "Deleted " + what + " for good"
				}
				return "Deleted " + countOf(n) + " for good"
			})
	})
	m.ov.danger = true
	return nil
}

// emptyTrash deletes the trash's entries listed, and only those, for good.
func (m *Model) emptyTrash(listed []Trashed) tea.Cmd {
	epoch := m.epoch
	m.ov.loading = true
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		n, err := v.RemoveFromTrash(listed...)
		if err != nil {
			trash, _ := v.Trash() //nolint:errcheck // the list as it is, under the error said
			return trashMsg{trash: trash, err: err, epoch: epoch}
		}
		trash, err := v.Trash()
		return trashMsg{trash: trash, err: err, said: "Deleted " + countOf(n) + " in the trash for good", epoch: epoch}
	})
}

// forgetVersion deletes k's earlier secret ver, listed as version n, for
// good, and lists those left.
func (m *Model) forgetVersion(k vault.Key, n int, ver Version) tea.Cmd {
	epoch := m.epoch
	m.ov.loading = true
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		if err := v.ForgetVersion(k, ver); err != nil {
			versions, _ := v.History(k) //nolint:errcheck // the list as it is, under the error said
			return historyMsg{k: k, versions: versions, err: err, epoch: epoch}
		}
		versions, err := v.History(k)
		return historyMsg{k: k, versions: versions, err: err, said: fmt.Sprintf("Deleted version %d of %s for good", n, keyName(k)), epoch: epoch}
	})
}

// removeFromTrash deletes the trash's entry t, as listed, for good.
func (m *Model) removeFromTrash(t *Trashed) tea.Cmd {
	epoch := m.epoch
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		_, err := v.RemoveFromTrash(*t)
		return doneMsg{what: "Deleted " + kindName(t.Key) + " for good", err: err, epoch: epoch, reread: true}
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
		if msg.err != nil && !errors.Is(msg.err, ErrLocked) && msg.versions != nil {
			// A change refused: the list as it is now, and why.
			m.ov.versions, m.ov.loading, m.ov.err = msg.versions, false, msg.err.Error()
			m.ov.sel = max(min(m.ov.sel, len(msg.versions)-1), 0)
			return nil
		}
		return m.loaded(msg.err, func() {
			m.ov.versions = msg.versions
			m.ov.sel = max(min(m.ov.sel, len(msg.versions)-1), 0)
			if msg.said != "" {
				m.say(msg.said)
			}
		})
	case trashMsg:
		if msg.epoch != m.epoch || m.ov == nil || m.ov.kind != panelTrash {
			return nil
		}
		if msg.err != nil && !errors.Is(msg.err, ErrLocked) && msg.trash != nil {
			m.ov.loading, m.ov.err = false, msg.err.Error()
			m.ov.listTrash(msg.trash)
			return nil
		}
		return m.loaded(msg.err, func() {
			m.ov.listTrash(msg.trash)
			if msg.said != "" {
				m.say(msg.said)
			}
		})
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
	if ov.kind == panelSettings || ov.kind == panelChecks || ov.kind == panelBackups || ov.kind == panelImport || ov.kind == panelAudit || ov.wide {
		w = min(96, m.width-6)
	}
	if ov.kind == panelQR && len(ov.qr) > 0 {
		// As wide as its code needs, where the window has room.
		w = min(max(w, lipgloss.Width(ov.qr[0])+qrMargin), m.width-6)
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
	var sel *item
	if ov.sel < len(ov.items) {
		sel = &ov.items[ov.sel]
	}
	if sel != nil && sel.detail != "" && (!sel.cut || lipgloss.Width(sel.label) > w-12) && !ov.loading && room >= 5 {
		said := strings.Split(th.dimmed().Width(w-6).Render(sel.detail), "\n")
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
	case ov.kind == panelQR && !ov.loading && len(ov.qr) > 0:
		lines = append(lines, m.qrLines(ov, w, room)...)
	case ov.loading && ov.busy != "":
		lines = append(lines, "", th.dimmed().Render(ov.busy))
	case ov.loading:
		lines = append(lines, "", th.dimmed().Render("Loading…"))
	case ov.err != "" && ov.len() == 0:
		lines = append(lines, "", lipgloss.NewStyle().Foreground(th.bad).Width(w-6).Render(ov.err))
	case ov.kind == panelBackups && ov.filled && len(ov.items) == 0:
		lines = append(lines, "", th.dimmed().Width(w-6).Render("No backups yet: n backs the vault up now."))
	case ov.kind == panelAudit && ov.filled && len(ov.items) == 0:
		lines = append(lines, "", th.dimmed().Width(w-6).Render("No events yet: reading a secret, and each change, is recorded here."))
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
			if at := ov.versions[i].ReplacedAt; !at.IsZero() {
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
			mark := "  "
			if ov.marked[t.ID] {
				mark = th.accented().Render("✓ ")
			}
			lines = append(lines, row(i, "", mark+fmt.Sprintf("%s  %s", keyName(t.Key), th.dimmed().Render(fmt.Sprintf("%s · deleted %s · id %d", kindLabel(t.Key.Kind), ago(now, t.DeletedAt), t.ID)))))
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
		hint = th.hints([2]string{"↵", "copy"}, [2]string{"r", "restore"}, [2]string{"x", "delete"}, [2]string{"esc", "back"})
		if len(ov.versions) == 0 {
			hint = th.hints([2]string{"esc", "back"})
		}
	case panelTrash:
		hint = th.hints([2]string{"↵", "put back"}, [2]string{"a", "as…"}, [2]string{"space", "mark"}, [2]string{"x", "delete"}, [2]string{"e", "empty"}, [2]string{"esc", "back"})
		if len(ov.marked) > 0 {
			hint = th.hints([2]string{"x", fmt.Sprintf("delete the %d marked", len(ov.marked))}, [2]string{"space", "mark"}, [2]string{"esc", "back"})
		}
		// Narrower, the letters alone; then only Enter's.
		for _, h := range []string{th.hints([2]string{"↵", "put back"}, [2]string{"a space x e", ""}, [2]string{"esc", "back"}), th.hints([2]string{"↵", "put back"}, [2]string{"esc", "back"})} {
			if lipgloss.Width(hint) > w-6 {
				hint = h
			}
		}
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
	case panelAudit:
		hint = th.hints([2]string{"↑↓", "read"}, [2]string{"p", "prune"}, [2]string{"esc", "back"})
	case panelFiling:
		hint = th.hints([2]string{"↵", "show its entries"}, [2]string{"r", "rename"}, [2]string{"esc", "back"})
		if ov.sel < len(m.side) && m.side[ov.sel].name == "" {
			hint = th.hints([2]string{"↵", "show its entries"}, [2]string{"esc", "back"})
		}
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
		if ov.loading {
			hint = th.hints([2]string{"esc", "leave it"})
		}
	case panelQR:
		hint = th.hints([2]string{"c", "copy the link"}, [2]string{"esc", "close"})
		if !ov.until.IsZero() {
			hint = th.hints([2]string{"c", "copy the link"}, [2]string{"esc", fmt.Sprintf("close (%ds)", max(int(ov.until.Sub(m.opts.Now()).Seconds()), 0))})
		}
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
