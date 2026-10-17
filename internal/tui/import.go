package tui

import (
	"errors"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/bashhack/sesh/internal/secure"
)

// importing is an import read, being previewed: its source as said, and
// what's done with entries the vault has.
type importing struct {
	im         Importer
	name       string
	onConflict string
	plan       ImportPlan
	// failed is the last plan having failed: there's nothing to import
	// until s or o plans again. applying is y's import under way, which
	// carries on to the end.
	failed, applying bool
}

// Messages from an import.
type (
	importStartedMsg struct {
		err   error
		im    Importer
		f     *form
		epoch int
	}
	importPlannedMsg struct {
		err   error
		in    *importing
		plan  ImportPlan
		epoch int
	}
	importedMsg struct {
		err   error
		in    *importing
		said  string
		epoch int
	}
)

// importSources are the sources the panel offers, as sesh import names
// them, with their keys and how they're said. No key is j or k, which
// move through the panel's rows.
var importSources = []struct{ key, source, name, files string }{
	{"s", "sesh", "sesh's own encrypted export", "file"},
	{"b", "bitwarden", "Bitwarden", "file (its JSON or CSV export)"},
	{"p", "keepass", "KeePass", "file (its XML export)"},
	{"c", "chrome", "Chrome", "file (its CSV export)"},
	{"f", "firefox", "Firefox", "file (its CSV export)"},
	{"a", "apple-passwords", "Apple Passwords", "file (its CSV export)"},
	{"g", "google-authenticator", "Google Authenticator", "files: screenshots of its transfer codes, separated by commas"},
	{"l", "lastpass-authenticator", "LastPass Authenticator", "file (its JSON export)"},
}

// importRows are the panel's rows for importing.
func (m *Model) importRows() []item {
	var rows []item
	for i, s := range importSources {
		rows = append(rows, item{key: s.key, label: "import from " + s.name + "…", stay: true, rule: i == 0,
			run: func() tea.Cmd { return m.importForm(s.source, s.name, s.files) }})
	}
	return rows
}

// importForm asks for the files to import from source, and, when the
// export asks for one, its password.
func (m *Model) importForm(source, name, files string) tea.Cmd {
	in := m.textInput(files, "")
	in.hint = "a full path, or one starting with ~/"
	many := strings.Contains(files, "separated")
	asked := false
	pw := &input{kind: inputSecret, label: "the export's password", shown: func() bool { return asked }}
	f := &form{title: "Import from " + name, inputs: []*input{in, pw}, row: -1, enterDone: "read it", working: "Reading…"}
	f.submit = func() tea.Cmd {
		var paths []string
		switch {
		case many:
			paths = splitPaths(in.value())
		case in.value() != "":
			paths = []string{in.value()}
		}
		switch {
		case len(paths) == 0:
			f.err = "Type the file to import."
			return nil
		case asked && len(pw.secret) == 0:
			f.err = "Type the export's password."
			return nil
		}
		f.saving, f.err = true, ""
		secret, epoch := append([]byte(nil), pw.secret...), m.epoch
		return wipeUnread(secret, m.read(func(v Vault, _ func() bool) tea.Msg {
			im, err := v.StartImport(source, paths, secret)
			secure.SecureZeroBytes(secret)
			return importStartedMsg{im: im, err: err, f: f, epoch: epoch}
		}))
	}
	f.focusInput(0)
	m.form = f
	// The form learns it needs the password from the reply.
	m.importAsk = func() {
		asked = true
		f.focusInput(1)
	}
	m.importName = name
	return nil
}

// splitPaths is the files typed, separated by commas.
func splitPaths(typed string) []string {
	var out []string
	for p := range strings.SplitSeq(typed, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// importStarted plans the import read, or keeps its form to say why not.
func (m *Model) importStarted(msg *importStartedMsg) tea.Cmd {
	f := msg.f
	if msg.epoch != m.epoch || m.v == nil || m.form != f {
		if msg.im != nil {
			msg.im.Close()
		}
		return nil
	}
	f.saving = false
	switch {
	case errors.Is(msg.err, ErrLocked):
		f.wipe()
		m.form = nil
		return m.lock(lockedReason(msg.err))
	case errors.Is(msg.err, ErrNeedsPassword) && m.importAsk != nil:
		m.importAsk()
		f.err = strings.ToUpper(msg.err.Error()[:1]) + msg.err.Error()[1:] + ": type it below."
		return nil
	case msg.err != nil:
		f.err = "Not read: " + strings.TrimSuffix(msg.err.Error(), ".") + "."
		return nil
	}
	f.wipe()
	m.form = nil
	m.importAsk = nil
	ended := m.endImport() // one still held, from before
	m.importing = &importing{im: msg.im, name: m.importName}
	m.ov = &overlay{kind: panelImport, back: m.ov, title: "Import from " + m.importName, loading: true, busy: "Comparing with the vault…"}
	return tea.Batch(ended, m.planImport(""))
}

// planImport plans the import with onConflict.
func (m *Model) planImport(onConflict string) tea.Cmd {
	in, epoch := m.importing, m.epoch
	in.onConflict = onConflict
	return m.read(func(_ Vault, _ func() bool) tea.Msg {
		plan, err := in.im.Plan(onConflict)
		return importPlannedMsg{plan: plan, err: err, in: in, epoch: epoch}
	})
}

// importPlanned shows what the import would do.
func (m *Model) importPlanned(msg *importPlannedMsg) tea.Cmd {
	ov, in := m.ov, msg.in
	if msg.epoch != m.epoch || in != m.importing || ov == nil || ov.kind != panelImport {
		return nil
	}
	ov.loading, ov.busy = false, ""
	switch {
	case errors.Is(msg.err, ErrLocked):
		return m.lock(lockedReason(msg.err))
	case msg.err != nil:
		// Nothing is planned, so nothing is imported until s or o plans
		// again.
		in.plan, in.failed, ov.items = ImportPlan{}, true, nil
		ov.err = "Not read: " + msg.err.Error()
		return nil
	}
	in.plan, in.failed = msg.plan, false
	ov.err = ""
	m.showPlan()
	ov.opened = m.opts.Now()
	return nil
}

// showPlan puts the import's plan in its panel, each line wrapped to the
// panel's width, so none is cut.
func (m *Model) showPlan() {
	ov, in := m.ov, m.importing
	if in == nil || in.failed || ov == nil || ov.kind != panelImport {
		return
	}
	ov.items = nil
	width := max(min(96, m.width-6)-12, 20)
	for l := range strings.SplitSeq(in.plan.Summary, "\n") {
		indent := l[:len(l)-len(strings.TrimLeft(l, " "))]
		for w := range strings.SplitSeq(m.th.style().Width(width-len(indent)).Render(strings.TrimLeft(l, " ")), "\n") {
			ov.items = append(ov.items, item{label: indent + strings.TrimRight(w, " ")})
		}
	}
	ov.sel = min(ov.sel, max(len(ov.items)-1, 0))
}

// importLetter is what the preview's letters do: s and o say what's done
// with entries the vault has, and y imports.
func (m *Model) importLetter(k string) tea.Cmd {
	in, ov := m.importing, m.ov
	if in == nil || ov.loading {
		return nil
	}
	retry := in.failed || in.plan.Clashes > 0
	switch {
	case k == "s" && retry && (in.failed || in.onConflict != "skip"):
		ov.loading, ov.busy = true, "Comparing with the vault…"
		return m.planImport("skip")
	case k == "o" && retry && (in.failed || in.onConflict != "overwrite"):
		ov.loading, ov.busy = true, "Comparing with the vault…"
		return m.planImport("overwrite")
	case k == "y":
		switch {
		case in.failed:
			return nil
		case in.plan.Clashes > 0 && in.onConflict == "":
			ov.err = "Some of these are in the vault already: s leaves them as they are, o replaces them."
			return nil
		case in.plan.Count == 0:
			ov.err = strings.TrimSpace("Nothing to import. " + in.plan.After)
			return nil
		case m.opts.Now().Sub(ov.opened) < confirmAfter:
			return nil
		}
		ov.loading, ov.busy, in.applying = true, "Importing…", true
		epoch := m.epoch
		return m.read(func(_ Vault, _ func() bool) tea.Msg {
			said, err := in.im.Apply()
			return importedMsg{said: said, err: err, in: in, epoch: epoch}
		})
	}
	return nil
}

// imported says what the import did, and reads the entries again.
func (m *Model) imported(msg *importedMsg) tea.Cmd {
	if msg.epoch != m.epoch || msg.in != m.importing {
		return nil
	}
	said := msg.said
	if msg.err != nil {
		said = importFailed(msg.err)
	}
	ended := m.endImport()
	switch {
	case m.quitAfter:
		m.afterword = said
		return tea.Batch(ended, tea.Quit)
	case errors.Is(msg.err, ErrLocked):
		return tea.Batch(ended, m.lock(said))
	}
	// The entries may have changed under the panels below, by the
	// import's writes or another command's: the notice goes back to an
	// import and export panel of its own.
	m.ov = nil
	m.openTransfer()
	m.ov = &overlay{kind: panelNotice, back: m.ov, title: "Import", question: said}
	return tea.Batch(ended, m.reread())
}

// importFailed says an import's failure: one that stopped partway says
// what it imported first.
func importFailed(err error) string {
	switch {
	case errors.Is(err, ErrLocked):
		return lockedReason(err)
	case strings.HasPrefix(err.Error(), "imported "):
		return "The import stopped: " + err.Error()
	}
	return "Not imported: " + err.Error()
}

// endImport lets the import go: closed, which wipes what it read, once a
// plan or apply under way has finished, so not here, where that would
// hold the app up.
func (m *Model) endImport() tea.Cmd {
	if m.importing == nil {
		return nil
	}
	im := m.importing.im
	m.importing = nil
	return func() tea.Msg {
		im.Close()
		return nil
	}
}

// importHint is the preview's keys, as they fit width.
func (m *Model) importHint(width int) string {
	th, in := m.th, m.importing
	var keys [][2]string
	switch {
	case in != nil && in.applying && m.quitAfter:
		return ""
	case in != nil && in.applying:
		keys = [][2]string{{"ctrl+c", "quit once it's written"}}
	case in == nil || m.ov.loading:
		return th.hints([2]string{"esc", "cancel"})
	case in.failed:
		keys = [][2]string{{"s", "read it again, leaving those you have"}, {"o", "replacing them"}, {"esc", "cancel"}}
	case in.plan.Clashes > 0 && in.onConflict == "":
		keys = [][2]string{{"s", "leave those you have"}, {"o", "replace them"}, {"esc", "cancel"}}
	case in.plan.Count == 0:
		keys = [][2]string{{"esc", "back"}}
	case in.onConflict == "skip":
		keys = [][2]string{{"y", "import " + plural(in.plan.Count, "1 entry", strconv.Itoa(in.plan.Count)+" entries")}, {"o", "replace those you have"}, {"esc", "cancel"}}
	case in.onConflict == "overwrite":
		keys = [][2]string{{"y", "import " + plural(in.plan.Count, "1 entry", strconv.Itoa(in.plan.Count)+" entries")}, {"s", "leave those you have"}, {"esc", "cancel"}}
	default:
		keys = [][2]string{{"y", "import " + plural(in.plan.Count, "1 entry", strconv.Itoa(in.plan.Count)+" entries")}, {"esc", "cancel"}}
	}
	if h := th.hints(keys...); lipgloss.Width(h) <= width {
		return h
	}
	// Narrower, the letters alone, then the first and Esc.
	letters := make([][2]string, len(keys))
	for i, k := range keys {
		letters[i] = [2]string{k[0], ""}
	}
	if h := th.hints(letters...); lipgloss.Width(h) <= width || len(keys) == 1 {
		return h
	}
	return th.hints([2]string{keys[0][0], ""}, [2]string{"esc", ""})
}
