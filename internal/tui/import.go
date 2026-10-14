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
		plan  ImportPlan
		epoch int
	}
	importedMsg struct {
		err   error
		said  string
		epoch int
	}
)

// importSources are the sources the panel offers, as sesh import names
// them, with their keys and how they're said.
var importSources = []struct{ key, source, name, files string }{
	{"s", "sesh", "sesh's own encrypted export", "file"},
	{"b", "bitwarden", "Bitwarden", "file (its JSON export)"},
	{"k", "keepass", "KeePass", "file (its XML export)"},
	{"c", "chrome", "Chrome", "file (its CSV export)"},
	{"f", "firefox", "Firefox", "file (its CSV export)"},
	{"a", "safari", "Safari", "file (its CSV export)"},
	{"g", "google-authenticator", "Google Authenticator", "files: screenshots of its transfer codes, separated by commas"},
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
	in.many = strings.Contains(files, "separated")
	asked := false
	pw := &input{kind: inputSecret, label: "the export's password", shown: func() bool { return asked }}
	f := &form{title: "Import from " + name, inputs: []*input{in, pw}, row: -1, enterDone: "read it", working: "Reading…"}
	f.submit = func() tea.Cmd {
		paths := splitPaths(in.value())
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
	m.importing = &importing{im: msg.im, name: m.importName}
	m.ov = &overlay{kind: panelImport, back: m.ov, title: "Import from " + m.importName, loading: true, busy: "Comparing with the vault…"}
	return m.planImport("")
}

// planImport plans the import with onConflict.
func (m *Model) planImport(onConflict string) tea.Cmd {
	in, epoch := m.importing, m.epoch
	in.onConflict = onConflict
	return m.read(func(_ Vault, _ func() bool) tea.Msg {
		plan, err := in.im.Plan(onConflict)
		return importPlannedMsg{plan: plan, err: err, epoch: epoch}
	})
}

// importPlanned shows what the import would do.
func (m *Model) importPlanned(msg *importPlannedMsg) tea.Cmd {
	ov := m.ov
	if msg.epoch != m.epoch || m.importing == nil || ov == nil || ov.kind != panelImport {
		return nil
	}
	ov.loading, ov.busy = false, ""
	switch {
	case errors.Is(msg.err, ErrLocked):
		return m.lock(lockedReason(msg.err))
	case msg.err != nil:
		ov.err = "Not read: " + msg.err.Error()
		return nil
	}
	m.importing.plan = msg.plan
	ov.items = nil
	for l := range strings.SplitSeq(msg.plan.Summary, "\n") {
		ov.items = append(ov.items, item{label: l})
	}
	ov.sel = min(ov.sel, max(len(ov.items)-1, 0))
	ov.opened = m.opts.Now()
	return nil
}

// importLetter is what the preview's letters do: s and o say what's done
// with entries the vault has, and y imports.
func (m *Model) importLetter(k string) tea.Cmd {
	in, ov := m.importing, m.ov
	if in == nil || ov.loading {
		return nil
	}
	switch {
	case k == "s" && in.plan.Clashes > 0 && in.onConflict != "skip":
		ov.loading, ov.busy = true, "Comparing with the vault…"
		return m.planImport("skip")
	case k == "o" && in.plan.Clashes > 0 && in.onConflict != "overwrite":
		ov.loading, ov.busy = true, "Comparing with the vault…"
		return m.planImport("overwrite")
	case k == "y":
		switch {
		case in.plan.Clashes > 0 && in.onConflict == "":
			ov.err = "Some of these are in the vault already: s leaves them as they are, o replaces them."
			return nil
		case in.plan.Count == 0:
			ov.err = "Nothing to import."
			return nil
		case m.opts.Now().Sub(ov.opened) < confirmAfter:
			return nil
		}
		ov.loading, ov.busy = true, "Importing…"
		epoch := m.epoch
		return m.read(func(_ Vault, _ func() bool) tea.Msg {
			said, err := in.im.Apply()
			return importedMsg{said: said, err: err, epoch: epoch}
		})
	}
	return nil
}

// imported says what the import did, and reads the entries again.
func (m *Model) imported(msg *importedMsg) tea.Cmd {
	if msg.epoch != m.epoch || m.importing == nil {
		return nil
	}
	m.endImport()
	switch {
	case errors.Is(msg.err, ErrLocked):
		return m.lock(lockedReason(msg.err))
	case msg.err != nil:
		m.ov = &overlay{kind: panelNotice, back: m.transferPanel(), title: "Import", question: "Not imported: " + msg.err.Error()}
		return m.reread()
	}
	m.ov = &overlay{kind: panelNotice, back: m.transferPanel(), title: "Import", question: msg.said}
	return m.reread()
}

// transferPanel is the import and export panel under the preview.
func (m *Model) transferPanel() *overlay {
	for ov := m.ov; ov != nil; ov = ov.back {
		if ov.kind == panelMenu && ov.title == "Import and export" {
			return ov
		}
	}
	return nil
}

// endImport wipes the import read.
func (m *Model) endImport() {
	if m.importing != nil {
		m.importing.im.Close()
		m.importing = nil
	}
}

// importHint is the preview's keys, as they fit width.
func (m *Model) importHint(width int) string {
	th, in := m.th, m.importing
	if in == nil || m.ov.loading {
		return th.hints([2]string{"esc", "cancel"})
	}
	var keys [][2]string
	switch {
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
	return th.hints(keys[0], keys[len(keys)-1])
}
