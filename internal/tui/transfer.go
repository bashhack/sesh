package tui

import (
	"bytes"
	"errors"
	"slices"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

// exportedMsg is an export written, or why not.
type exportedMsg struct {
	err       error
	f         *form
	replaceOf *string // the file a second Enter replaces, set when one is there
	said, to  string
}

// openTransfer opens the import and export panel.
func (m *Model) openTransfer() tea.Cmd {
	m.ov = &overlay{kind: panelMenu, back: m.ov, title: "Import and export", items: append([]item{
		{key: "e", label: "export, encrypted…", stay: true, run: m.exportForm},
	}, m.importRows()...)}
	return nil
}

// exportKinds are the kinds an export can be narrowed to, in the order
// its form offers them after every entry.
var exportKinds = []vault.Kind{"", vault.KindPassword, vault.KindAPIKey, vault.KindNote, vault.KindTOTP}

// exportForm asks where to export, which entries (every one, or those of
// a kind, folder or tags), and a password for the export, twice, and
// writes it.
func (m *Model) exportForm() tea.Cmd {
	file := m.textInput("file", "")
	file.hint = "a full path, or one starting with ~/"
	kind := &input{kind: inputChoice, label: "entries", choices: []string{"every entry", "passwords", "API keys", "notes", "TOTP"}}
	folder := m.textInput("in folder", "")
	folder.hint, folder.offers = "empty: any; a folder takes in those under it", m.folderNames()
	tags := m.textInput("with tags", "")
	tags.hint, tags.many, tags.offers = "empty: any; separated by commas, an entry having each", true, m.tagNames()
	pw := &input{kind: inputSecret, label: "export password", rated: true, hint: "at least 8 characters: it opens the export anywhere"}
	again := &input{kind: inputSecret, label: "export password again"}
	f := &form{title: "Export, encrypted", inputs: []*input{file, kind, folder, tags, pw, again}, row: -1, enterDone: "export",
		working: "Exporting…", quitting: "Quitting once the export is written…"}
	replaceOf := ""
	f.lost = func() string {
		if f.saving {
			return "The export may or may not have been written: look at " + file.value() + " before exporting again."
		}
		return ""
	}
	f.submit = func() tea.Cmd {
		to := file.value()
		only := ExportOnly{Kind: exportKinds[kind.choice], Folder: folder.value()}
		for t := range strings.SplitSeq(tags.value(), ",") {
			if t = strings.TrimSpace(t); t != "" && !slices.Contains(only.Tags, t) {
				only.Tags = append(only.Tags, t)
			}
		}
		badFiling := ""
		if only.Folder != "" {
			if err := vault.CheckFolder(only.Folder); err != nil {
				badFiling = err.Error()
			}
		}
		for _, t := range only.Tags {
			if err := vault.CheckTag(t); err != nil && badFiling == "" {
				badFiling = err.Error()
			}
		}
		switch {
		case to == "":
			f.err = "Type where to put it."
		case badFiling != "":
			f.err = badFiling
		case len(pw.secret) < 8:
			f.err = "The export password must be at least 8 characters."
		case !bytes.Equal(pw.secret, again.secret):
			f.err = "The export password and its repeat don't match."
		case pw.weak && !pw.accepted:
			pw.accepted = true
			f.err = "That password is easy to guess, and anyone with the file can try passwords against it. Press Enter again to use it anyway."
		default:
			f.saving, f.err = true, ""
			// The export takes what was typed; the form keeps a copy to try
			// again with.
			secret, replace := pw.secret, to == replaceOf
			pw.secret = bytes.Clone(secret)
			return wipeUnread(secret, m.read(func(v Vault, _ func() bool) tea.Msg {
				said, err := v.Export(to, secret, replace, only)
				return exportedMsg{f: f, said: said, err: err, to: to, replaceOf: &replaceOf}
			}))
		}
		return nil
	}
	f.focusInput(0)
	m.form = f
	return nil
}

// exported says what an export did, or keeps its form to try again.
func (m *Model) exported(msg *exportedMsg) tea.Cmd {
	f := msg.f
	if m.form != f {
		// Locked meanwhile, which said so.
		return nil
	}
	if m.quitAfter {
		m.form = nil
		f.wipe()
		m.afterword = msg.said
		if msg.err != nil {
			m.afterword = "The vault wasn't exported: " + msg.err.Error()
		}
		return tea.Quit
	}
	f.saving = false
	switch {
	case errors.Is(msg.err, ErrLocked):
		return m.lock(lockedReason(msg.err))
	case errors.Is(msg.err, ErrExists):
		*msg.replaceOf = msg.to
		f.err = msg.err.Error() + " Press Enter again to replace it."
		return nil
	case msg.err != nil:
		f.err = "Not exported: " + strings.TrimSuffix(msg.err.Error(), ".") + "."
		return nil
	}
	f.wipe()
	m.form = nil
	m.say(msg.said)
	return nil
}

// wipeUnread is read, wiping secret when the app locked before it could
// run (and take secret to wipe it).
func wipeUnread(secret []byte, read tea.Cmd) tea.Cmd {
	return func() tea.Msg {
		msg := read()
		if msg == nil {
			secure.SecureZeroBytes(secret)
		}
		return msg
	}
}
