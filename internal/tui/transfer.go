package tui

import (
	"bytes"
	"errors"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/bashhack/sesh/internal/secure"
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
	m.ov = &overlay{kind: panelMenu, back: m.ov, title: "Import and export", items: []item{
		{key: "e", label: "export the vault, encrypted…", stay: true, run: m.exportForm},
	}}
	return nil
}

// exportForm asks where to export the vault, and a password for the
// export, twice, and writes it.
func (m *Model) exportForm() tea.Cmd {
	file := m.textInput("file", "")
	file.hint = "a full path, or one starting with ~/"
	pw := &input{kind: inputSecret, label: "export password", rated: true, hint: "at least 8 characters: it opens the export anywhere"}
	again := &input{kind: inputSecret, label: "export password again"}
	f := &form{title: "Export the vault", inputs: []*input{file, pw, again}, row: -1, enterDone: "export",
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
		switch {
		case to == "":
			f.err = "Type where to put it."
		case len(pw.secret) < 8:
			f.err = "The export password must be at least 8 characters."
		case !bytes.Equal(pw.secret, again.secret):
			f.err = "The export password and its repeat don't match."
		case pw.weak && !pw.accepted:
			pw.accepted = true
			f.err = "That password is easy to guess, and anyone with the file can try passwords against it. Press Enter again to use it anyway."
		default:
			f.saving, f.err = true, ""
			secret, replace := bytes.Clone(pw.secret), to == replaceOf
			return wipeUnread(secret, m.read(func(v Vault, _ func() bool) tea.Msg {
				said, err := v.Export(to, secret, replace)
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
