package tui

import (
	"errors"

	tea "charm.land/bubbletea/v2"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

// savedFileMsg is a file entry's file written out, or why it wasn't.
type savedFileMsg struct {
	err   error
	what  string
	epoch int
}

// askSaveFile asks where to write file entry e's file, then writes it
// there, readable only by you: a read the audit log records.
func (m *Model) askSaveFile(e *vault.Entry) tea.Cmd {
	if m.opts.SaveFile == nil {
		m.sayBad("sesh ui can't write files here.")
		return nil
	}
	k, name, opts, epoch := e.Key, entryName(e), m.opts, m.epoch
	suggest := ""
	if e.Settings.FileName != "" {
		suggest = "~/" + e.Settings.FileName
	}
	return m.askOver(false, "Save "+name+" to a file", "file", suggest, "a full path, or from ~/; a file already there isn't replaced", nil, func(typed string) (string, tea.Cmd) {
		if typed == "" {
			return "Give the file to write it to.", nil
		}
		return "", m.read(func(v Vault, _ func() bool) tea.Msg {
			content, err := v.Secret(k, "in sesh ui, to save it to a file")
			if err != nil {
				return savedFileMsg{err: err, epoch: epoch}
			}
			defer secure.SecureZeroBytes(content)
			where, err := opts.SaveFile(typed, content)
			if err != nil {
				return savedFileMsg{err: err, epoch: epoch}
			}
			return savedFileMsg{what: "Saved " + name + " to " + where + ", readable only by you", epoch: epoch}
		})
	})
}

// savedFile says what saving a file did.
func (m *Model) savedFile(msg *savedFileMsg) tea.Cmd {
	switch {
	case msg.epoch != m.epoch || m.v == nil:
		return nil
	case errors.Is(msg.err, ErrLocked):
		return m.lock(lockedReason(msg.err))
	case msg.err != nil:
		m.sayBad("Not saved: " + msg.err.Error())
	default:
		m.say(msg.what)
	}
	return nil
}
