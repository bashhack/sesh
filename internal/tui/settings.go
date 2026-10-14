package tui

import (
	"fmt"
	"strconv"
	"time"

	tea "charm.land/bubbletea/v2"
)

// Setting is a config setting as the settings panel lists it.
type Setting struct {
	Key   string
	Value string // as said: "30s", "0 (off)"
	Raw   string // as the config file has it, to change
	Said  string // where it comes from: "default", "config file"
	// Applies is when a change takes effect.
	Applies string
	// Default is Raw's default, which an empty value goes back to.
	Default string
	// Env is the environment variable (or flag) that sets it, when one
	// does: it can't be changed from the app then.
	Env      string
	Editable bool
}

// Live is what of the settings the app takes up as it runs: the rest it
// reads when it starts.
type Live struct {
	OldAfter time.Duration
}

// settingsMsg is the settings, read for the panel.
type settingsMsg struct {
	err      error
	settings []Setting
}

// openSettings opens the settings and safety panel.
func (m *Model) openSettings() tea.Cmd {
	if m.opts.Settings == nil {
		m.sayBad("Settings can't be shown here.")
		return nil
	}
	m.ov = &overlay{kind: panelSettings, back: m.ov, title: "Settings and safety", loading: true}
	read := m.opts.Settings
	return func() tea.Msg {
		s, err := read()
		return settingsMsg{settings: s, err: err}
	}
}

// showSettings lists the settings in the open panel.
func (m *Model) showSettings(settings []Setting) {
	ov := m.ov
	sel := ov.sel
	ov.items = nil
	if m.opts.ChangePassword != nil {
		ov.items = append(ov.items, item{
			label:  fmt.Sprintf("%-24s %s", "Master password", "change…"),
			detail: "Every entry is re-encrypted under the new one; Touch ID unlock and the recovery key go on working with it. The current one is asked first.",
			run:    m.changePassword,
			stay:   true,
		})
	}
	ov.items = append(ov.items, item{
		label:  fmt.Sprintf("%-24s %s", "Checks (sesh doctor)", "run…"),
		detail: "Checks sesh's setup, then that the vault's file, every entry, the trash, the history, the recovery key and Touch ID all read, as sesh doctor does. Reading the vault is recorded in the audit log.",
		run:    m.openChecks,
		does:   "run them",
		stay:   true,
	})
	for i, s := range settings {
		from := ""
		switch {
		case s.Env != "":
			from = "  (" + s.Env + ")"
		case s.Said == "config file":
			from = "  (config file)"
		}
		ov.items = append(ov.items, item{
			label:  fmt.Sprintf("%-24s %s%s", s.Key, s.Value, from),
			detail: settingDetail(&s),
			run:    func() tea.Cmd { return m.changeSetting(&s) },
			stay:   true,
			rule:   i == 0,
		})
	}
	ov.sel = min(sel, max(len(ov.items)-1, 0))
}

// changeSetting asks for setting s's new value, and saves it in the
// config file.
func (m *Model) changeSetting(s *Setting) tea.Cmd {
	switch {
	case s.Env != "":
		m.sayBad(s.Key + " is set by " + s.Env + ", outside the config file; change it there.")
		return nil
	case !s.Editable:
		m.sayBad(s.Key + " is where the vault is; it's changed with sesh init, not under an open vault.")
		return nil
	case m.opts.SetSetting == nil:
		return nil
	}
	key, raw, def, applies, set := s.Key, s.Raw, s.Default, s.Applies, m.opts.SetSetting
	return m.askOver(true, "Change "+key, key, s.Raw, "empty: back to the default; it takes effect "+applies, nil, func(value string) (string, tea.Cmd) {
		if value == raw {
			m.say("Nothing changed.")
			return "", nil
		}
		save := func() tea.Cmd {
			live, err := set(key, value)
			if err != nil {
				if m.ov != nil {
					m.ov.err = "Not saved: " + err.Error()
				}
				return m.refreshSettings()
			}
			m.opts.OldAfter = live.OldAfter
			said := "Saved " + key + ": it takes effect " + applies
			if value == "" {
				said = "Took " + key + " out of the config file: its default takes effect " + applies
			}
			m.say(said)
			return m.refreshSettings()
		}
		to := value
		if to == "" {
			to = def
		}
		// Against the file as it is now, which another command may have
		// changed since the panel was read.
		from := raw
		if now, err := m.opts.Settings(); err == nil {
			for _, x := range now {
				if x.Key == key {
					from = x.Raw
				}
			}
		}
		if loss := settingLoss(key, from, to); loss != "" {
			// What's deleted for good is asked about first.
			panel := m.ov
			m.ov = m.confirm(panel, "Change "+key, loss+" Change it?", func() tea.Cmd {
				m.ov = panel
				return save()
			})
			m.ov.danger = true
			return "", nil
		}
		// Checked before the form closes, so a value refused is said in it.
		live, err := set(key, value)
		if err != nil {
			return err.Error(), nil
		}
		m.opts.OldAfter = live.OldAfter
		said := "Saved " + key + ": it takes effect " + applies
		if value == "" {
			said = "Took " + key + " out of the config file: its default takes effect " + applies
		}
		m.say(said)
		return "", m.refreshSettings()
	})
}

// settingLoss is what changing key from from to to deletes for good, in
// words; "" when nothing. Each of these keeps everything at 0, so only a
// smaller number deletes.
func settingLoss(key, from, to string) string {
	f, ferr := strconv.Atoi(from)
	t, terr := strconv.Atoi(to)
	if ferr != nil || terr != nil || t <= 0 || (f > 0 && t >= f) {
		return ""
	}
	switch key {
	case "history.keep":
		return fmt.Sprintf("Each entry's earlier secrets beyond its newest %d will be deleted for good, the next time a command unlocks the vault.", t)
	case "trash.keep_days":
		return fmt.Sprintf("Entries in the trash for more than %s will be deleted for good, the next time a command unlocks the vault.", plural(t, "1 day", fmt.Sprintf("%d days", t)))
	case "audit.retention_days":
		return fmt.Sprintf("Audit log events older than %s will be deleted, the next time a command unlocks the vault.", plural(t, "1 day", fmt.Sprintf("%d days", t)))
	case "backup.keep":
		return fmt.Sprintf("Backups beyond the newest %d will be deleted at the next backup.", t)
	}
	return ""
}

// refreshSettings reads the settings again into the open panel.
func (m *Model) refreshSettings() tea.Cmd {
	read := m.opts.Settings
	return func() tea.Msg {
		s, err := read()
		return settingsMsg{settings: s, err: err}
	}
}

// gotSettings fills the settings panel, when it's open.
func (m *Model) gotSettings(msg *settingsMsg) tea.Cmd {
	if m.ov == nil || m.ov.kind != panelSettings {
		return nil
	}
	return m.loaded(msg.err, func() { m.showSettings(msg.settings) })
}

// settingDetail says more of the selected setting than its row: its
// whole value, where it comes from, and when a change takes effect.
func settingDetail(s *Setting) string {
	switch {
	case s.Env != "":
		return s.Value + " · set by " + s.Env + ", outside the config file: change it there"
	case !s.Editable:
		return s.Value + " · where the vault is: sesh init moves it"
	}
	return s.Value + " · " + s.Said + " · a change takes effect " + s.Applies
}
