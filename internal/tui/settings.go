package tui

import (
	"cmp"
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/bashhack/sesh/internal/config"
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
	Env string
	// File is the config file a change is saved in; NoFile, that it isn't
	// there yet, and the first change makes it.
	File     string
	Editable bool
	// Switch says it's on or off (Raw true or false): Enter turns it over.
	Switch bool
	NoFile bool
}

// Live is what of the settings the app takes up as it runs: the rest it
// reads when it starts.
type Live struct {
	OldAfter time.Duration
}

// settingsMsg is the settings, read for the panel.
type settingsMsg struct {
	err      error
	recovery *Recovery // nil when it isn't shown
	touchID  *TouchID  // nil when it isn't shown
	settings []Setting
}

// openSettings opens the settings and safety panel.
func (m *Model) openSettings() tea.Cmd {
	if m.opts.Settings == nil {
		m.sayBad("Settings can't be shown here.")
		return nil
	}
	m.ov = &overlay{kind: panelSettings, back: m.ov, title: "Settings and safety", loading: true}
	return m.refreshSettings()
}

// showSettings lists the settings in the open panel.
func (m *Model) showSettings(settings []Setting, recovery *Recovery, touch *TouchID) {
	ov := m.ov
	sel := ov.sel
	ov.items = nil
	if m.opts.ChangePassword != nil {
		ov.items = append(ov.items, item{
			label:  fmt.Sprintf("%-25s %s", "Master password", "change…"),
			detail: "Every entry is re-encrypted under the new one; Touch ID unlock and the recovery key go on working with it. The current one is asked first.",
			run:    m.changePassword,
			stay:   true,
		})
	}
	if recovery != nil {
		ov.items = append(ov.items, m.recoveryRow(*recovery))
	}
	if touch != nil {
		ov.items = append(ov.items, m.touchIDRow(*touch))
	}
	ov.items = append(ov.items, item{
		label:  fmt.Sprintf("%-25s %s", "Checks (sesh doctor)", "run…"),
		detail: "Checks sesh's setup, then that the vault's file, every entry, the trash, the history, the recovery key and Touch ID all read, as sesh doctor does. Reading the vault is recorded in the audit log.",
		run:    m.openChecks,
		does:   "run them",
		stay:   true,
	}, item{
		label:  fmt.Sprintf("%-25s %s", "Audit log (sesh audit)", "read…"),
		detail: "Each secret read, each change, delete and restore, and each master password change, the newest first: names and what was done, never a secret. audit.retention_days below sets how long events are kept.",
		run:    m.openAudit,
		does:   "read it",
		stay:   true,
	})
	for i := range settings {
		s := &settings[i]
		from := ""
		switch {
		case s.Env != "":
			from = "  (" + s.Env + ")"
		case s.Said == "config file":
			from = "  (config file)"
		}
		does := ""
		if s.Switch && s.Env == "" {
			does = "turn it on"
			if s.Raw == "true" {
				does = "turn it off"
			}
		}
		ov.items = append(ov.items, item{
			label:  fmt.Sprintf("%-25s %s%s", s.Key, s.Value, from),
			detail: settingDetail(s),
			run:    func() tea.Cmd { return m.changeSetting(s) },
			does:   does,
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
	key, raw, def, applies, said, set := s.Key, s.Raw, s.Default, s.Applies, s.Said, m.opts.SetSetting
	in := "the config file"
	if s.File != "" {
		in = s.File
	}
	if s.Switch {
		to, word := "true", "on"
		if raw == "true" {
			to, word = "false", "off"
		}
		live, err := set(key, to)
		if err != nil {
			if m.ov != nil {
				m.ov.err = "Not saved: " + err.Error()
			}
			return m.refreshSettings()
		}
		m.opts.OldAfter = live.OldAfter
		m.say("Turned " + key + " " + word + " in " + in + ": it takes effect " + applies)
		return m.refreshSettings()
	}
	return m.askOver(true, "Change "+key, key, s.Raw, "empty: back to the default; it takes effect "+applies, nil, func(value string) (string, tea.Cmd) {
		// Against the file as it is now, which another command may have
		// changed since the panel was read.
		from, fromSaid := raw, said
		if now, err := m.opts.Settings(); err == nil {
			for i := range now {
				if x := &now[i]; x.Key == key {
					from, fromSaid = x.Raw, x.Said
				}
			}
		}
		if value == from || value == "" && strings.HasPrefix(fromSaid, "default") {
			m.say("Nothing changed: " + key + " is " + cmp.Or(value, "at its default") + " already.")
			if from != raw || fromSaid != said {
				return "", m.refreshSettings() // the panel shows it as it was
			}
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
			said := "Saved " + key + " in " + in + ": it takes effect " + applies
			if value == "" {
				said = "Took " + key + " out of " + in + ": its default takes effect " + applies
			}
			m.say(said)
			return m.refreshSettings()
		}
		to := value
		if to == "" {
			to = def
		}
		if loss := config.Loss(key, from, to); loss != "" {
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
		said := "Saved " + key + " in " + in + ": it takes effect " + applies
		if value == "" {
			said = "Took " + key + " out of " + in + ": its default takes effect " + applies
		}
		m.say(said)
		return "", m.refreshSettings()
	})
}

// refreshSettings reads the settings again into the open panel.
func (m *Model) refreshSettings() tea.Cmd {
	read, recovery, touch := m.opts.Settings, m.opts.Recovery, m.opts.TouchIDState
	return func() tea.Msg {
		var msg settingsMsg
		msg.settings, msg.err = read()
		if recovery != nil && msg.err == nil {
			r, err := recovery()
			msg.recovery, msg.err = &r, err
		}
		if touch != nil && msg.err == nil {
			t, err := touch()
			msg.touchID, msg.err = &t, err
		}
		return msg
	}
}

// gotSettings fills the settings panel, when it's open: on top, or under
// a question about one of its rows.
func (m *Model) gotSettings(msg *settingsMsg) tea.Cmd {
	panel := m.ov
	for panel != nil && panel.kind != panelSettings {
		panel = panel.back
	}
	if panel == nil {
		return nil
	}
	top := m.ov
	m.ov = panel
	cmd := m.loaded(msg.err, func() { m.showSettings(msg.settings, msg.recovery, msg.touchID) })
	if m.ov == panel {
		m.ov = top
	}
	return cmd
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
	d := s.Value + " · " + s.Said + " · a change takes effect " + s.Applies
	switch {
	case s.File == "":
	case s.NoFile:
		d += " · saved in " + s.File + ", which the first change makes"
	default:
		d += " · saved in " + s.File
	}
	return d
}
