package tui

import (
	"fmt"
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
	// Env is the environment variable that sets it, when one does: it
	// can't be changed from the app then.
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
	ov.settings = settings
	for _, s := range settings {
		from := ""
		switch {
		case s.Env != "":
			from = "  (" + s.Env + ")"
		case s.Said == "config file":
			from = "  (config file)"
		}
		ov.items = append(ov.items, item{
			label: fmt.Sprintf("%-24s %s%s", s.Key, s.Value, from),
			run:   func() tea.Cmd { return m.changeSetting(&s) },
			stay:  true,
		})
	}
	ov.sel = min(sel, max(len(ov.items)-1, 0))
}

// changeSetting asks for setting s's new value, and saves it in the
// config file.
func (m *Model) changeSetting(s *Setting) tea.Cmd {
	switch {
	case s.Env != "":
		m.sayBad(s.Key + " is set by " + s.Env + " in the environment; change it there.")
		return nil
	case !s.Editable:
		m.sayBad(s.Key + " is where the vault is; it's changed with sesh init, not under an open vault.")
		return nil
	case m.opts.SetSetting == nil:
		return nil
	}
	key, applies, set := s.Key, s.Applies, m.opts.SetSetting
	return m.askOver(true, "Change "+key, key, s.Raw, "empty: back to the default; it takes effect "+applies, nil, func(value string) (string, tea.Cmd) {
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
		return s.Value + " · set by " + s.Env + " in the environment: change it there"
	case !s.Editable:
		return s.Value + " · where the vault is: sesh init moves it"
	}
	return s.Value + " · " + s.Said + " · a change takes effect " + s.Applies
}
