package tui

import (
	"errors"
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

// revealFor is how long secrets revealed with Tab stay on screen.
const revealFor = 30 * time.Second

// revealed is the selected entry's secrets, shown with Tab until it
// moves, the time runs out, or the app locks.
type revealed struct {
	until  time.Time
	k      vault.Key
	fields []vault.Field
	secret []byte
}

func (r *revealed) wipe() {
	if r == nil {
		return
	}
	secure.SecureZeroBytes(r.secret)
	for _, f := range r.fields {
		secure.SecureZeroBytes(f.Value)
	}
}

type (
	notesMsg struct {
		err   error
		k     vault.Key
		notes []byte
		epoch int
	}
	revealMsg struct {
		err    error
		k      vault.Key
		secret []byte
		fields []vault.Field
		epoch  int
	}
)

// selected is the selected entry, nil when there's none.
func (m *Model) selected() *vault.Entry {
	if m.sel < 0 || m.sel >= len(m.rows) {
		return nil
	}
	return &m.rows[m.sel]
}

// moved is what follows a change to the list or the selection: secrets
// revealed for another entry are hidden, the preview goes back to its top,
// and the keys and notes now shown are read.
func (m *Model) moved() tea.Cmd {
	e := m.selected()
	var k vault.Key
	if e != nil {
		k = e.Key
	}
	if k != m.selKey {
		m.selKey, m.previewTop = k, 0
		m.hide()
	}
	return tea.Batch(m.readKeys(), m.readNotes())
}

// hasNotes says whether e has notes to show: a secure note's text, or
// another entry's notes.
func hasNotes(e *vault.Entry) bool {
	return e.Kind == vault.KindNote || e.HasNotes
}

// readNotes reads the selected entry's notes, when it has some not held.
func (m *Model) readNotes() tea.Cmd {
	e := m.selected()
	if m.v == nil || e == nil || !hasNotes(e) {
		return nil
	}
	k := e.Key
	if m.notes[k] != nil || m.notesPending[k] || m.notesFailed[k] != "" {
		return nil
	}
	m.notesPending[k] = true
	epoch := m.epoch
	return m.read(func(v Vault, closed func() bool) tea.Msg {
		notes, err := v.Notes(k)
		if closed() {
			secure.SecureZeroBytes(notes)
			return nil
		}
		return notesMsg{k: k, notes: notes, err: err, epoch: epoch}
	})
}

// gotNotes keeps notes read, once.
func (m *Model) gotNotes(msg *notesMsg) tea.Cmd {
	if msg.epoch != m.epoch || m.v == nil || m.notes[msg.k] != nil {
		secure.SecureZeroBytes(msg.notes)
		return nil
	}
	delete(m.notesPending, msg.k)
	switch {
	case errors.Is(msg.err, ErrLocked):
		return m.lock(lockedReason(msg.err))
	case msg.err != nil:
		m.notesFailed[msg.k] = msg.err.Error()
	case len(msg.notes) == 0:
		m.notes[msg.k] = []byte{}
	default:
		m.notes[msg.k] = msg.notes
	}
	return nil
}

// toggleReveal shows the selected entry's password and secret fields, or
// hides them when they're shown.
func (m *Model) toggleReveal() tea.Cmd {
	e := m.selected()
	if e == nil {
		return nil
	}
	if m.shown != nil && m.shown.k == e.Key {
		m.hide()
		return nil
	}
	if m.revealing {
		return nil
	}
	k, kind := e.Key, e.Kind
	secretFields := false
	for _, f := range e.Fields {
		secretFields = secretFields || f.Secret
	}
	if (kind == vault.KindNote || kind == vault.KindTOTP) && !secretFields {
		m.say("Nothing more to reveal: " + whatsHidden(kind))
		return nil
	}
	epoch := m.epoch
	m.revealing = true
	return m.read(func(v Vault, closed func() bool) tea.Msg {
		msg := revealMsg{k: k, epoch: epoch}
		if kind != vault.KindNote && kind != vault.KindTOTP {
			msg.secret, msg.err = v.Secret(k, "in sesh ui, to reveal it")
		}
		if msg.err == nil && secretFields {
			msg.fields, msg.err = v.SecretFields(k)
		}
		if closed() {
			(&revealed{secret: msg.secret, fields: msg.fields}).wipe()
			return nil
		}
		return msg
	})
}

// whatsHidden says why Tab has nothing to show for a kind of entry.
func whatsHidden(k vault.Kind) string {
	if k == vault.KindTOTP {
		return "a TOTP entry shows its code, not its key"
	}
	return "the note is already shown"
}

// gotReveal shows what was revealed, while the entry stays selected.
func (m *Model) gotReveal(msg *revealMsg) tea.Cmd {
	m.revealing = false
	r := &revealed{k: msg.k, secret: msg.secret, fields: msg.fields, until: m.opts.Now().Add(revealFor)}
	if msg.epoch != m.epoch || m.v == nil || m.selKey != msg.k {
		r.wipe()
		return nil
	}
	if msg.err != nil {
		r.wipe()
		if errors.Is(msg.err, ErrLocked) {
			return m.lock(lockedReason(msg.err))
		}
		m.sayBad("Couldn't reveal it: " + msg.err.Error())
		return nil
	}
	m.hide()
	m.shown = r
	return nil
}

// hide wipes secrets revealed, and their wrapped lines.
func (m *Model) hide() {
	m.shown.wipe()
	m.shown = nil
	for id := range m.wraps {
		if strings.HasPrefix(id, "reveal ") {
			delete(m.wraps, id)
		}
	}
}

// wrapped is text wrapped to a width.
type wrapped struct {
	lines []string
	width int
}

// wrap is s wrapped to w, wrapped once for id at each width: s is made a
// string only then, so a secret isn't copied again each time it's drawn.
func (m *Model) wrap(id string, s []byte, w int) []string {
	if c, ok := m.wraps[id]; ok && c.width == w {
		return c.lines
	}
	lines := strings.Split(wrapText(string(s), w), "\n")
	m.wraps[id] = wrapped{lines: lines, width: w}
	return lines
}

// scrollPreview moves the preview by n lines.
func (m *Model) scrollPreview(n int) {
	m.previewTop = max(m.previewTop+n, 0)
}

// previewLines show the selected entry: what it is and where it's filed,
// its fields and notes, a TOTP entry's code counting down, and its
// password and secret fields only when revealed. h lines of width w;
// the last says what Enter and Tab do.
func (m *Model) previewLines(w, h int) []string {
	e := m.selected()
	if e == nil {
		return make([]string, h)
	}
	th := m.th
	var body []string
	add := func(s string) { body = append(body, " "+s) }
	add("")
	add(th.style().Bold(true).Render(ansi.Truncate(e.Service, w-2, "…")))
	where := badge(&th, e.Kind)
	if e.Folder != "" {
		where += th.dimmed().Render("  ▸ " + e.Folder)
	}
	add(where)
	add("")
	if e.Kind == vault.KindTOTP {
		if code, left, ok := m.code(e, m.opts.Now()); ok {
			add(th.accented().Bold(true).Render(spaced(groupCode(code))))
			add(m.countdown(left, e.Settings.TOTP, min(w-8, 28)))
			add("")
		} else if m.failed[e.Key] {
			add(lipgloss.NewStyle().Foreground(th.bad).Render("Its key can't be read: run sesh doctor."))
			add("")
		}
	}
	// The labels line up, as wide as the longest, up to a third of the pane.
	labelWidth := len("password")
	for _, f := range e.Fields {
		labelWidth = max(labelWidth, ansi.StringWidth(f.Name))
	}
	labelWidth = min(labelWidth, max(w/3, 8)) + 2
	label := func(s string) string {
		return th.dimmed().Render(fitTo(ansi.Truncate(s, labelWidth-2, "…"), labelWidth))
	}
	valueWidth := max(w-labelWidth-3, 8)
	field := func(name, value string, style lipgloss.Style) {
		if value == "" {
			return
		}
		lines := strings.Split(wrapText(value, valueWidth), "\n")
		for i, l := range lines {
			lab := ""
			if i == 0 {
				lab = name
			}
			add(label(lab) + style.Render(l))
		}
	}
	secretField := func(name string, lines []string, style lipgloss.Style) {
		for i, l := range lines {
			lab := ""
			if i == 0 {
				lab = name
			}
			add(label(lab) + style.Render(l))
		}
	}
	plain := th.style()
	shown := m.shown != nil && m.shown.k == e.Key
	hidden := th.dimmed().Render("••••••••")
	if e.Kind != vault.KindTOTP && e.Kind != vault.KindNote {
		name := "password"
		if e.Kind == vault.KindAPIKey {
			name = "key"
		}
		if shown {
			secretField(name, m.wrap("reveal "+name, m.shown.secret, valueWidth), th.accented())
		} else {
			add(label(name) + hidden)
		}
	}
	field("user", e.Username, plain)
	field("url", e.URL, plain)
	for _, f := range e.Fields {
		switch {
		case !f.Secret:
			field(f.Name, string(f.Value), plain)
		case shown:
			secretField(f.Name, m.wrap("reveal field "+f.Name, revealedField(m.shown, f.Name), valueWidth), th.accented())
		default:
			add(label(f.Name) + hidden)
		}
	}
	field("tags", strings.Join(e.Tags, ", "), plain)
	if p := e.Settings.TOTP; e.Kind == vault.KindTOTP && !p.IsDefault() {
		digits, period := p.Digits, p.Period
		if digits == 0 {
			digits = 6
		}
		if period == 0 {
			period = 30
		}
		field("code", fmt.Sprintf("%d digits, every %ds", digits, period), plain)
	}
	if !e.UpdatedAt.IsZero() {
		field("changed", ago(m.opts.Now(), e.UpdatedAt), th.dimmed())
	}
	if hasNotes(e) {
		add("")
		switch notes, ok := m.notes[e.Key]; {
		case ok:
			for _, l := range m.wrap("notes "+e.Key.String(), notes, w-3) {
				add(plain.Render(l))
			}
		case m.notesFailed[e.Key] != "":
			add(lipgloss.NewStyle().Foreground(th.bad).Render(ansi.Truncate("Notes can't be read: "+m.notesFailed[e.Key], w-3, "…")))
		default:
			add(th.dimmed().Render("…"))
		}
	}

	// The body scrolls above the line of keys.
	room := h - 1
	m.previewTop = min(m.previewTop, max(len(body)-room, 0))
	out := make([]string, 0, h)
	out = append(out, body[m.previewTop:min(m.previewTop+room, len(body))]...)
	for len(out) < room {
		out = append(out, "")
	}
	keys := [][2]string{{"↵", "copy"}}
	if e.Kind != vault.KindTOTP && e.Kind != vault.KindNote || hasSecretFields(e) {
		word := "reveal"
		if shown {
			word = fmt.Sprintf("hide (%ds)", max(int(m.shown.until.Sub(m.opts.Now()).Seconds()), 0))
		}
		keys = append(keys, [2]string{"tab", word})
	}
	if len(body) > room {
		keys = append(keys, [2]string{"shift ↑↓", "scroll"})
	}
	return append(out, " "+th.hints(keys...))
}

func hasSecretFields(e *vault.Entry) bool {
	for _, f := range e.Fields {
		if f.Secret {
			return true
		}
	}
	return false
}

// revealedField is the revealed value of the secret field named name.
func revealedField(r *revealed, name string) []byte {
	for _, f := range r.fields {
		if f.Name == name {
			return f.Value
		}
	}
	return nil
}

// wrapText wraps s to w columns, keeping its own line breaks. Control
// characters are drawn as symbols: a note or a secret can hold any, and
// written as they are, one could move the cursor or restyle the terminal.
func wrapText(s string, w int) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n':
			return r
		case r == '\t':
			return ' '
		case r < 0x20:
			return 0x2400 + r // ␀ … ␟
		case r == 0x7f:
			return '␡'
		case r >= 0x80 && r < 0xa0:
			return '�'
		}
		return r
	}, s)
	return ansi.Wrap(s, max(w, 4), "")
}
