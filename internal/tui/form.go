package tui

import (
	"bytes"
	"io"
	"strings"
	"unicode/utf8"

	"charm.land/bubbles/v2/textarea"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/bashhack/sesh/internal/secure"
)

// inputKind is what an input of a form takes.
type inputKind int

const (
	inputText   inputKind = iota // a line of text
	inputSecret                  // a secret, typed unseen into wipeable memory
	inputNotes                   // lines of text
	inputChoice                  // one of a few
	inputFields                  // an entry's custom fields
)

// input is one of a form's inputs.
type input struct {
	shown   func() bool   // nil: always shown
	named   func() string // its label, when that depends on other inputs
	label   string
	hint    string
	choices []string
	secret  []byte
	rows    []fieldRow
	text    textinput.Model
	area    textarea.Model
	kind    inputKind
	choice  int
	row     int
	rated   bool // a password, whose strength is said
	weak    bool // the secret typed is easy to guess
}

// name is the input's label.
func (in *input) name() string {
	if in.named != nil {
		return in.named()
	}
	return in.label
}

func (in *input) visible() bool { return in.shown == nil || in.shown() }

// value is a text input's value, trimmed.
func (in *input) value() string { return strings.TrimSpace(in.text.Value()) }

// fieldRow is a custom field in a form: its name, and its value, which a
// secret field the form hasn't changed doesn't hold (nil).
type fieldRow struct {
	name, orig string // orig is the name it had, "" for one added
	value      []byte
	secret     bool
	changed    bool
}

// form is a form over the app: an entry's edit, an entry to add, or one
// custom field's.
type form struct {
	submit  func() tea.Cmd // checks the inputs and saves
	back    *form          // the form a field's form returns to
	title   string
	err     string
	inputs  []*input
	focus   int
	row     int // the field a field's form edits; -1 for a new one
	saving  bool
	changed bool // something was typed or chosen
	leaving bool // Esc was pressed once on a changed form
}

// textInput is a line of text, at first value.
func (m *Model) textInput(label, value string) *input {
	in := textinput.New()
	in.Prompt = ""
	in.KeyMap.Paste.SetEnabled(false)
	in.KeyMap.AcceptSuggestion.SetEnabled(false)
	in.KeyMap.NextSuggestion.SetEnabled(false)
	in.KeyMap.PrevSuggestion.SetEnabled(false)
	in.SetValue(value)
	in.CursorEnd()
	s := textinput.DefaultStyles(m.dark)
	s.Focused.Text, s.Blurred.Text = m.th.style(), m.th.style()
	s.Cursor.Color, s.Cursor.Blink = m.th.accent, false
	in.SetStyles(s)
	return &input{kind: inputText, label: label, text: in}
}

// notesInput is lines of text, at first value.
func (m *Model) notesInput(label, value string) *input {
	a := textarea.New()
	a.ShowLineNumbers = false
	a.Prompt = ""
	a.KeyMap.Paste.SetEnabled(false)
	a.SetValue(value)
	s := textarea.DefaultStyles(m.dark)
	s.Focused.Text, s.Blurred.Text = m.th.style(), m.th.style()
	s.Cursor.Color, s.Cursor.Blink = m.th.accent, false
	a.SetStyles(s)
	return &input{kind: inputNotes, label: label, area: a}
}

// focusInput moves the form's focus to its input i.
func (f *form) focusInput(i int) {
	for j, in := range f.inputs {
		switch {
		case in.kind == inputText && j == i:
			in.text.Focus()
		case in.kind == inputText:
			in.text.Blur()
		case in.kind == inputNotes && j == i:
			in.area.Focus()
		case in.kind == inputNotes:
			in.area.Blur()
		}
	}
	f.focus = i
}

// move moves the focus by step to the next input shown.
func (f *form) move(step int) {
	for i := f.focus + step; i >= 0 && i < len(f.inputs); i += step {
		if f.inputs[i].visible() {
			f.focusInput(i)
			return
		}
	}
}

// wipe overwrites the secrets the form holds.
func (f *form) wipe() {
	for ; f != nil; f = f.back {
		for _, in := range f.inputs {
			secure.SecureZeroBytes(in.secret)
			for _, r := range in.rows {
				if r.secret {
					secure.SecureZeroBytes(r.value)
				}
			}
		}
	}
}

// editorMsg is notes back from the editor.
type editorMsg struct {
	err   error
	notes []byte
}

// editor runs the user's editor on notes with the terminal handed to it.
type editor struct {
	edit  func([]byte) ([]byte, error)
	err   error
	notes []byte
}

func (e *editor) Run() error {
	out, err := e.edit(e.notes)
	secure.SecureZeroBytes(e.notes)
	e.notes, e.err = out, err
	return err
}
func (e *editor) SetStdin(io.Reader)  {}
func (e *editor) SetStdout(io.Writer) {}
func (e *editor) SetStderr(io.Writer) {}

// formKey handles a key while a form is open: Tab and Shift-Tab move
// between its inputs, Ctrl-S saves, Esc goes back, and the rest are the
// focused input's.
func (m *Model) formKey(msg tea.KeyPressMsg) tea.Cmd {
	m.lastKey = m.opts.Now()
	f := m.form
	if f.saving {
		if msg.String() == "ctrl+c" {
			return tea.Quit
		}
		return nil
	}
	in := f.inputs[f.focus]
	if msg.String() == "ctrl+c" {
		return tea.Quit
	}
	if m.width < minWidth || m.height < minHeight {
		// The form isn't on screen: nothing is typed into it unseen.
		return nil
	}
	if msg.String() != "esc" {
		f.leaving = false
	}
	switch msg.String() {
	case "esc":
		// What was typed isn't thrown away on one stray Esc.
		if f.changed && !f.leaving {
			f.leaving, f.err = true, "Not saved. Esc again discards what you changed."
			return nil
		}
		if f.back == nil {
			f.wipe()
		}
		m.form = f.back
		return nil
	case "tab":
		f.move(1)
		return nil
	case "shift+tab":
		f.move(-1)
		return nil
	case "ctrl+s":
		return f.submit()
	case "enter":
		switch in.kind {
		case inputNotes:
		case inputFields:
			return m.openFieldForm(in, in.row)
		default:
			f.move(1)
			return nil
		}
	}
	f.err, f.changed = "", true
	switch in.kind {
	case inputText:
		var cmd tea.Cmd
		in.text, cmd = in.text.Update(msg)
		return cmd
	case inputNotes:
		if msg.String() == "ctrl+e" && m.opts.EditNotes != nil {
			e := &editor{edit: m.opts.EditNotes, notes: []byte(in.area.Value())}
			return tea.Exec(e, func(err error) tea.Msg { return editorMsg{notes: e.notes, err: e.err} })
		}
		var cmd tea.Cmd
		in.area, cmd = in.area.Update(msg)
		return cmd
	case inputSecret:
		switch msg.String() {
		case "backspace":
			if _, size := utf8.DecodeLastRune(in.secret); size > 0 {
				secure.SecureZeroBytes(in.secret[len(in.secret)-size:])
				in.secret = in.secret[:len(in.secret)-size]
			}
		case "ctrl+u":
			secure.SecureZeroBytes(in.secret)
			in.secret = in.secret[:0]
		default:
			if msg.Text == "" || msg.Mod&(tea.ModCtrl|tea.ModAlt) != 0 {
				return nil
			}
			in.secret = appendSecret(in.secret, msg.Text)
		}
		m.rateSecret(in)
	case inputChoice:
		switch msg.String() {
		case "left", "h":
			in.choice = (in.choice + len(in.choices) - 1) % len(in.choices)
		case "right", "l", "space":
			in.choice = (in.choice + 1) % len(in.choices)
		}
	case inputFields:
		switch msg.String() {
		case "up", "k":
			in.row = max(in.row-1, 0)
		case "down", "j":
			in.row = min(in.row+1, max(len(in.rows)-1, 0))
		case "a", "n":
			return m.openFieldForm(in, -1)
		case "x", "delete":
			if in.row < len(in.rows) {
				if in.rows[in.row].secret {
					secure.SecureZeroBytes(in.rows[in.row].value)
				}
				in.rows = append(in.rows[:in.row], in.rows[in.row+1:]...)
				in.row = max(min(in.row, len(in.rows)-1), 0)
			}
		}
	}
	return nil
}

// formPaste pastes into the focused input, without a line's end.
func (m *Model) formPaste(text string) tea.Cmd {
	f := m.form
	if f.saving {
		return nil
	}
	in := f.inputs[f.focus]
	f.changed = true
	switch in.kind {
	case inputText:
		var cmd tea.Cmd
		in.text, cmd = in.text.Update(tea.PasteMsg{Content: trimNewlines(text)})
		return cmd
	case inputNotes:
		in.area.InsertString(text)
	case inputSecret:
		in.secret = appendSecret(in.secret, strings.TrimRight(text, "\r\n"))
		m.rateSecret(in)
	}
	return nil
}

// rateSecret notes whether the secret typed is easy to guess.
func (m *Model) rateSecret(in *input) {
	in.weak = in.rated && len(in.secret) > 0 && m.opts.IsWeak != nil && m.opts.IsWeak(in.secret)
}

// openFieldForm opens a form for the custom field at row (-1: a new one)
// of the fields input in.
func (m *Model) openFieldForm(in *input, row int) tea.Cmd {
	var r fieldRow
	if row >= 0 && row < len(in.rows) {
		r = in.rows[row]
	} else {
		row = -1
	}
	name := m.textInput("name", r.name)
	secretChoice := &input{kind: inputChoice, label: "secret", choices: []string{"no", "yes"}}
	if r.secret {
		secretChoice.choice = 1
	}
	isSecret := func() bool { return secretChoice.choice == 1 }
	plain := m.textInput("value", "")
	if !r.secret {
		plain.text.SetValue(string(r.value))
	}
	plain.shown = func() bool { return !isSecret() }
	hidden := &input{kind: inputSecret, label: "value", shown: isSecret}
	if r.secret && r.value == nil && row >= 0 {
		hidden.hint = "leave it empty to keep the value it has"
	}
	if r.secret && r.value != nil {
		hidden.secret = bytes.Clone(r.value)
	}
	ff := &form{title: "A field", back: m.form, row: row, inputs: []*input{name, secretChoice, plain, hidden}}
	ff.submit = func() tea.Cmd {
		n := name.value()
		if n == "" {
			ff.err = "Give the field a name."
			return nil
		}
		nr := fieldRow{name: n, orig: r.orig, secret: isSecret(), changed: true}
		switch {
		case !nr.secret:
			nr.value = []byte(plain.text.Value())
			secure.SecureZeroBytes(hidden.secret)
		case len(hidden.secret) > 0:
			nr.value = hidden.secret
		case r.secret && row >= 0 && n == r.name:
			nr.value, nr.changed = r.value, r.changed // kept as it was
		default:
			ff.err = "Type the secret value."
			return nil
		}
		if row >= 0 && r.secret && !bytes.Equal(nr.value, r.value) {
			secure.SecureZeroBytes(r.value)
		}
		if row >= 0 {
			in.rows[row] = nr
		} else {
			in.rows = append(in.rows, nr)
			in.row = len(in.rows) - 1
		}
		m.form = ff.back
		return nil
	}
	ff.focusInput(0)
	m.form = ff
	return nil
}

// drawForm draws the open form as a card over the app, base.
func (m *Model) drawForm(base string) string {
	th := m.th
	f := m.form
	w := min(76, m.width-4)
	inner := w - 6
	var blocks [][]string // each input's lines
	for i, in := range f.inputs {
		if !in.visible() {
			blocks = append(blocks, nil)
			continue
		}
		focused := i == f.focus
		label := th.dimmed().Render(" " + in.name())
		if focused {
			label = th.accented().Bold(true).Render(" " + in.name())
		}
		var body string
		switch in.kind {
		case inputText:
			in.text.SetWidth(inner - 6)
			body = in.text.View()
		case inputSecret:
			body = th.style().Render(strings.Repeat("•", min(utf8.RuneCount(in.secret), inner-8)))
			if focused {
				body += th.accented().Render("▌")
			}
			if in.weak {
				body += "\n" + lipgloss.NewStyle().Foreground(th.warn).Render("easy to guess: a longer one, or generated, is safer")
			}
		case inputNotes:
			in.area.SetWidth(inner - 5)
			in.area.SetHeight(max(min(m.height-26, 8), 3))
			body = in.area.View()
		case inputChoice:
			var opts []string
			for j, c := range in.choices {
				if j == in.choice {
					opts = append(opts, th.accented().Bold(true).Render("● "+c))
				} else {
					opts = append(opts, th.dimmed().Render("○ "+c))
				}
			}
			body = strings.Join(opts, "   ")
		case inputFields:
			var rows []string
			for j, r := range in.rows {
				value := string(r.value)
				if r.secret {
					value = "•••••••• (secret)"
				}
				row := fitTo(th.style().Render(r.name)+"  "+th.dimmed().Render(value), inner-8)
				if focused && j == in.row {
					row = lipgloss.NewStyle().Background(th.selBg).Render(row)
				}
				rows = append(rows, row)
			}
			if len(rows) == 0 {
				rows = []string{th.dimmed().Render("none")}
			}
			body = strings.Join(rows, "\n")
		}
		lines := append([]string{label}, strings.Split(th.field(focused, body), "\n")...)
		if focused {
			switch {
			case in.kind == inputFields:
				lines = append(lines, "   "+th.hints([2]string{"a", "add"}, [2]string{"↵", "edit"}, [2]string{"x", "remove"}))
			case in.kind == inputChoice:
				lines = append(lines, "   "+th.hints([2]string{"← →", "choose"}))
			case in.kind == inputNotes && m.opts.EditNotes != nil:
				lines = append(lines, "   "+th.hints([2]string{"ctrl+e", "edit in your $EDITOR"}))
			case in.hint != "":
				lines = append(lines, "   "+th.dimmed().Render(in.hint))
			}
		}
		blocks = append(blocks, lines)
	}
	// What doesn't fit is scrolled away, keeping the focused input shown.
	room := max(m.height-10, 4)
	var all []string
	focusTop := 0
	for i, b := range blocks {
		if b == nil {
			continue
		}
		if i == f.focus {
			focusTop = len(all)
		}
		all = append(all, b...)
	}
	if len(all) > room {
		top := min(max(focusTop-2, 0), len(all)-room)
		all = all[top : top+room]
	}
	lines := []string{th.accented().Bold(true).Render(ansi.Truncate(f.title, inner, "…")), th.lines().Render(strings.Repeat("─", inner))}
	lines = append(lines, all...)
	if f.err != "" {
		lines = append(lines, "", lipgloss.NewStyle().Foreground(th.bad).Width(inner).Render(f.err))
	}
	hint := th.hints([2]string{"tab", "next"}, [2]string{"ctrl+s", "save"}, [2]string{"esc", "cancel"})
	if f.saving {
		hint = th.dimmed().Render("Saving…")
	}
	lines = append(lines, "", hint)
	card := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(th.accent).Padding(0, 2).Width(w).
		Render(lipgloss.JoinVertical(lipgloss.Left, lines...))
	x := max((m.width-lipgloss.Width(card))/2, 0)
	y := max((m.height-lipgloss.Height(card))/2, 0)
	return lipgloss.NewCompositor(lipgloss.NewLayer(th.behind(base)), lipgloss.NewLayer(card).X(x).Y(y).Z(2)).Render()
}
