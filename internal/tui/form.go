package tui

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"charm.land/bubbles/v2/textarea"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
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
	shown    func() bool    // nil: always shown
	load     func() tea.Cmd // reads the secret an empty input stands for, to show it
	then     func() tea.Cmd // what to do once load has read it, instead of showing it
	named    func() string  // its label, when that depends on other inputs
	label    string
	hint     string
	choices  []string
	secret   []byte
	loaded   []byte // the secret load read, to tell whether it was changed
	rows     []fieldRow
	of       vault.Key // the entry whose fields these are; zero for one being added
	offers   []string  // what a line of text can be completed to
	text     textinput.Model
	area     textarea.Model
	kind     inputKind
	choice   int
	row      int
	pick     int  // the offer chosen with the arrows, from 1; 0: none
	many     bool // the text is a list, separated by commas
	reveal   bool // the secret typed is shown, while the input has the focus
	readOnly bool // a secret shown, not typed: the one an entry has
	loading  bool
	rated    bool // a password, whose strength is said
	weak     bool // the secret typed is easy to guess
	accepted bool // weak, and to be used anyway: typing again asks again
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

// maxOffers is how many of an input's offers are listed under it.
const maxOffers = 5

// piece is what the offers are matched against: the text, or the last of
// a list's items.
func (in *input) piece() (before, piece string) {
	v := in.text.Value()
	if !in.many {
		return "", strings.TrimSpace(v)
	}
	i := strings.LastIndex(v, ",") + 1
	return v[:i], strings.TrimSpace(v[i:])
}

// matches is the offers with what's typed anywhere in them, whatever its
// case, those starting with it first; all of them when nothing is typed.
// One already typed in full, or already in the list, isn't offered.
func (in *input) matches() []string {
	if in.kind != inputText {
		return nil
	}
	before, piece := in.piece()
	have := map[string]bool{piece: true}
	for item := range strings.SplitSeq(before, ",") {
		have[strings.TrimSpace(item)] = true
	}
	lower := strings.ToLower(piece)
	var starts, within []string
	for _, o := range in.offers {
		switch at := strings.Index(strings.ToLower(o), lower); {
		case have[o] || at < 0:
		case at == 0:
			starts = append(starts, o)
		default:
			within = append(within, o)
		}
	}
	starts = append(starts, within...)
	return starts[:min(len(starts), maxOffers)]
}

// take puts the offer picked in place of what's typed of it.
func (in *input) take() bool {
	found := in.matches()
	if in.pick < 1 || in.pick > len(found) {
		return false
	}
	before, _ := in.piece()
	if before != "" {
		before += " "
	}
	in.text.SetValue(before + found[in.pick-1])
	in.text.CursorEnd()
	in.pick = 0
	return true
}

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
	submit func() tea.Cmd // checks the inputs and saves
	cancel func()         // what Esc closing it does, besides; nil: nothing
	// lost is what to say of it when a lock throws it away; nil: nothing.
	lost  func() string
	back  *form // the form a field's form returns to
	title string
	err   string
	// enterDone is what Enter on the last input does, which submits the
	// form; "" when Enter only moves on, and Ctrl-S saves.
	enterDone string
	// working says the form is being submitted, instead of "Saving…".
	working string
	// shown is drawn above the inputs, unwrapped where it fits (a key to
	// write down), and note under it.
	shown, note string
	// quitting is said when Ctrl-C while it's saving waits for the save
	// to quit; "" quits at once.
	quitting string
	inputs   []*input
	focus    int
	row      int // the field a field's form edits; -1 for a new one
	saving   bool
	changed  bool // something was typed or chosen
	leaving  bool // Esc was pressed once on a changed form
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
		in.reveal = false
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

// last says whether the focus is on the form's last input shown.
func (f *form) last() bool {
	for i := f.focus + 1; i < len(f.inputs); i++ {
		if f.inputs[i].visible() {
			return false
		}
	}
	return true
}

// wipe overwrites the secrets the form, and the forms it returns to, hold.
func (f *form) wipe() {
	for ; f != nil; f = f.back {
		f.wipeOwn()
	}
}

// wipeOwn overwrites the secrets in the form's own inputs.
func (f *form) wipeOwn() {
	for _, in := range f.inputs {
		secure.SecureZeroBytes(in.secret)
		secure.SecureZeroBytes(in.loaded)
		for _, r := range in.rows {
			if r.secret {
				secure.SecureZeroBytes(r.value)
			}
		}
	}
}

// fieldValueMsg is a secret field's value, read to be shown in its input.
type fieldValueMsg struct {
	err   error
	in    *input
	value []byte
	epoch int
}

// gotFieldValue shows the value read in its input, when nothing was typed
// there meanwhile.
func (m *Model) gotFieldValue(msg *fieldValueMsg) tea.Cmd {
	in := msg.in
	in.loading = false
	switch {
	case msg.epoch != m.epoch || m.form == nil || !slices.Contains(m.form.inputs, in) || len(in.secret) > 0:
		secure.SecureZeroBytes(msg.value)
	case errors.Is(msg.err, ErrLocked):
		m.form.wipe()
		m.form = nil
		return m.lock(lockedReason(msg.err))
	case msg.err != nil:
		m.form.err = "Couldn't read its value: " + msg.err.Error()
	default:
		in.secret, in.loaded, in.hint = msg.value, bytes.Clone(msg.value), ""
		if then := in.then; then != nil {
			in.then = nil
			return then()
		}
		in.reveal = true
	}
	in.then = nil
	return nil
}

// editorMsg is notes back from the editor.
type editorMsg struct {
	err   error
	notes []byte
}

// editor runs the user's editor on notes with the terminal handed to it.
type editor struct {
	edit  func([]byte) ([]byte, error)
	keep  func() // tells the vault it's in use, every so often while editing
	err   error
	notes []byte
	every time.Duration
}

func (e *editor) Run() error {
	// The app's loop waits for the editor, so it can't keep the agent from
	// locking for being idle meanwhile; this does.
	done := make(chan struct{})
	var wg sync.WaitGroup
	defer wg.Wait()
	defer close(done)
	wg.Go(func() {
		t := time.NewTicker(e.every)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				e.keep()
			}
		}
	})
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
		switch {
		case msg.String() != "ctrl+c":
		case f.quitting != "":
			m.quitAfter = true
			f.working = f.quitting
		default:
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
			f.leaving, f.err = true, "You have unsaved changes. Press Esc again to discard them."
			return nil
		}
		// A field's form holds only what was typed into it: the field
		// stays in its entry's form as it was.
		f.wipeOwn()
		m.form = f.back
		if f.cancel != nil {
			f.cancel()
		}
		return nil
	case "tab":
		f.move(1)
		return nil
	case "shift+tab":
		f.move(-1)
		return nil
	case "ctrl+s":
		return f.submit()
	case "ctrl+r":
		switch {
		case in.kind != inputSecret || in.loading:
		case len(in.secret) == 0 && in.load != nil:
			// The value it has isn't held until it's asked for.
			in.loading = true
			return in.load()
		default:
			in.reveal = !in.reveal
		}
		return nil
	case "up", "down":
		if in.kind == inputText {
			step := map[string]int{"up": -1, "down": 1}[msg.String()]
			in.pick = max(min(in.pick+step, len(in.matches())), 0)
			return nil
		}
	case "enter":
		if in.kind == inputText && in.take() {
			f.changed = true
			return nil
		}
		switch {
		case in.kind == inputNotes:
		case in.kind == inputFields:
			return m.openFieldForm(in, in.row)
		case len(f.inputs) == 1:
			// A one-line form is done when its line is.
			return f.submit()
		case f.enterDone != "" && f.last():
			return f.submit()
		default:
			f.move(1)
			return nil
		}
	}
	f.err = ""
	was := f.changed
	f.changed = true
	switch in.kind {
	case inputText:
		var cmd tea.Cmd
		in.text, cmd = in.text.Update(msg)
		in.pick = 0
		return cmd
	case inputNotes:
		if msg.String() == "ctrl+e" && m.opts.EditNotes != nil {
			g, every := m.v, time.Minute
			if m.opts.IdleTimeout > 0 {
				every = min(every, m.opts.IdleTimeout/2)
			}
			keep := func() { g.run(func(v Vault, _ func() bool) tea.Msg { _ = v.KeepAlive(); return nil }) } //nolint:errcheck // a lock shows on return
			e := &editor{edit: m.opts.EditNotes, keep: keep, every: max(every, time.Second), notes: []byte(in.area.Value())}
			m.inEditor = true
			return tea.Exec(e, func(err error) tea.Msg { return editorMsg{notes: e.notes, err: e.err} })
		}
		var cmd tea.Cmd
		in.area, cmd = in.area.Update(msg)
		return cmd
	case inputSecret:
		if in.readOnly {
			f.changed = was
			return nil
		}
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
		default:
			f.changed = was
		}
	case inputFields:
		switch msg.String() {
		case "up", "k":
			in.row = max(in.row-1, 0)
			f.changed = was
		case "down", "j":
			in.row = min(in.row+1, max(len(in.rows)-1, 0))
			f.changed = was
		case "a", "n":
			f.changed = was // a field added in its form is the change
			return m.openFieldForm(in, -1)
		case "x", "delete":
			if in.row < len(in.rows) {
				if in.rows[in.row].secret {
					secure.SecureZeroBytes(in.rows[in.row].value)
				}
				in.rows = append(in.rows[:in.row], in.rows[in.row+1:]...)
				in.row = max(min(in.row, len(in.rows)-1), 0)
			}
		default:
			f.changed = was
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
	if m.width < minWidth || m.height < minHeight {
		// The form isn't on screen: nothing is pasted into it unseen.
		return nil
	}
	in := f.inputs[f.focus]
	if in.readOnly {
		return nil
	}
	f.changed, f.leaving, f.err = true, false, ""
	switch in.kind {
	case inputText:
		var cmd tea.Cmd
		in.text, cmd = in.text.Update(tea.PasteMsg{Content: trimNewlines(text)})
		in.pick = 0
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
	in.accepted = false
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
		if of, field, epoch := in.of, r.orig, m.epoch; field != "" {
			hidden.hint = "typing replaces it"
			hidden.load = func() tea.Cmd {
				return m.read(func(v Vault, closed func() bool) tea.Msg {
					value, err := v.Field(of, field)
					if closed() {
						secure.SecureZeroBytes(value)
						return nil
					}
					return fieldValueMsg{in: hidden, value: value, err: err, epoch: epoch}
				})
			}
		}
	}
	if r.secret && r.value != nil {
		hidden.secret = bytes.Clone(r.value)
	}
	title := "New field"
	if row >= 0 {
		title = "Field " + r.name
	}
	ff := &form{title: title, back: m.form, row: row, inputs: []*input{name, secretChoice, plain, hidden}}
	ff.submit = func() tea.Cmd {
		n := name.value()
		if n == "" {
			ff.err = "Give the field a name."
			return nil
		}
		for j, o := range in.rows {
			if j != row && strings.EqualFold(o.name, n) {
				ff.err = "Another field already has that name (names can't differ only in case)."
				return nil
			}
		}
		nr := fieldRow{name: n, orig: r.orig, secret: isSecret(), changed: true}
		kept := false
		switch {
		case !nr.secret && r.secret && plain.text.Value() == "":
			ff.err = "Type a new value to make it plain; the current one stays secret."
			return nil
		case !nr.secret:
			nr.value = []byte(plain.text.Value())
			secure.SecureZeroBytes(hidden.secret)
		case hidden.loaded != nil && bytes.Equal(hidden.secret, hidden.loaded) && n == r.name:
			nr.value, nr.changed, kept = r.value, r.changed, true // read to be shown, and left as it was
			secure.SecureZeroBytes(hidden.secret)
		case len(hidden.secret) > 0:
			nr.value = hidden.secret
		case r.secret && row >= 0 && n == r.name:
			nr.value, nr.changed, kept = r.value, r.changed, true
		case hidden.load != nil && !hidden.loading:
			// Renamed, it's set again under its new name: its value is read
			// first, and the field saved once it has been.
			hidden.loading, hidden.then = true, ff.submit
			return hidden.load()
		case hidden.loading:
			// Ctrl-R's read is still on its way: the field is saved once it lands.
			hidden.then = ff.submit
			return nil
		default:
			ff.err = "Type the secret value."
			return nil
		}
		if row >= 0 && !kept && nr.name == r.name && nr.secret == r.secret && r.value != nil && bytes.Equal(nr.value, r.value) {
			// Saved as it was: no change.
			if nr.secret {
				secure.SecureZeroBytes(nr.value)
			}
			nr.value, nr.changed, kept = r.value, r.changed, true
		}
		secure.SecureZeroBytes(hidden.loaded)
		if row >= 0 && r.secret && !kept {
			secure.SecureZeroBytes(r.value)
		}
		ff.back.changed = ff.back.changed || nr.changed
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
			if in.reveal {
				// Its end is kept in view: that's where it's being typed.
				shown := strings.ReplaceAll(wrapText(string(in.secret), 1<<20), "\n", "␤")
				body = th.style().Render(ansi.TruncateLeft(shown, max(ansi.StringWidth(shown)-(inner-8), 0), ""))
			}
			if len(in.secret) == 0 && in.load != nil {
				// Its value, unread: dots, as the preview shows a secret.
				body = th.dimmed().Render("••••••••")
			}
			if focused && !in.readOnly {
				body += th.accented().Render("▌")
			}
			if in.weak {
				body += "\n" + lipgloss.NewStyle().Foreground(th.warn).Render("easy to guess; a longer or generated one is safer")
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
				rows = []string{th.dimmed().Render("none yet")}
			}
			body = strings.Join(rows, "\n")
		}
		lines := append([]string{label}, strings.Split(th.field(focused, body), "\n")...)
		if focused && in.kind == inputText {
			for j, o := range in.matches() {
				row := "   " + fitTo(th.dimmed().Render(o), inner-8)
				if j+1 == in.pick {
					row = "   " + lipgloss.NewStyle().Background(th.selBg).Render(fitTo(th.style().Render(o), inner-8))
				}
				lines = append(lines, row)
			}
		}
		if focused {
			switch {
			case in.kind == inputText && len(in.matches()) > 0:
				lines = append(lines, "   "+th.hints([2]string{"↓", "pick an existing one"}, [2]string{"↵", "use it"}))
			case in.kind == inputFields:
				lines = append(lines, "   "+th.hints([2]string{"a", "add"}, [2]string{"↵", "edit"}, [2]string{"x", "remove"}))
			case in.kind == inputChoice:
				lines = append(lines, "   "+th.hints([2]string{"← →", "choose"}))
			case in.kind == inputNotes && m.opts.EditNotes != nil:
				lines = append(lines, "   "+th.hints([2]string{"ctrl+e", "edit in your $EDITOR"}))
			case in.kind == inputSecret:
				word := "show what you typed"
				switch {
				case in.reveal:
					word = "hide it"
				case in.loading:
					word = "reading it…"
				case len(in.secret) == 0 && in.load != nil:
					word = "show it"
				}
				line := "   " + th.hints([2]string{"ctrl+r", word})
				switch hint := th.dimmed().Render(in.hint); {
				case in.hint == "":
					lines = append(lines, line)
				case lipgloss.Width(line)+3+lipgloss.Width(hint) <= inner:
					lines = append(lines, line+"   "+hint)
				default:
					lines = append(lines, line, "   "+hint)
				}
			}
			if in.hint != "" && in.kind != inputSecret && len(in.matches()) == 0 {
				lines = append(lines, "   "+th.dimmed().Render(in.hint))
			}
		}
		blocks = append(blocks, lines)
	}
	var errLines []string
	if f.err != "" {
		// At most three lines of it, so the card fits the window.
		wrapped := strings.Split(lipgloss.NewStyle().Width(inner).Render(f.err), "\n")
		if len(wrapped) > 3 {
			wrapped = append(wrapped[:2], ansi.Truncate(wrapped[2], inner-1, "")+"…")
		}
		errLines = append([]string{""}, wrapped...)
		for i, l := range errLines {
			errLines[i] = lipgloss.NewStyle().Foreground(th.bad).Render(l)
		}
	}
	// What doesn't fit is scrolled away, keeping the focused input, or the
	// field chosen in it, shown.
	// A note's end is cut to leave the inputs room; what's shown isn't.
	var head []string
	if f.shown != "" {
		shown := f.shown
		if lipgloss.Width(shown)+4 <= inner {
			shown = "    " + shown
		}
		head = append(head, "", th.accented().Bold(true).Width(inner).Render(shown))
	}
	if f.note != "" {
		note := strings.Split(th.style().Width(inner).Render(f.note), "\n")
		if most := m.height - 10 - len(errLines) - len(head) - 3; len(note) > most {
			note = note[:max(most-1, 0)]
			if most > 0 {
				note = append(note, th.dimmed().Render("…"))
			}
		}
		if len(note) > 0 {
			head = append(head, "")
			head = append(head, note...)
		}
	}
	if len(head) > 0 {
		head = append(head, "")
	}
	room := max(m.height-10-len(errLines)-len(head), 1)
	var all []string
	focusTop := 0
	for i, b := range blocks {
		if b == nil {
			continue
		}
		if i == f.focus {
			focusTop = len(all)
			if in := f.inputs[i]; in.kind == inputFields && len(in.rows) > 0 {
				focusTop += 1 + in.row // its label, then the rows above
			}
		}
		all = append(all, b...)
	}
	if len(all) > room {
		top := min(max(focusTop-2, 0), len(all)-room)
		all = all[top : top+room]
	}
	lines := []string{th.accented().Bold(true).Render(ansi.Truncate(f.title, inner, "…")), th.lines().Render(strings.Repeat("─", inner))}
	lines = append(lines, head...)
	lines = append(lines, all...)
	lines = append(lines, errLines...)
	hint := th.hints([2]string{"tab", "next"}, [2]string{"ctrl+s", "save"}, [2]string{"esc", "cancel"})
	switch {
	case f.saving && f.working != "":
		hint = th.dimmed().Render(f.working)
	case f.saving:
		hint = th.dimmed().Render("Saving…")
	case len(f.inputs) == 1:
		hint = th.hints([2]string{"↵", "done"}, [2]string{"esc", "cancel"})
	case f.enterDone != "" && f.last():
		hint = th.hints([2]string{"↵", f.enterDone}, [2]string{"shift+tab", "back"}, [2]string{"esc", "cancel"})
	case f.enterDone != "":
		hint = th.hints([2]string{"↵", "next"}, [2]string{"esc", "cancel"})
	}
	lines = append(lines, "", hint)
	card := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(th.accent).Padding(0, 2).Width(w).
		Render(lipgloss.JoinVertical(lipgloss.Left, lines...))
	x := max((m.width-lipgloss.Width(card))/2, 0)
	y := max((m.height-lipgloss.Height(card))/2, 0)
	return lipgloss.NewCompositor(lipgloss.NewLayer(th.behind(base)), lipgloss.NewLayer(card).X(x).Y(y).Z(2)).Render()
}
