package tui

import (
	"strconv"

	tea "charm.land/bubbletea/v2"

	"github.com/bashhack/sesh/internal/secure"
)

// generatedLength is a generated password's length unless another is
// typed, as sesh generate's.
const generatedLength = 24

// generating is how a password is to be generated.
type generating struct {
	length  int
	symbols bool
}

// generateInputs are a form's inputs for how a password is generated:
// its length, and whether it has symbols.
type generateInputs struct{ length, chars *input }

func (m *Model) generateInputs() generateInputs {
	length := m.textInput("length", strconv.Itoa(generatedLength))
	length.hint = "how many characters; some sites take no more than 16 or so"
	chars := &input{kind: inputChoice, label: "characters", choices: []string{"letters, digits and symbols", "letters and digits only"},
		hint: "for a site that refuses symbols"}
	return generateInputs{length: length, chars: chars}
}

// read is how the inputs say to generate, or what's wrong with them.
func (g generateInputs) read() (generating, string) {
	n, err := strconv.Atoi(g.length.value())
	if err != nil || n < 1 {
		return generating{}, "The length is a whole number of characters, such as 24."
	}
	return generating{length: n, symbols: g.chars.choice == 0}, ""
}

// generatedMsg is a password generated and copied, or why it wasn't.
type generatedMsg struct {
	err   error
	what  string
	epoch int
}

// openGenerator opens the form that makes a password and copies it,
// storing it nowhere, as sesh generate --copy does.
func (m *Model) openGenerator() tea.Cmd {
	if m.opts.Generate == nil {
		m.sayBad("sesh ui can't generate a password here.")
		return nil
	}
	gen := m.generateInputs()
	f := &form{title: "Generate a password", inputs: []*input{gen.length, gen.chars}, row: -1, enterDone: "copy it",
		note: "It's copied, not stored: add an entry with it, or paste it where it's needed."}
	f.submit = func() tea.Cmd {
		g, bad := gen.read()
		if bad != "" {
			f.err = bad
			return nil
		}
		f.saving, f.err, f.working = true, "", "Generating…"
		generate, opts, epoch := m.opts.Generate, m.opts, m.epoch
		return func() tea.Msg {
			pw, err := generate(g.length, g.symbols)
			if err != nil {
				return generatedMsg{err: err, epoch: epoch}
			}
			defer secure.SecureZeroBytes(pw)
			if err := opts.Copy(string(pw)); err != nil {
				return generatedMsg{err: err, epoch: epoch}
			}
			what := "a new password of " + strconv.Itoa(g.length) + " characters"
			if opts.IsWeak != nil && opts.IsWeak(pw) {
				what += " (easy to guess: 12 or more is safer)"
			}
			what = copied(what, opts.ClearAfter)
			return generatedMsg{what: what, epoch: epoch}
		}
	}
	f.focusInput(0)
	m.form = f
	return nil
}

// generated closes the generator's form once the password is copied, or
// says why it wasn't.
func (m *Model) generated(msg *generatedMsg) tea.Cmd {
	if msg.epoch != m.epoch || m.form == nil {
		return nil
	}
	f := m.form
	f.saving, f.working = false, ""
	if msg.err != nil {
		f.err = "Not generated: " + msg.err.Error()
		return nil
	}
	m.form = nil
	m.say(msg.what)
	if m.opts.ClearAfter > 0 {
		m.clipUntil = m.opts.Now().Add(m.opts.ClearAfter)
	}
	return nil
}
