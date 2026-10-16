package tui

import (
	"errors"
	"strconv"

	tea "charm.land/bubbletea/v2"

	"github.com/bashhack/sesh/internal/secure"
)

// generatedLength is a generated password's length unless another is
// typed, as sesh generate's.
const generatedLength = 24

// generatedWords is a passphrase's number of words unless another is
// typed, as sesh generate --words suggests.
const generatedWords = 6

// generating is how a password is to be generated: length characters,
// with symbols or not; or, when words isn't 0, a passphrase of that many
// words, joined by separator, capitalized or not.
type generating struct {
	separator  string
	length     int
	words      int
	symbols    bool
	capitalize bool
}

// generateInputs are a form's inputs for how a password is generated:
// random characters (how many, and whether with symbols), or, where the
// app makes passphrases, words (how many, what goes between them, and
// whether each starts with a capital).
type generateInputs struct {
	style                *input // nil where only characters are made
	length, chars        *input
	words, sep, capitals *input
}

func (m *Model) generateInputs() generateInputs {
	length := m.textInput("length", strconv.Itoa(generatedLength))
	length.hint = "how many characters; some sites take no more than 16 or so"
	chars := &input{kind: inputChoice, label: "characters", choices: []string{"letters, digits and symbols", "letters and digits only"},
		hint: "for a site that refuses symbols"}
	g := generateInputs{length: length, chars: chars}
	if m.opts.Passphrase == nil {
		return g
	}
	g.style = &input{kind: inputChoice, label: "made of", choices: []string{"random characters", "words (a passphrase)"},
		hint: "words are easier to type and remember; 6 are about 77 bits"}
	g.words = m.textInput("words", strconv.Itoa(generatedWords))
	g.words.hint = "how many, from 3 to 20, from the EFF's long word list"
	g.sep = m.textInput("between words", "-")
	g.sep.hint = "what goes between the words; a space is fine, or nothing"
	g.capitals = &input{kind: inputChoice, label: "capitals", choices: []string{"none", "each word's first letter"},
		hint: "for a site that wants a capital letter"}
	return g
}

// inputs are the inputs, in a form's order.
func (g generateInputs) inputs() []*input {
	if g.style == nil {
		return []*input{g.length, g.chars}
	}
	return []*input{g.style, g.length, g.chars, g.words, g.sep, g.capitals}
}

// shownWhen shows the inputs while shown says to, each of those for
// characters or for words only while that's what's made.
func (g generateInputs) shownWhen(shown func() bool) {
	if shown == nil {
		shown = func() bool { return true }
	}
	if g.style == nil {
		g.length.shown, g.chars.shown = shown, shown
		return
	}
	g.style.shown = shown
	chars := func() bool { return shown() && g.style.choice == 0 }
	words := func() bool { return shown() && g.style.choice == 1 }
	g.length.shown, g.chars.shown = chars, chars
	g.words.shown, g.sep.shown, g.capitals.shown = words, words, words
}

// read is how the inputs say to generate, or what's wrong with them.
func (g generateInputs) read() (generating, string) {
	if g.style != nil && g.style.choice == 1 {
		n, err := strconv.Atoi(g.words.value())
		if err != nil || n < 1 {
			return generating{}, "The words are a whole number, such as 6."
		}
		// Not trimmed: a space between the words is one to keep.
		return generating{words: n, separator: g.sep.text.Value(), capitalize: g.capitals.choice == 1}, ""
	}
	n, err := strconv.Atoi(g.length.value())
	if err != nil || n < 1 {
		return generating{}, "The length is a whole number of characters, such as 24."
	}
	return generating{length: n, symbols: g.chars.choice == 0}, ""
}

// make generates as g says, with opts' generators.
func (g generating) make(opts *Options) ([]byte, error) {
	if g.words > 0 {
		if opts.Passphrase == nil {
			return nil, errors.New("sesh ui can't make a passphrase here")
		}
		return opts.Passphrase(g.words, g.separator, g.capitalize)
	}
	if opts.Generate == nil {
		return nil, errors.New("sesh ui can't generate a password here")
	}
	return opts.Generate(g.length, g.symbols)
}

// what is what g makes, said: "a new password of 24 characters".
func (g generating) what() string {
	if g.words > 0 {
		return "a new passphrase of " + strconv.Itoa(g.words) + " words"
	}
	return "a new password of " + strconv.Itoa(g.length) + " characters"
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
	gen.shownWhen(nil)
	f := &form{title: "Generate a password", inputs: gen.inputs(), row: -1, enterDone: "copy it",
		note: "It's copied, not stored: add an entry with it, or paste it where it's needed."}
	f.submit = func() tea.Cmd {
		g, bad := gen.read()
		if bad != "" {
			f.err = bad
			return nil
		}
		f.saving, f.err, f.working = true, "", "Generating…"
		opts, epoch := m.opts, m.epoch
		return func() tea.Msg {
			pw, err := g.make(&opts)
			if err != nil {
				return generatedMsg{err: err, epoch: epoch}
			}
			defer secure.SecureZeroBytes(pw)
			if err := opts.Copy(string(pw)); err != nil {
				return generatedMsg{err: err, epoch: epoch}
			}
			what := g.what()
			switch {
			case opts.IsWeak == nil || !opts.IsWeak(pw):
			case g.words > 0:
				what += " (easy to guess: 5 words or more is safer)"
			default:
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
