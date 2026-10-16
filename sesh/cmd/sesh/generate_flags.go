package main

import (
	"errors"
	"flag"
	"fmt"

	"github.com/bashhack/sesh/internal/password"
)

// genFlags shape a generated password: random characters (--length,
// --no-symbols), or a passphrase of words (--words, --separator,
// --capitalize).
type genFlags struct {
	separator         string
	length, words     int
	noSymbols, capped bool
	// passphrase says --words was given: words, not characters.
	passphrase bool
}

// register defines the flags on fs.
func (g *genFlags) register(fs *flag.FlagSet) {
	fs.IntVar(&g.length, "length", 24, "How many characters")
	fs.BoolVar(&g.noSymbols, "no-symbols", false, "Letters and digits only")
	fs.IntVar(&g.words, "words", 6, "A passphrase: how many words")
	fs.StringVar(&g.separator, "separator", "-", "A passphrase: what goes between its words")
	fs.BoolVar(&g.capped, "capitalize", false, "A passphrase: each word starts with a capital")
}

// parsed takes in which of the flags were given (set), once parsed:
// generating says --generate was too, or it's sesh generate. What doesn't
// go together is an error.
func (g *genFlags) parsed(set map[string]bool, generating bool) error {
	chars := set["length"] || set["no-symbols"]
	words := set["words"] || set["separator"] || set["capitalize"]
	switch {
	case (chars || words) && !generating:
		return errors.New("--length, --no-symbols, --words, --separator and --capitalize shape a generated password: add --generate")
	case chars && words:
		return errors.New("--length and --no-symbols make random characters, --words a passphrase: choose one")
	case words && !set["words"]:
		return errors.New("--separator and --capitalize shape a passphrase: add --words N (6 is a good number)")
	}
	g.passphrase = set["words"]
	return nil
}

// check says what's wrong with the values given, before anything is
// unlocked.
func (g *genFlags) check() error {
	if g.passphrase {
		if err := g.wordOptions().Check(); err != nil {
			return fmt.Errorf("--words: %w", err)
		}
		return nil
	}
	if err := g.charOptions().Check(); err != nil {
		return fmt.Errorf("--length: %w", err)
	}
	return nil
}

// generate makes the password; the caller zeroes it.
func (g *genFlags) generate() ([]byte, error) {
	if g.passphrase {
		return password.GeneratePassphrase(g.wordOptions())
	}
	return password.GeneratePassword(g.charOptions())
}

// noun is what's generated: "password" or "passphrase".
func (g *genFlags) noun() string {
	if g.passphrase {
		return "passphrase"
	}
	return "password"
}

// stronger says how to generate a stronger one.
func (g *genFlags) stronger() string {
	if g.passphrase {
		return "use --words 5 or more"
	}
	return "use --length 12 or more"
}

func (g *genFlags) charOptions() password.GenerateOptions {
	o := password.DefaultGenerateOptions()
	o.Length, o.Symbols = g.length, !g.noSymbols
	return o
}

func (g *genFlags) wordOptions() password.PassphraseOptions {
	return password.PassphraseOptions{Words: g.words, Separator: g.separator, Capitalize: g.capped}
}
