package password

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"fmt"
	"math/big"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bashhack/sesh/internal/secure"
)

// effLargeWordlist is the EFF's long word list for passphrases, as
// published at https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
// (sha256 addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e):
// 7776 words, each after its five dice rolls and a tab. By the Electronic
// Frontier Foundation, under the Creative Commons Attribution 4.0
// International License; see https://www.eff.org/dice.
//
//go:embed eff_large_wordlist.txt
var effLargeWordlist string

// wordlist is the word list's words, in its order.
var wordlist = func() []string {
	lines := strings.Split(strings.TrimSpace(effLargeWordlist), "\n")
	out := make([]string, len(lines))
	for i, line := range lines {
		_, w, _ := strings.Cut(line, "\t")
		out[i] = w
	}
	return out
}()

// longestWord is the list's longest word's length.
const longestWord = 9

// The fewest and most words a passphrase has.
const (
	MinPassphraseWords = 3
	MaxPassphraseWords = 20
	// MaxSeparatorLength is the longest separator taken.
	MaxSeparatorLength = 8
)

// PassphraseOptions says how a passphrase is made: how many words, what
// goes between them, and whether each starts with a capital.
type PassphraseOptions struct {
	Separator  string
	Words      int
	Capitalize bool
}

// DefaultPassphraseOptions are six words joined by hyphens: about 77 bits.
func DefaultPassphraseOptions() PassphraseOptions {
	return PassphraseOptions{Words: 6, Separator: "-"}
}

// Check reports why GeneratePassphrase would refuse these options, if it
// would.
func (o PassphraseOptions) Check() error {
	switch {
	case o.Words < MinPassphraseWords || o.Words > MaxPassphraseWords:
		return fmt.Errorf("a passphrase has %d to %d words, not %d", MinPassphraseWords, MaxPassphraseWords, o.Words)
	case utf8.RuneCountInString(o.Separator) > MaxSeparatorLength:
		return fmt.Errorf("the separator %q is longer than %d characters", o.Separator, MaxSeparatorLength)
	case strings.IndexFunc(o.Separator, unicode.IsControl) >= 0:
		return fmt.Errorf("the separator %q has a control character", o.Separator)
	}
	return nil
}

// GeneratePassphrase makes a passphrase of words chosen at random from the
// EFF's long list, each about 12.9 bits. The result is secret: the caller
// zeroes it once done.
func GeneratePassphrase(o PassphraseOptions) ([]byte, error) {
	if err := o.Check(); err != nil {
		return nil, err
	}
	// Room for the longest words up front, so the buffer never grows and
	// leaves a copy behind.
	var b bytes.Buffer
	b.Grow(o.Words*longestWord + (o.Words-1)*len(o.Separator))
	n := big.NewInt(int64(len(wordlist)))
	for i := range o.Words {
		idx, err := rand.Int(rand.Reader, n)
		if err != nil {
			secure.SecureZeroBytes(b.Bytes())
			return nil, fmt.Errorf("choose a word: %w", err)
		}
		if i > 0 {
			b.WriteString(o.Separator)
		}
		w := wordlist[idx.Int64()]
		if o.Capitalize {
			b.WriteByte(w[0] - 'a' + 'A')
			w = w[1:]
		}
		b.WriteString(w)
	}
	// Copied out at its length, so no spare capacity holds a copy.
	out := bytes.Clone(b.Bytes())
	secure.SecureZeroBytes(b.Bytes())
	return out, nil
}
