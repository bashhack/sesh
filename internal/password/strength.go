package password

import (
	"strings"

	"github.com/trustelem/zxcvbn"
)

// weakScore is the highest zxcvbn score (0–4) that counts as weak: 2 or
// less means zxcvbn estimates a cracking program needs fewer than about
// 10^8 guesses.
const weakScore = 2

// maxRated is how many characters of a password are rated. zxcvbn slows
// down sharply with length (seconds at a few hundred characters), and a
// password whose first 64 characters are hard to guess is hard to guess.
const maxRated = 64

// IsWeak reports whether pw is easy to guess, by zxcvbn's estimate of its
// first maxRated characters. hints are names the password shouldn't lean
// on, such as the entry's service name and username; one of several words
// also counts word by word and run together ("My Bank" as "mybank"). zxcvbn works on strings, so it makes copies of pw that
// can't be zeroed; they live until the process exits or the memory is reused.
func IsWeak(pw []byte, hints ...string) bool {
	rated := []rune(string(pw))
	if len(rated) > maxRated {
		rated = rated[:maxRated]
	}
	words := make([]string, 0, len(hints))
	for _, h := range hints {
		if h == "" {
			continue
		}
		words = append(words, h)
		if f := strings.Fields(h); len(f) > 1 {
			words = append(words, f...)
			words = append(words, strings.Join(f, ""))
		}
	}
	return zxcvbn.PasswordStrength(string(rated), words).Score <= weakScore
}
