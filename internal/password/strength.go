package password

import "github.com/trustelem/zxcvbn"

// weakScore is the highest zxcvbn score (0–4) that counts as weak: 2 or
// less means zxcvbn estimates a cracking program needs fewer than about
// 10^8 guesses.
const weakScore = 2

// IsWeak reports whether pw is easy to guess, by zxcvbn's estimate. hints
// are words the password shouldn't lean on, such as the entry's service
// name and username. zxcvbn works on strings, so it makes copies of pw that
// can't be zeroed; they live until the process exits or the memory is reused.
func IsWeak(pw []byte, hints ...string) bool {
	return zxcvbn.PasswordStrength(string(pw), hints).Score <= weakScore
}
