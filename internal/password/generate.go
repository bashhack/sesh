package password

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/bashhack/sesh/internal/secure"
)

const (
	lowerChars  = "abcdefghijklmnopqrstuvwxyz"
	upperChars  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitChars  = "0123456789"
	symbolChars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
)

// GenerateOptions controls password generation.
type GenerateOptions struct {
	Length    int  // Password length (default 24)
	Uppercase bool // Include uppercase letters (default true)
	Lowercase bool // Include lowercase letters (default true)
	Digits    bool // Include digits (default true)
	Symbols   bool // Include symbols (default true)
}

// DefaultGenerateOptions returns sensible defaults for password generation.
func DefaultGenerateOptions() GenerateOptions {
	return GenerateOptions{
		Length:    24,
		Uppercase: true,
		Lowercase: true,
		Digits:    true,
		Symbols:   true,
	}
}

// MaxGenerateLength is the longest password GeneratePassword makes.
const MaxGenerateLength = 1024

// Check reports why GeneratePassword would refuse these options, if it
// would.
func (o GenerateOptions) Check() error {
	switch {
	case o.Length < 1:
		return fmt.Errorf("password length must be at least 1")
	case o.Length > MaxGenerateLength:
		return fmt.Errorf("password length %d is more than the %d sesh makes", o.Length, MaxGenerateLength)
	case buildCharset(o) == "":
		return fmt.Errorf("at least one character set must be enabled")
	}
	if required := requiredChars(o); o.Length < len(required) {
		return fmt.Errorf("password length %d is too short for %d required character sets", o.Length, len(required))
	}
	return nil
}

// GeneratePassword creates a cryptographically random password with the given
// options. The returned slice holds plaintext secret material; the caller is
// responsible for zeroing it (e.g. secure.SecureZeroBytes) once done.
func GeneratePassword(opts GenerateOptions) ([]byte, error) {
	if err := opts.Check(); err != nil {
		return nil, err
	}
	charset := buildCharset(opts)
	required := requiredChars(opts)

	pw := make([]byte, opts.Length)

	// Place one character from each required set first.
	for i, req := range required {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(req))))
		if err != nil {
			secure.SecureZeroBytes(pw)
			return nil, fmt.Errorf("generate random char: %w", err)
		}
		pw[i] = req[idx.Int64()]
	}

	// Fill the remaining positions from the full charset.
	for i := len(required); i < opts.Length; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			secure.SecureZeroBytes(pw)
			return nil, fmt.Errorf("generate random byte: %w", err)
		}
		pw[i] = charset[idx.Int64()]
	}

	// Shuffle to avoid required chars always being at the start.
	for i := len(pw) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			secure.SecureZeroBytes(pw)
			return nil, fmt.Errorf("shuffle: %w", err)
		}
		pw[i], pw[j.Int64()] = pw[j.Int64()], pw[i]
	}

	return pw, nil
}

func buildCharset(opts GenerateOptions) string {
	var charset string
	if opts.Lowercase {
		charset += lowerChars
	}
	if opts.Uppercase {
		charset += upperChars
	}
	if opts.Digits {
		charset += digitChars
	}
	if opts.Symbols {
		charset += symbolChars
	}
	return charset
}

func requiredChars(opts GenerateOptions) []string {
	var required []string
	if opts.Lowercase {
		required = append(required, lowerChars)
	}
	if opts.Uppercase {
		required = append(required, upperChars)
	}
	if opts.Digits {
		required = append(required, digitChars)
	}
	if opts.Symbols {
		required = append(required, symbolChars)
	}
	return required
}
