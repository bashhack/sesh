package totp

import (
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/bashhack/sesh/internal/secure"
)

// ValidateAndNormalizeSecret validates and normalizes a base32-encoded TOTP secret.
// It handles common formatting issues like spaces, lowercase letters, and missing padding.
func ValidateAndNormalizeSecret(secret string) (string, error) {
	if secret == "" {
		return "", fmt.Errorf("secret cannot be empty")
	}

	cleaned := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "").Replace(secret)

	if cleaned == "" {
		return "", fmt.Errorf("secret cannot be empty")
	}

	cleaned = strings.ToUpper(cleaned)

	for i, char := range cleaned {
		if (char < 'A' || char > 'Z') && (char < '2' || char > '7') && char != '=' {
			return "", fmt.Errorf("invalid character '%c' at position %d - base32 secrets can only contain A-Z, 2-7, and =", char, i)
		}
	}

	// Check minimum length - RFC 4226 recommends 128 bits (26 base32 chars),
	// but many providers use shorter secrets. Accept anything >= 64 bits (13 chars)
	if len(cleaned) < 13 {
		return "", fmt.Errorf("secret too short (%d characters) - TOTP secrets should be at least 13 characters (64 bits)", len(cleaned))
	}

	// Base32 requires padding to make length a multiple of 8
	remainder := len(cleaned) % 8
	if remainder != 0 {
		padLength := 8 - remainder
		cleaned += strings.Repeat("=", padLength)
	}

	_, err := Generate(cleaned)
	if err != nil {
		return "", fmt.Errorf("secret failed validation test: %w", err)
	}

	return cleaned, nil
}

func Generate(secret string) (string, error) {
	// Explicitly use default options for consistent 6-digit codes,
	// best practice dictates a minimum of 6-digits for TOTP - however,
	// given the spec allows for 4-10 digits, I'm definitely
	// thinking I might tie this to opt in the future (maybe based on
	// provider?) should be a simple flag to set in the options struct anyway
	opts := totp.ValidateOpts{
		Digits: 6,
	}

	code, err := totp.GenerateCodeCustom(secret, time.Now(), opts)
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP: %w", err)
	}

	return code, nil
}

// GenerateForTime generates a TOTP code for a specific time
func GenerateForTime(secret string, t time.Time) (string, error) {
	opts := totp.ValidateOpts{
		Digits: 6,
	}

	code, err := totp.GenerateCodeCustom(secret, t, opts)
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP for time: %v: %w", t, err)
	}

	return code, nil
}

// GenerateConsecutiveCodes generates two consecutive TOTP codes for MFA device setup.
func GenerateConsecutiveCodes(secret string) (current, next string, err error) {
	return GenerateConsecutiveCodesForTime(secret, time.Now())
}

// GenerateConsecutiveCodesForTime generates two consecutive TOTP codes for a given base time.
func GenerateConsecutiveCodesForTime(secret string, baseTime time.Time) (current, next string, err error) {
	secretBytes := []byte(secret)
	defer secure.SecureZeroBytes(secretBytes)

	// Note to self here, if I end up making this generic and pulling up into
	// app init, I'll need to hit all instances of ValidateOpts
	opts := totp.ValidateOpts{
		Digits: 6,
	}

	current, err = totp.GenerateCodeCustom(secret, baseTime, opts)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate current TOTP: %w", err)
	}

	// Typically 30 seconds, so keeping it consistent - but again, could make configurable if need arises
	// just haven't seen it yet for myself
	next, err = totp.GenerateCodeCustom(secret, baseTime.Add(30*time.Second), opts)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate next TOTP: %w", err)
	}

	return current, next, nil
}

// GenerateSecure is like Generate but securely zeroes the secret after use
func GenerateSecure(secret string) (string, error) {
	secretBytes := []byte(secret)
	defer secure.SecureZeroBytes(secretBytes)
	return Generate(secret)
}

// GenerateForTimeSecure is like GenerateForTime but securely zeroes the secret after use
func GenerateForTimeSecure(secret string, t time.Time) (string, error) {
	secretBytes := []byte(secret)
	defer secure.SecureZeroBytes(secretBytes)
	return GenerateForTime(secret, t)
}

// stripWhitespaceInPlace removes all whitespace from b in-place and returns
// the trimmed slice. This avoids extra allocations that can't be zeroed,
// matching the normalization behavior of ValidateAndNormalizeSecret.
func stripWhitespaceInPlace(b []byte) []byte {
	n := 0
	for _, c := range b {
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			b[n] = c
			n++
		}
	}
	return b[:n]
}

// GenerateBytes generates a TOTP code from a byte slice secret.
// The secret is expected to be a byte slice containing a base32-encoded string
func GenerateBytes(secret []byte) (string, error) {
	if len(secret) == 0 {
		return "", fmt.Errorf("empty secret provided")
	}

	secretCopy := make([]byte, len(secret))
	copy(secretCopy, secret)
	defer secure.SecureZeroBytes(secretCopy)

	// Strip whitespace in-place to avoid an extra allocation that can't be zeroed
	secretStr := string(stripWhitespaceInPlace(secretCopy))

	if secretStr == "" {
		return "", fmt.Errorf("secret cannot be empty after trimming whitespace")
	}

	return Generate(secretStr)
}

// GenerateConsecutiveCodesBytes generates two consecutive TOTP codes from a byte slice secret.
func GenerateConsecutiveCodesBytes(secret []byte) (current, next string, err error) {
	return GenerateConsecutiveCodesForTimeBytes(secret, time.Now())
}

// GenerateConsecutiveCodesForTimeBytes generates two consecutive TOTP codes from a byte slice secret for a given base time.
func GenerateConsecutiveCodesForTimeBytes(secret []byte, baseTime time.Time) (current, next string, err error) {
	if len(secret) == 0 {
		return "", "", fmt.Errorf("empty secret provided to GenerateConsecutiveCodesBytes")
	}

	secretCopy := make([]byte, len(secret))
	copy(secretCopy, secret)
	defer secure.SecureZeroBytes(secretCopy)

	// Strip whitespace in-place to avoid an extra allocation that can't be zeroed
	secretStr := string(stripWhitespaceInPlace(secretCopy))

	if secretStr == "" {
		return "", "", fmt.Errorf("secret cannot be empty after trimming whitespace")
	}

	opts := totp.ValidateOpts{
		Digits: 6,
	}

	current, err = totp.GenerateCodeCustom(secretStr, baseTime, opts)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate current TOTP: %w", err)
	}

	next, err = totp.GenerateCodeCustom(secretStr, baseTime.Add(30*time.Second), opts)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate next TOTP: %w", err)
	}
	return current, next, nil
}

// GenerateForTimeBytes generates a TOTP code for a specific time from a byte slice secret
// The secret is expected to be a byte slice containing a base32-encoded string
func GenerateForTimeBytes(secret []byte, t time.Time) (string, error) {
	if len(secret) == 0 {
		return "", fmt.Errorf("empty secret provided")
	}

	secretCopy := make([]byte, len(secret))
	copy(secretCopy, secret)
	defer secure.SecureZeroBytes(secretCopy)

	// Strip whitespace in-place to avoid an extra allocation that can't be zeroed
	secretStr := string(stripWhitespaceInPlace(secretCopy))

	if secretStr == "" {
		return "", fmt.Errorf("secret cannot be empty after trimming whitespace")
	}

	return GenerateForTime(secretStr, t)
}
