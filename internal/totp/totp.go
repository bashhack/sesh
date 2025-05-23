package totp

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/pquerna/otp/totp"
)

// ValidateAndNormalizeSecret validates and normalizes a base32-encoded TOTP secret.
// It handles common formatting issues like spaces, lowercase letters, and missing padding.
func ValidateAndNormalizeSecret(secret string) (string, error) {
	if secret == "" {
		return "", fmt.Errorf("secret cannot be empty")
	}

	// Remove all whitespace (spaces, tabs, newlines)
	cleaned := strings.ReplaceAll(secret, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "\t", "")
	cleaned = strings.ReplaceAll(cleaned, "\n", "")
	cleaned = strings.ReplaceAll(cleaned, "\r", "")

	// After cleaning whitespace, check if we have anything left
	if cleaned == "" {
		return "", fmt.Errorf("secret cannot be empty")
	}

	// Convert to uppercase (base32 standard)
	cleaned = strings.ToUpper(cleaned)

	// Validate characters - only A-Z, 2-7, and = are valid in base32
	for i, char := range cleaned {
		if !((char >= 'A' && char <= 'Z') || (char >= '2' && char <= '7') || char == '=') {
			return "", fmt.Errorf("invalid character '%c' at position %d - base32 secrets can only contain A-Z, 2-7, and =", char, i)
		}
	}

	// Check minimum length - RFC 4226 recommends 128 bits (26 base32 chars), 
	// but many providers use shorter secrets. Accept anything >= 64 bits (13 chars)
	if len(cleaned) < 8 {
		return "", fmt.Errorf("secret too short (%d characters) - TOTP secrets should be at least 8 characters", len(cleaned))
	}

	// Add proper base32 padding if missing
	// Base32 requires padding to make length a multiple of 8
	remainder := len(cleaned) % 8
	if remainder != 0 {
		padLength := 8 - remainder
		cleaned = cleaned + strings.Repeat("=", padLength)
	}

	// Validate by attempting to decode (this catches structural issues)
	testBytes := []byte(cleaned)
	defer secure.SecureZeroBytes(testBytes)
	
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
		return "", fmt.Errorf("failed to generate TOTP for time %v: %w", t, err)
	}

	return code, nil
}

// GenerateConsecutiveCodes generates two consecutive TOTP codes for MFA device setup
func GenerateConsecutiveCodes(secret string) (current string, next string, err error) {
	if MockGenerateConsecutiveCodes.Enabled {
		return MockGenerateConsecutiveCodes.CurrentCode, MockGenerateConsecutiveCodes.NextCode, MockGenerateConsecutiveCodes.Error
	}

	// Create a copy of the secret we can zero later
	secretBytes := []byte(secret)
	defer secure.SecureZeroBytes(secretBytes)

	now := time.Now()

	// Note to self here, if I end up making this generic and pulling up into
	// app init, I'll need to hit all instances of ValidateOpts
	opts := totp.ValidateOpts{
		Digits: 6,
	}

	current, err = totp.GenerateCodeCustom(secret, now, opts)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate current TOTP: %w", err)
	}

	// Typically 30 seconds, so keeping it consistent - but again, could make configurable if need arises
	// just haven't seen it yet for myself
	next, err = totp.GenerateCodeCustom(secret, now.Add(30*time.Second), opts)
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

// Byte-slice based implementations for improved security

// GenerateBytes generates a TOTP code from a byte slice secret
// The secret is expected to be a byte slice containing a base32-encoded string
func GenerateBytes(secret []byte) (string, error) {
	// Make a defensive copy to avoid modifying the caller's data
	secretCopy := make([]byte, len(secret))
	copy(secretCopy, secret)
	defer secure.SecureZeroBytes(secretCopy)

	// Convert to string - the secret is already base32-encoded in string form
	secretStr := string(secretCopy)

	// Basic cleanup - trim whitespace which can cause decode failures
	secretStr = string(bytes.TrimSpace([]byte(secretStr)))

	// Now use the string-based implementation
	return Generate(secretStr)
}

// GenerateConsecutiveCodesBytes generates two consecutive TOTP codes from a byte slice secret
// The secret is expected to be a byte slice containing a base32-encoded string
func GenerateConsecutiveCodesBytes(secret []byte) (current string, next string, err error) {
	if MockGenerateConsecutiveCodes.Enabled {
		return MockGenerateConsecutiveCodes.CurrentCode, MockGenerateConsecutiveCodes.NextCode, MockGenerateConsecutiveCodes.Error
	}

	// Check if we have valid input
	if len(secret) == 0 {
		return "", "", fmt.Errorf("empty secret provided to GenerateConsecutiveCodesBytes")
	}

	// Make a defensive copy to avoid modifying the caller's data
	secretCopy := make([]byte, len(secret))
	copy(secretCopy, secret)
	defer secure.SecureZeroBytes(secretCopy)

	// Convert to string - the secret is already base32-encoded in string form
	// We're just converting the byte representation back to a string
	secretStr := string(secretCopy)

	// Basic cleanup - trim whitespace which can cause decode failures
	secretStr = string(bytes.TrimSpace([]byte(secretStr)))

	// Use the string-based implementation directly to avoid error chain
	now := time.Now()
	nextTimeWindow := now.Add(30 * time.Second)

	opts := totp.ValidateOpts{
		Digits: 6,
	}

	current, err = totp.GenerateCodeCustom(secretStr, now, opts)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate current TOTP: %w", err)
	}

	next, err = totp.GenerateCodeCustom(secretStr, nextTimeWindow, opts)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate next TOTP: %w", err)
	}

	return current, next, nil
}

// GenerateForTimeBytes generates a TOTP code for a specific time from a byte slice secret
// The secret is expected to be a byte slice containing a base32-encoded string
func GenerateForTimeBytes(secret []byte, t time.Time) (string, error) {
	// Make a defensive copy to avoid modifying the caller's data
	secretCopy := make([]byte, len(secret))
	copy(secretCopy, secret)
	defer secure.SecureZeroBytes(secretCopy)

	// Convert to string - the secret is already base32-encoded in string form
	secretStr := string(secretCopy)

	// Basic cleanup - trim whitespace which can cause decode failures
	secretStr = string(bytes.TrimSpace([]byte(secretStr)))

	// Use the string-based implementation
	return GenerateForTime(secretStr, t)
}
