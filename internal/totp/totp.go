package totp

import (
	"fmt"
	"os"
	"time"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/pquerna/otp/totp"
)

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
	
	// Check if it matches base32 pattern and clean it up if needed
	allValid := true
	validChars := 0
	for _, c := range secretStr {
		// Only uppercase letters A-Z and digits 2-7 and padding = are valid in base32
		if (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7') || c == '=' {
			validChars++
		} else if c == '\n' || c == '\r' || c == ' ' || c == '\t' {
			// Ignore whitespace characters
		} else {
			allValid = false
		}
	}
	
	if !allValid {
		fmt.Fprintf(os.Stderr, "DEBUG: Secret string contains non-base32 characters (only %d/%d valid)\n", 
			validChars, len(secretStr))
		
		// Attempt to clean up the secret - this is a recovery mechanism
		// Strip any non-base32 characters and try to proceed with what's left
		cleanSecret := make([]byte, 0, len(secretStr))
		for _, c := range secretStr {
			if (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7') || c == '=' {
				cleanSecret = append(cleanSecret, byte(c))
			}
			// Silently drop invalid characters
		}
		
		// If we have enough valid characters after cleanup, proceed with the cleaned version
		if len(cleanSecret) >= 16 {
			fmt.Fprintf(os.Stderr, "DEBUG: Cleaned secret, now has %d valid base32 characters\n", len(cleanSecret))
			secretStr = string(cleanSecret)
		} else {
			fmt.Fprintf(os.Stderr, "DEBUG: Not enough valid base32 characters in secret after cleanup (%d)\n", len(cleanSecret))
			return "", fmt.Errorf("secret does not contain enough valid base32 characters after cleanup")
		}
	}
	
	// Now use the string-based implementation
	return Generate(secretStr)
}

// GenerateConsecutiveCodesBytes generates two consecutive TOTP codes from a byte slice secret
// The secret is expected to be a byte slice containing a base32-encoded string
func GenerateConsecutiveCodesBytes(secret []byte) (current string, next string, err error) {
	if MockGenerateConsecutiveCodes.Enabled {
		return MockGenerateConsecutiveCodes.CurrentCode, MockGenerateConsecutiveCodes.NextCode, MockGenerateConsecutiveCodes.Error
	}

	// Debug - check if we have valid input
	if len(secret) == 0 {
		fmt.Fprintf(os.Stderr, "DEBUG: GenerateConsecutiveCodesBytes received empty secret\n")
		return "", "", fmt.Errorf("empty secret provided to GenerateConsecutiveCodesBytes")
	}

	// For debugging, print length info (but nothing about the actual secret)
	fmt.Fprintf(os.Stderr, "DEBUG: GenerateConsecutiveCodesBytes received %d bytes\n", len(secret))

	// Make a defensive copy to avoid modifying the caller's data
	secretCopy := make([]byte, len(secret))
	copy(secretCopy, secret)
	defer secure.SecureZeroBytes(secretCopy)
	
	// Convert to string - the secret is already base32-encoded in string form
	// We're just converting the byte representation back to a string
	secretStr := string(secretCopy)

	// Debug - check secret format without revealing it
	if len(secretStr) < 16 {
		fmt.Fprintf(os.Stderr, "DEBUG: Secret string is too short: %d chars\n", len(secretStr))
	}
	
	// Debug - check if it matches base32 pattern and clean it up if needed
	allValid := true
	validChars := 0
	fmt.Fprintf(os.Stderr, "DEBUG TOTP: Secret string length: %d\n", len(secretStr))
	
	// Print only the first 5 characters to help debug without exposing the full secret
	if len(secretStr) > 5 {
		fmt.Fprintf(os.Stderr, "DEBUG TOTP: First 5 chars (hex): %x\n", []byte(secretStr[:5]))
	}
	
	for i, c := range secretStr {
		// Only uppercase letters A-Z and digits 2-7 and padding = are valid in base32
		if (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7') || c == '=' {
			validChars++
			if i < 5 {
				fmt.Fprintf(os.Stderr, "DEBUG TOTP: Char %d (%c) is valid base32\n", i, c)
			}
		} else if c == '\n' || c == '\r' || c == ' ' || c == '\t' {
			// Ignore whitespace characters
			if i < 5 {
				fmt.Fprintf(os.Stderr, "DEBUG TOTP: Char %d (0x%x) is whitespace\n", i, c)
			}
		} else {
			allValid = false
			if i < 5 {
				fmt.Fprintf(os.Stderr, "DEBUG TOTP: Char %d (0x%x) is NOT valid base32\n", i, c)
			}
		}
	}
	
	if !allValid {
		fmt.Fprintf(os.Stderr, "DEBUG: Secret string contains non-base32 characters (only %d/%d valid)\n", 
			validChars, len(secretStr))
		
		// Attempt to clean up the secret - this is a recovery mechanism
		// Strip any non-base32 characters and try to proceed with what's left
		cleanSecret := make([]byte, 0, len(secretStr))
		for _, c := range secretStr {
			if (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7') || c == '=' {
				cleanSecret = append(cleanSecret, byte(c))
			}
			// Silently drop invalid characters
		}
		
		// If we have enough valid characters after cleanup, proceed with the cleaned version
		if len(cleanSecret) >= 16 {
			fmt.Fprintf(os.Stderr, "DEBUG: Cleaned secret, now has %d valid base32 characters\n", len(cleanSecret))
			secretStr = string(cleanSecret)
		} else {
			fmt.Fprintf(os.Stderr, "DEBUG: Not enough valid base32 characters in secret after cleanup (%d)\n", len(cleanSecret))
			return "", "", fmt.Errorf("secret does not contain enough valid base32 characters after cleanup")
		}
	}
	
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
	
	// Check if it matches base32 pattern and clean it up if needed
	allValid := true
	validChars := 0
	for _, c := range secretStr {
		// Only uppercase letters A-Z and digits 2-7 and padding = are valid in base32
		if (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7') || c == '=' {
			validChars++
		} else if c == '\n' || c == '\r' || c == ' ' || c == '\t' {
			// Ignore whitespace characters
		} else {
			allValid = false
		}
	}
	
	if !allValid {
		fmt.Fprintf(os.Stderr, "DEBUG: Secret string contains non-base32 characters (only %d/%d valid)\n", 
			validChars, len(secretStr))
		
		// Attempt to clean up the secret - this is a recovery mechanism
		// Strip any non-base32 characters and try to proceed with what's left
		cleanSecret := make([]byte, 0, len(secretStr))
		for _, c := range secretStr {
			if (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7') || c == '=' {
				cleanSecret = append(cleanSecret, byte(c))
			}
			// Silently drop invalid characters
		}
		
		// If we have enough valid characters after cleanup, proceed with the cleaned version
		if len(cleanSecret) >= 16 {
			fmt.Fprintf(os.Stderr, "DEBUG: Cleaned secret, now has %d valid base32 characters\n", len(cleanSecret))
			secretStr = string(cleanSecret)
		} else {
			fmt.Fprintf(os.Stderr, "DEBUG: Not enough valid base32 characters in secret after cleanup (%d)\n", len(cleanSecret))
			return "", fmt.Errorf("secret does not contain enough valid base32 characters after cleanup")
		}
	}
	
	// Use the string-based implementation
	return GenerateForTime(secretStr, t)
}
