package totp

import "time"

// Provider defines the interface for TOTP operations
type Provider interface {
	// Generate generates a single TOTP code
	Generate(secret string) (string, error)

	// GenerateConsecutiveCodes generates two consecutive TOTP codes
	GenerateConsecutiveCodes(secret string) (current string, next string, err error)

	// GenerateForTime generates a TOTP code for a specific time
	GenerateForTime(secret string, t time.Time) (string, error)
	
	// GenerateSecure is like Generate but securely zeroes the secret after use
	GenerateSecure(secret string) (string, error)
	
	// GenerateForTimeSecure is like GenerateForTime but securely zeroes the secret after use
	GenerateForTimeSecure(secret string, t time.Time) (string, error)
	
	// More secure variants using byte slices
	
	// GenerateBytes generates a single TOTP code from a byte slice secret
	// This allows for proper memory zeroing
	GenerateBytes(secret []byte) (string, error)
	
	// GenerateConsecutiveCodesBytes generates two consecutive TOTP codes from a byte slice secret
	GenerateConsecutiveCodesBytes(secret []byte) (current string, next string, err error)
	
	// GenerateForTimeBytes generates a TOTP code for a specific time from a byte slice secret
	GenerateForTimeBytes(secret []byte, t time.Time) (string, error)
}

// DefaultProvider is the default implementation using otp library
type DefaultProvider struct{}

// Ensure DefaultProvider implements Provider interface
var _ Provider = (*DefaultProvider)(nil)

// Generate implements the Provider interface
func (p *DefaultProvider) Generate(secret string) (string, error) {
	return Generate(secret)
}

// GenerateConsecutiveCodes implements the Provider interface
func (p *DefaultProvider) GenerateConsecutiveCodes(secret string) (current string, next string, err error) {
	return GenerateConsecutiveCodes(secret)
}

// GenerateForTime implements the Provider interface
func (p *DefaultProvider) GenerateForTime(secret string, t time.Time) (string, error) {
	return GenerateForTime(secret, t)
}

// GenerateSecure implements the Provider interface
func (p *DefaultProvider) GenerateSecure(secret string) (string, error) {
	return GenerateSecure(secret)
}

// GenerateForTimeSecure implements the Provider interface
func (p *DefaultProvider) GenerateForTimeSecure(secret string, t time.Time) (string, error) {
	return GenerateForTimeSecure(secret, t)
}

// GenerateBytes implements the Provider interface
func (p *DefaultProvider) GenerateBytes(secret []byte) (string, error) {
	return GenerateBytes(secret)
}

// GenerateConsecutiveCodesBytes implements the Provider interface
func (p *DefaultProvider) GenerateConsecutiveCodesBytes(secret []byte) (current string, next string, err error) {
	return GenerateConsecutiveCodesBytes(secret)
}

// GenerateForTimeBytes implements the Provider interface
func (p *DefaultProvider) GenerateForTimeBytes(secret []byte, t time.Time) (string, error) {
	return GenerateForTimeBytes(secret, t)
}

// NewDefaultProvider creates a new DefaultProvider
func NewDefaultProvider() Provider {
	return &DefaultProvider{}
}
