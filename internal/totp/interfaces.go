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

// NewDefaultProvider creates a new DefaultProvider
func NewDefaultProvider() Provider {
	return &DefaultProvider{}
}
