package totp

// Provider defines the interface for TOTP operations
type Provider interface {
	// Generate generates a single TOTP code
	Generate(secret string) (string, error)

	// GenerateConsecutiveCodes generates two consecutive TOTP codes
	GenerateConsecutiveCodes(secret string) (current string, next string, err error)
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

// NewDefaultProvider creates a new DefaultProvider
func NewDefaultProvider() Provider {
	return &DefaultProvider{}
}
