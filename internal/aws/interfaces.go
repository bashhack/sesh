package aws

// Provider defines the interface for AWS operations
type Provider interface {
	// GetSessionToken gets temporary AWS credentials using MFA
	GetSessionToken(profile, serial, code string) (Credentials, error)

	// GetFirstMFADevice retrieves the first MFA device for the current user
	GetFirstMFADevice(profile string) (string, error)
}

// DefaultProvider is the default implementation using aws-cli
type DefaultProvider struct{}

// Ensure DefaultProvider implements the Provider interface
var _ Provider = (*DefaultProvider)(nil)

// GetSessionToken implements the Provider interface
func (p *DefaultProvider) GetSessionToken(profile, serial, code string) (Credentials, error) {
	return GetSessionToken(profile, serial, code)
}

// GetFirstMFADevice implements the Provider interface
func (p *DefaultProvider) GetFirstMFADevice(profile string) (string, error) {
	return GetFirstMFADevice(profile)
}

// NewDefaultProvider creates a new DefaultProvider
func NewDefaultProvider() Provider {
	return &DefaultProvider{}
}
