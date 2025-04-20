package keychain

// Provider defines the interface for keychain operations
type Provider interface {
	// GetSecret retrieves a secret from the keychain
	GetSecret(account, service string) (string, error)

	// GetMFASerial retrieves the MFA serial from the keychain
	GetMFASerial(account string) (string, error)
}

// DefaultProvider is the default implementation using the system keychain
type DefaultProvider struct{}

// Ensure DefaultProvider implements Provider interface
var _ Provider = (*DefaultProvider)(nil)

// GetSecret implements the Provider interface
func (p *DefaultProvider) GetSecret(account, service string) (string, error) {
	return GetSecret(account, service)
}

// GetMFASerial implements the Provider interface
func (p *DefaultProvider) GetMFASerial(account string) (string, error) {
	return GetMFASerial(account)
}

// NewDefaultProvider creates a new DefaultProvider
func NewDefaultProvider() Provider {
	return &DefaultProvider{}
}
