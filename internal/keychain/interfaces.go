package keychain

// Provider defines the interface for keychain operations
type Provider interface {
	// GetSecret retrieves a secret from the keychain
	GetSecret(account, service string) (string, error)

	// SetSecret sets a secret in the keychain
	SetSecret(account, service, secret string) error

	// GetMFASerial retrieves the MFA serial from the keychain
	GetMFASerial(account string) (string, error)

	// ListEntries lists all entries for a given service
	ListEntries(service string) ([]KeychainEntry, error)

	// DeleteEntry deletes an entry from the keychain
	DeleteEntry(account, service string) error
}

// KeychainEntry represents an entry in the keychain
type KeychainEntry struct {
	Service     string
	Account     string
	Description string
}

// DefaultProvider is the default implementation using the system keychain
type DefaultProvider struct{}

// Ensure DefaultProvider implements Provider interface
var _ Provider = (*DefaultProvider)(nil)

// GetSecret implements the Provider interface
func (p *DefaultProvider) GetSecret(account, service string) (string, error) {
	return GetSecret(account, service)
}

// SetSecret implements the Provider interface
func (p *DefaultProvider) SetSecret(account, service, secret string) error {
	return SetSecret(account, service, secret)
}

// GetMFASerial implements the Provider interface
func (p *DefaultProvider) GetMFASerial(account string) (string, error) {
	return GetMFASerial(account)
}

// ListEntries implements the Provider interface
func (p *DefaultProvider) ListEntries(service string) ([]KeychainEntry, error) {
	return ListEntries(service)
}

// DeleteEntry implements the Provider interface
func (p *DefaultProvider) DeleteEntry(account, service string) error {
	return DeleteEntry(account, service)
}

// NewDefaultProvider creates a new DefaultProvider
func NewDefaultProvider() Provider {
	return &DefaultProvider{}
}
