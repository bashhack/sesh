package keychain

import "time"

// Provider defines the interface for credential storage operations.
// Implementations include the macOS system keychain and the SQLite store.
type Provider interface {
	// GetSecret retrieves a secret as a byte slice.
	// The returned byte slice should be zeroed after use with secure.SecureZeroBytes.
	GetSecret(account, service string) ([]byte, error)

	// SetSecret stores a secret as a byte slice.
	SetSecret(account, service string, secret []byte) error

	// GetSecretString retrieves a secret as a string.
	// Less secure than GetSecret — use only when necessary.
	GetSecretString(account, service string) (string, error)

	// SetSecretString stores a string secret.
	// Less secure than SetSecret — use only when necessary.
	SetSecretString(account, service, secret string) error

	// GetMFASerialBytes retrieves the MFA serial as bytes.
	GetMFASerialBytes(account, profile string) ([]byte, error)

	// ListEntries lists all entries whose service key starts with the given prefix.
	ListEntries(service string) ([]KeychainEntry, error)

	// DeleteEntry removes an entry.
	DeleteEntry(account, service string) error

	// SetDescription sets a human-readable description on an existing entry.
	SetDescription(service, account, description string) error
}

// KeychainEntry represents an entry in the credential store.
type KeychainEntry struct {
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Service     string
	Account     string
	Description string
}

// DefaultProvider is the default implementation using the system keychain
type DefaultProvider struct{}

var _ Provider = (*DefaultProvider)(nil)

// GetSecret implements the Provider interface
func (p *DefaultProvider) GetSecret(account, service string) ([]byte, error) {
	return GetSecretBytes(account, service)
}

// SetSecret implements the Provider interface
func (p *DefaultProvider) SetSecret(account, service string, secret []byte) error {
	return SetSecretBytes(account, service, secret)
}

// GetSecretString implements the Provider interface
func (p *DefaultProvider) GetSecretString(account, service string) (string, error) {
	return GetSecretString(account, service)
}

// SetSecretString implements the Provider interface
func (p *DefaultProvider) SetSecretString(account, service, secret string) error {
	return SetSecretString(account, service, secret)
}

// GetMFASerialBytes implements the Provider interface
func (p *DefaultProvider) GetMFASerialBytes(account, profile string) ([]byte, error) {
	return GetMFASerialBytes(account, profile)
}

// ListEntries implements the Provider interface
func (p *DefaultProvider) ListEntries(service string) ([]KeychainEntry, error) {
	return ListEntries(service)
}

// DeleteEntry implements the Provider interface
func (p *DefaultProvider) DeleteEntry(account, service string) error {
	return DeleteEntry(account, service)
}

// SetDescription implements the Provider interface
func (p *DefaultProvider) SetDescription(service, account, description string) error {
	servicePrefix := getServicePrefix(service)
	return StoreEntryMetadata(servicePrefix, service, account, description)
}

// NewDefaultProvider creates a new DefaultProvider
func NewDefaultProvider() Provider {
	return &DefaultProvider{}
}
