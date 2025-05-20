package keychain

// Provider defines the interface for keychain operations
type Provider interface {
	// GetSecret retrieves a secret from the keychain as a byte slice
	// for improved security. The returned byte slice should be zeroed
	// after use with secure.SecureZeroBytes
	GetSecret(account, service string) ([]byte, error)

	// SetSecret sets a secret in the keychain from a byte slice
	SetSecret(account, service string, secret []byte) error
	
	// GetSecretString retrieves a secret from the keychain as a string
	// Note: This is less secure than GetSecret and should be used only when necessary
	GetSecretString(account, service string) (string, error)

	// SetSecretString sets a string secret in the keychain
	// Note: This is less secure than SetSecret and should be used only when necessary
	SetSecretString(account, service, secret string) error

	// GetMFASerial retrieves the MFA serial from the keychain
	GetMFASerial(account string) (string, error)

	// ListEntries lists all entries for a given service
	ListEntries(service string) ([]KeychainEntry, error)

	// DeleteEntry deletes an entry from the keychain
	DeleteEntry(account, service string) error
	
	// StoreEntryMetadata adds or updates metadata for a keychain entry
	StoreEntryMetadata(servicePrefix, service, account, description string) error
	
	// LoadEntryMetadata loads metadata entries for a given service prefix
	LoadEntryMetadata(servicePrefix string) ([]KeychainEntryMeta, error)
	
	// RemoveEntryMetadata removes an entry from the metadata
	RemoveEntryMetadata(servicePrefix, service, account string) error
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

// StoreEntryMetadata implements the Provider interface
func (p *DefaultProvider) StoreEntryMetadata(servicePrefix, service, account, description string) error {
	return StoreEntryMetadata(servicePrefix, service, account, description)
}

// LoadEntryMetadata implements the Provider interface
func (p *DefaultProvider) LoadEntryMetadata(servicePrefix string) ([]KeychainEntryMeta, error) {
	return LoadEntryMetadata(servicePrefix)
}

// RemoveEntryMetadata implements the Provider interface
func (p *DefaultProvider) RemoveEntryMetadata(servicePrefix, service, account string) error {
	return RemoveEntryMetadata(servicePrefix, service, account)
}

// NewDefaultProvider creates a new DefaultProvider
func NewDefaultProvider() Provider {
	return &DefaultProvider{}
}
