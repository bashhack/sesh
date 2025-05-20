package mocks

import "github.com/bashhack/sesh/internal/keychain"

// MockProvider is a mock implementation of the keychain.Provider interface
type MockProvider struct {
	GetSecretFunc           func(account, service string) ([]byte, error)
	SetSecretFunc           func(account, service string, secret []byte) error
	GetSecretStringFunc     func(account, service string) (string, error)
	SetSecretStringFunc     func(account, service, secret string) error
	GetMFASerialBytesFunc   func(account string) ([]byte, error)
	GetMFASerialFunc        func(account string) (string, error)
	ListEntriesFunc         func(service string) ([]keychain.KeychainEntry, error)
	DeleteEntryFunc         func(account, service string) error
	StoreEntryMetadataFunc  func(servicePrefix, service, account, description string) error
	LoadEntryMetadataFunc   func(servicePrefix string) ([]keychain.KeychainEntryMeta, error)
	RemoveEntryMetadataFunc func(servicePrefix, service, account string) error
}

// GetSecret implements the keychain.Provider interface
func (m *MockProvider) GetSecret(account, service string) ([]byte, error) {
	return m.GetSecretFunc(account, service)
}

// SetSecret implements the keychain.Provider interface
func (m *MockProvider) SetSecret(account, service string, secret []byte) error {
	return m.SetSecretFunc(account, service, secret)
}

// GetSecretString implements the keychain.Provider interface
func (m *MockProvider) GetSecretString(account, service string) (string, error) {
	return m.GetSecretStringFunc(account, service)
}

// SetSecretString implements the keychain.Provider interface
func (m *MockProvider) SetSecretString(account, service, secret string) error {
	return m.SetSecretStringFunc(account, service, secret)
}

// GetMFASerialBytes implements the keychain.Provider interface
func (m *MockProvider) GetMFASerialBytes(account string) ([]byte, error) {
	return m.GetMFASerialBytesFunc(account)
}

// GetMFASerial implements the keychain.Provider interface
func (m *MockProvider) GetMFASerial(account string) (string, error) {
	return m.GetMFASerialFunc(account)
}

// ListEntries implements the keychain.Provider interface
func (m *MockProvider) ListEntries(service string) ([]keychain.KeychainEntry, error) {
	return m.ListEntriesFunc(service)
}

// DeleteEntry implements the keychain.Provider interface
func (m *MockProvider) DeleteEntry(account, service string) error {
	return m.DeleteEntryFunc(account, service)
}

// StoreEntryMetadata implements the keychain.Provider interface
func (m *MockProvider) StoreEntryMetadata(servicePrefix, service, account, description string) error {
	return m.StoreEntryMetadataFunc(servicePrefix, service, account, description)
}

// LoadEntryMetadata implements the keychain.Provider interface
func (m *MockProvider) LoadEntryMetadata(servicePrefix string) ([]keychain.KeychainEntryMeta, error) {
	return m.LoadEntryMetadataFunc(servicePrefix)
}

// RemoveEntryMetadata implements the keychain.Provider interface
func (m *MockProvider) RemoveEntryMetadata(servicePrefix, service, account string) error {
	return m.RemoveEntryMetadataFunc(servicePrefix, service, account)
}
