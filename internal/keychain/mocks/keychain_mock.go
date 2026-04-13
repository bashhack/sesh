// Package mocks provides test doubles for the keychain package interfaces.
package mocks

import "github.com/bashhack/sesh/internal/keychain"

// MockProvider is a mock implementation of the keychain.Provider interface
type MockProvider struct {
	GetSecretFunc         func(account, service string) ([]byte, error)
	SetSecretFunc         func(account, service string, secret []byte) error
	GetSecretStringFunc   func(account, service string) (string, error)
	SetSecretStringFunc   func(account, service, secret string) error
	GetMFASerialBytesFunc func(account, profile string) ([]byte, error)
	ListEntriesFunc       func(service string) ([]keychain.KeychainEntry, error)
	DeleteEntryFunc       func(account, service string) error
	SetDescriptionFunc    func(service, account, description string) error
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
func (m *MockProvider) GetMFASerialBytes(account, profile string) ([]byte, error) {
	return m.GetMFASerialBytesFunc(account, profile)
}

// ListEntries implements the keychain.Provider interface
func (m *MockProvider) ListEntries(service string) ([]keychain.KeychainEntry, error) {
	if m.ListEntriesFunc == nil {
		return nil, nil
	}
	return m.ListEntriesFunc(service)
}

// DeleteEntry implements the keychain.Provider interface
func (m *MockProvider) DeleteEntry(account, service string) error {
	return m.DeleteEntryFunc(account, service)
}

// SetDescription implements the keychain.Provider interface
func (m *MockProvider) SetDescription(service, account, description string) error {
	return m.SetDescriptionFunc(service, account, description)
}
