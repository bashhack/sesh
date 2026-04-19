// Package mocks provides test doubles for the keychain package interfaces.
package mocks

import "github.com/bashhack/sesh/internal/keychain"

// MockProvider is a mock implementation of the keychain.Provider interface.
// Any *Func field left nil returns the zero value of its method's return
// types so tests can wire only the subset of methods they care about.
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
	if m.GetSecretFunc == nil {
		return nil, nil
	}
	return m.GetSecretFunc(account, service)
}

// SetSecret implements the keychain.Provider interface
func (m *MockProvider) SetSecret(account, service string, secret []byte) error {
	if m.SetSecretFunc == nil {
		return nil
	}
	return m.SetSecretFunc(account, service, secret)
}

// GetSecretString implements the keychain.Provider interface
func (m *MockProvider) GetSecretString(account, service string) (string, error) {
	if m.GetSecretStringFunc == nil {
		return "", nil
	}
	return m.GetSecretStringFunc(account, service)
}

// SetSecretString implements the keychain.Provider interface
func (m *MockProvider) SetSecretString(account, service, secret string) error {
	if m.SetSecretStringFunc == nil {
		return nil
	}
	return m.SetSecretStringFunc(account, service, secret)
}

// GetMFASerialBytes implements the keychain.Provider interface
func (m *MockProvider) GetMFASerialBytes(account, profile string) ([]byte, error) {
	if m.GetMFASerialBytesFunc == nil {
		return nil, nil
	}
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
	if m.DeleteEntryFunc == nil {
		return nil
	}
	return m.DeleteEntryFunc(account, service)
}

// SetDescription implements the keychain.Provider interface
func (m *MockProvider) SetDescription(service, account, description string) error {
	if m.SetDescriptionFunc == nil {
		return nil
	}
	return m.SetDescriptionFunc(service, account, description)
}
