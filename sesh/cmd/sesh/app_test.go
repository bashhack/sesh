package main

import (
	"testing"

	"github.com/bashhack/sesh/internal/aws"
	"github.com/bashhack/sesh/internal/keychain"
)

type KeychainError struct {
	Message string
}

func (e *KeychainError) Error() string {
	return e.Message
}

type SessionTokenError struct {
	Message string
}

func (e *SessionTokenError) Error() string {
	return e.Message
}

type MockAWS struct {
	MFADevice      string
	MFADeviceErr   error
	Credentials    aws.Credentials
	CredentialsErr error
}

func (m *MockAWS) GetFirstMFADevice(profile string) (string, error) {
	return m.MFADevice, m.MFADeviceErr
}

func (m *MockAWS) GetSessionToken(profile, serial string, code []byte) (aws.Credentials, error) {
	return m.Credentials, m.CredentialsErr
}

type MockKeychain struct {
	Secret       string
	SecretErr    error
	Entries      []keychain.KeychainEntry
	EntriesErr   error
}

// GetSecret implements keychain.Provider
func (m *MockKeychain) GetSecret(user, service string) ([]byte, error) {
	if m.SecretErr != nil {
		return nil, m.SecretErr
	}
	return []byte(m.Secret), nil
}

// SetSecret implements keychain.Provider
func (m *MockKeychain) SetSecret(user, service string, secret []byte) error {
	return nil
}

// GetSecretString implements keychain.Provider
func (m *MockKeychain) GetSecretString(user, keyName string) (string, error) {
	return m.Secret, m.SecretErr
}

// SetSecretString implements keychain.Provider
func (m *MockKeychain) SetSecretString(user, keyName, secret string) error {
	return nil
}

// GetMFASerialBytes implements keychain.Provider
func (m *MockKeychain) GetMFASerialBytes(account string) ([]byte, error) {
	return []byte("arn:aws:iam::123456789012:mfa/testuser"), nil
}

// ListEntries implements keychain.Provider
func (m *MockKeychain) ListEntries(service string) ([]keychain.KeychainEntry, error) {
	return m.Entries, m.EntriesErr
}

// DeleteEntry implements keychain.Provider
func (m *MockKeychain) DeleteEntry(account, service string) error {
	return nil
}

// StoreEntryMetadata implements keychain.Provider
func (m *MockKeychain) StoreEntryMetadata(servicePrefix, service, account, description string) error {
	return nil
}

// LoadEntryMetadata implements keychain.Provider
func (m *MockKeychain) LoadEntryMetadata(servicePrefix string) ([]keychain.KeychainEntryMeta, error) {
	return []keychain.KeychainEntryMeta{}, nil
}

// RemoveEntryMetadata implements keychain.Provider
func (m *MockKeychain) RemoveEntryMetadata(servicePrefix, service, account string) error {
	return nil
}

func TestNewDefaultApp(t *testing.T) {
	// Create app with mocked keychain from the start
	mockKeychain := &MockKeychain{}
	app := NewApp(mockKeychain)

	if app.Registry == nil {
		t.Error("Registry is nil")
	}
	if app.AWS == nil {
		t.Error("AWS provider is nil")
	}
	if app.Keychain == nil {
		t.Error("Keychain provider is nil")
	}
	if app.TOTP == nil {
		t.Error("TOTP provider is nil")
	}
	if app.SetupService == nil {
		t.Error("SetupService is nil")
	}
	if app.ExecLookPath == nil {
		t.Error("ExecLookPath is nil")
	}
	if app.Exit == nil {
		t.Error("Exit is nil")
	}
	if app.Stdout == nil {
		t.Error("Stdout is nil")
	}
	if app.Stderr == nil {
		t.Error("Stderr is nil")
	}

	// Check that providers are registered
	providers := app.Registry.ListProviders()
	if len(providers) == 0 {
		t.Error("No providers registered")
	}

	// Check AWS provider is registered
	awsProvider, err := app.Registry.GetProvider("aws")
	if err != nil {
		t.Error("AWS provider not registered")
	}
	if awsProvider == nil {
		t.Error("AWS provider is nil")
	}

	// Check TOTP provider is registered
	totpProvider, err := app.Registry.GetProvider("totp")
	if err != nil {
		t.Error("TOTP provider not registered")
	}
	if totpProvider == nil {
		t.Error("TOTP provider is nil")
	}
}

// This test is no longer applicable with the new architecture
// Error handling is now part of the provider implementations

// This test is no longer applicable with the new architecture
// Error handling is now part of the provider implementations

// This test is no longer applicable with the new architecture
// Error handling is now part of the provider implementations

// This test is no longer applicable with the new architecture
// Formatting is now part of the provider implementations or in PrintCredentials

// This test is no longer applicable with the new architecture
// MFA serial handling is now part of the AWS provider implementation

// This test is no longer applicable with the new architecture
// MFA serial handling is now part of the AWS provider implementation

// This test is no longer applicable with the new architecture
// MFA serial handling is now part of the AWS provider implementation

// This test is no longer applicable with the new architecture
// MFA serial handling is now part of the AWS provider implementation
