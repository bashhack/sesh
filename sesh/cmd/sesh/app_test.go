package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/aws"
	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/setup"
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

// MockSetupService is a mock implementation of setup.SetupService
type MockSetupService struct {
	RegisterHandlerFunc   func(handler setup.SetupHandler)
	SetupServiceFunc      func(serviceName string) error
	GetAvailableServicesFunc func() []string
}

// RegisterHandler implements setup.SetupService
func (m *MockSetupService) RegisterHandler(handler setup.SetupHandler) {
	if m.RegisterHandlerFunc != nil {
		m.RegisterHandlerFunc(handler)
	}
}

// SetupService implements setup.SetupService
func (m *MockSetupService) SetupService(serviceName string) error {
	if m.SetupServiceFunc != nil {
		return m.SetupServiceFunc(serviceName)
	}
	return nil
}

// GetAvailableServices implements setup.SetupService
func (m *MockSetupService) GetAvailableServices() []string {
	if m.GetAvailableServicesFunc != nil {
		return m.GetAvailableServicesFunc()
	}
	return []string{}
}

// MockProvider is a mock implementation of provider.ServiceProvider
type MockProvider struct {
	NameFunc             func() string
	DescriptionFunc      func() string
	SetupFlagsFunc       func(fs provider.FlagSet) error
	GetSetupHandlerFunc  func() interface{}
	GetCredentialsFunc   func() (provider.Credentials, error)
	GetClipboardValueFunc func() (provider.Credentials, error)
	ListEntriesFunc      func() ([]provider.ProviderEntry, error)
	DeleteEntryFunc      func(id string) error
	ValidateRequestFunc  func() error
	GetFlagInfoFunc      func() []provider.FlagInfo
}

// Name implements provider.ServiceProvider
func (m *MockProvider) Name() string {
	if m.NameFunc != nil {
		return m.NameFunc()
	}
	return "mock"
}

// Description implements provider.ServiceProvider
func (m *MockProvider) Description() string {
	if m.DescriptionFunc != nil {
		return m.DescriptionFunc()
	}
	return "Mock provider"
}

// SetupFlags implements provider.ServiceProvider
func (m *MockProvider) SetupFlags(fs provider.FlagSet) error {
	if m.SetupFlagsFunc != nil {
		return m.SetupFlagsFunc(fs)
	}
	return nil
}

// GetSetupHandler implements provider.ServiceProvider
func (m *MockProvider) GetSetupHandler() interface{} {
	if m.GetSetupHandlerFunc != nil {
		return m.GetSetupHandlerFunc()
	}
	return nil
}

// GetCredentials implements provider.ServiceProvider
func (m *MockProvider) GetCredentials() (provider.Credentials, error) {
	if m.GetCredentialsFunc != nil {
		return m.GetCredentialsFunc()
	}
	return provider.Credentials{}, nil
}

// GetClipboardValue implements provider.ServiceProvider
func (m *MockProvider) GetClipboardValue() (provider.Credentials, error) {
	if m.GetClipboardValueFunc != nil {
		return m.GetClipboardValueFunc()
	}
	return provider.Credentials{}, nil
}

// ListEntries implements provider.ServiceProvider
func (m *MockProvider) ListEntries() ([]provider.ProviderEntry, error) {
	if m.ListEntriesFunc != nil {
		return m.ListEntriesFunc()
	}
	return []provider.ProviderEntry{}, nil
}

// DeleteEntry implements provider.ServiceProvider
func (m *MockProvider) DeleteEntry(id string) error {
	if m.DeleteEntryFunc != nil {
		return m.DeleteEntryFunc(id)
	}
	return nil
}

// ValidateRequest implements provider.ServiceProvider
func (m *MockProvider) ValidateRequest() error {
	if m.ValidateRequestFunc != nil {
		return m.ValidateRequestFunc()
	}
	return nil
}

// GetFlagInfo implements provider.ServiceProvider
func (m *MockProvider) GetFlagInfo() []provider.FlagInfo {
	if m.GetFlagInfoFunc != nil {
		return m.GetFlagInfoFunc()
	}
	return []provider.FlagInfo{}
}

func TestNewDefaultApp(t *testing.T) {
	// Test NewDefaultApp which uses the default keychain provider
	app := NewDefaultApp()

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

func TestApp_DeleteEntry(t *testing.T) {
	tests := map[string]struct {
		serviceName string
		entryID     string
		setupApp    func(*App)
		wantErr     bool
		wantErrMsg  string
		wantOutput  string
	}{
		"successful delete": {
			serviceName: "totp",
			entryID:     "sesh-totp-github:testuser",
			setupApp: func(app *App) {
				mockProvider := &MockProvider{
					DeleteEntryFunc: func(id string) error {
						if id == "sesh-totp-github:testuser" {
							return nil
						}
						return fmt.Errorf("unexpected id: %s", id)
					},
				}
				app.Registry.RegisterProvider(mockProvider)
			},
			wantErr:    false,
			wantOutput: "✅ Entry deleted successfully\n",
		},
		"provider not found": {
			serviceName: "unknown",
			entryID:     "some-id",
			setupApp:    func(app *App) {},
			wantErr:     true,
			wantErrMsg:  "provider not found",
		},
		"delete entry error": {
			serviceName: "totp",
			entryID:     "sesh-totp-github:testuser",
			setupApp: func(app *App) {
				mockProvider := &MockProvider{
					DeleteEntryFunc: func(id string) error {
						return errors.New("keychain error")
					},
				}
				app.Registry.RegisterProvider(mockProvider)
			},
			wantErr:    true,
			wantErrMsg: "failed to delete entry: keychain error",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Create app with mocks
			app := &App{
				Registry: provider.NewRegistry(),
				Stdout:   &bytes.Buffer{},
				Stderr:   &bytes.Buffer{},
			}

			// Setup test-specific configuration
			test.setupApp(app)

			// Test DeleteEntry
			err := app.DeleteEntry(test.serviceName, test.entryID)

			// Check error
			if test.wantErr && err == nil {
				t.Error("DeleteEntry() expected error but got nil")
			}
			if !test.wantErr && err != nil {
				t.Errorf("DeleteEntry() unexpected error: %v", err)
			}
			if test.wantErrMsg != "" && err != nil {
				if !strings.Contains(err.Error(), test.wantErrMsg) {
					t.Errorf("error message = %v, want to contain %v", err.Error(), test.wantErrMsg)
				}
			}

			// Check output
			if test.wantOutput != "" {
				output := app.Stdout.(*bytes.Buffer).String()
				if output != test.wantOutput {
					t.Errorf("output = %v, want %v", output, test.wantOutput)
				}
			}
		})
	}
}

func TestApp_RunSetup(t *testing.T) {
	tests := map[string]struct {
		serviceName string
		setupApp    func(*App)
		wantErr     bool
		wantErrMsg  string
	}{
		"successful setup": {
			serviceName: "totp",
			setupApp: func(app *App) {
				mockSetup := &MockSetupService{
					SetupServiceFunc: func(name string) error {
						if name == "totp" {
							return nil
						}
						return fmt.Errorf("unexpected service: %s", name)
					},
				}
				app.SetupService = mockSetup
			},
			wantErr: false,
		},
		"setup service not found": {
			serviceName: "unknown",
			setupApp: func(app *App) {
				mockSetup := &MockSetupService{
					SetupServiceFunc: func(name string) error {
						return fmt.Errorf("no setup handler registered for service: %s", name)
					},
				}
				app.SetupService = mockSetup
			},
			wantErr:    true,
			wantErrMsg: "no setup handler registered for service: unknown",
		},
		"setup error": {
			serviceName: "aws",
			setupApp: func(app *App) {
				mockSetup := &MockSetupService{
					SetupServiceFunc: func(name string) error {
						return errors.New("AWS CLI not found")
					},
				}
				app.SetupService = mockSetup
			},
			wantErr:    true,
			wantErrMsg: "AWS CLI not found",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Create app with mocks
			app := &App{
				Registry: provider.NewRegistry(),
				Stdout:   &bytes.Buffer{},
				Stderr:   &bytes.Buffer{},
			}

			// Setup test-specific configuration
			test.setupApp(app)

			// Test RunSetup
			err := app.RunSetup(test.serviceName)

			// Check error
			if test.wantErr && err == nil {
				t.Error("RunSetup() expected error but got nil")
			}
			if !test.wantErr && err != nil {
				t.Errorf("RunSetup() unexpected error: %v", err)
			}
			if test.wantErrMsg != "" && err != nil {
				if err.Error() != test.wantErrMsg {
					t.Errorf("error message = %v, want %v", err.Error(), test.wantErrMsg)
				}
			}
		})
	}
}

// Additional test for NewApp to ensure proper dependency injection
func TestNewApp(t *testing.T) {
	// Create app with mocked keychain
	mockKeychain := &MockKeychain{}
	app := NewApp(mockKeychain)

	// Verify keychain is properly injected
	if app.Keychain != mockKeychain {
		t.Error("Keychain not properly injected")
	}

	// Verify all dependencies are initialized
	if app.Registry == nil {
		t.Error("Registry is nil")
	}
	if app.AWS == nil {
		t.Error("AWS provider is nil")
	}
	if app.TOTP == nil {
		t.Error("TOTP provider is nil")
	}
	if app.SetupService == nil {
		t.Error("SetupService is nil")
	}

	// Check that setup handlers are registered
	services := app.SetupService.GetAvailableServices()
	if len(services) < 2 {
		t.Errorf("Expected at least 2 setup services, got %d", len(services))
	}
}
