package totp

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/keychain"
	keychainMocks "github.com/bashhack/sesh/internal/keychain/mocks"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/setup"
	totpMocks "github.com/bashhack/sesh/internal/totp/mocks"
)

func TestProvider_Name(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "totp" {
		t.Errorf("Name() = %v, want %v", got, "totp")
	}
}

func TestProvider_Description(t *testing.T) {
	p := &Provider{}
	want := "Generic TOTP provider for any service"
	if got := p.Description(); got != want {
		t.Errorf("Description() = %v, want %v", got, want)
	}
}

func TestProvider_SetupFlags(t *testing.T) {
	// Create provider
	p := &Provider{}

	// Create flag set
	fs := flag.NewFlagSet("test", flag.ContinueOnError)

	// Setup flags
	err := p.SetupFlags(fs)
	if err != nil {
		t.Errorf("SetupFlags() unexpected error: %v", err)
		return
	}

	// Parse empty args to get defaults
	if err := fs.Parse([]string{}); err != nil {
		t.Errorf("Parse() error: %v", err)
	}

	// Check that keyUser is set
	if p.keyUser == "" {
		t.Error("keyUser should be set to current user")
	}
}

func TestProvider_GetFlagInfo(t *testing.T) {
	p := &Provider{}
	flags := p.GetFlagInfo()

	if len(flags) != 2 {
		t.Errorf("GetFlagInfo() returned %d flags, want 2", len(flags))
	}

	// Check service-name flag
	if flags[0].Name != "service-name" {
		t.Errorf("flag[0].Name = %v, want 'service-name'", flags[0].Name)
	}
	if flags[0].Type != "string" {
		t.Errorf("flag[0].Type = %v, want 'string'", flags[0].Type)
	}
	if !flags[0].Required {
		t.Error("service-name flag should be required")
	}

	// Check profile flag
	if flags[1].Name != "profile" {
		t.Errorf("flag[1].Name = %v, want 'profile'", flags[1].Name)
	}
	if flags[1].Type != "string" {
		t.Errorf("flag[1].Type = %v, want 'string'", flags[1].Type)
	}
	if flags[1].Required {
		t.Error("profile flag should not be required")
	}

}

// TOTP provider doesn't implement ShouldUseSubshell - it's not a SubshellProvider

func TestProvider_ValidateRequest(t *testing.T) {
	tests := map[string]struct {
		serviceName   string
		setupKeychain func(*keychainMocks.MockProvider)
		wantErr       bool
		wantErrMsg    string
	}{
		"valid request": {
			serviceName: "github",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.GetSecretFunc = func(account, service string) ([]byte, error) {
					if service == "sesh-totp-github" {
						return []byte("secret"), nil
					}
					return nil, fmt.Errorf("unexpected service: %s", service)
				}
			},
			wantErr: false,
		},
		"no TOTP secret for service": {
			serviceName: "gitlab",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.GetSecretFunc = func(account, service string) ([]byte, error) {
					return nil, errors.New("not found")
				}
			},
			wantErr:    true,
			wantErrMsg: "no TOTP entry found for service 'gitlab'. Run 'sesh --service totp --setup' first",
		},
		"empty service name": {
			serviceName: "",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				// Should not be called when service name is empty
				m.GetSecretFunc = func(account, service string) ([]byte, error) {
					t.Error("GetSecret should not be called with empty service name")
					return nil, errors.New("should not be called")
				}
			},
			wantErr:    true,
			wantErrMsg: "--service-name is required for TOTP provider",
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			// Create mock
			mockKeychain := &keychainMocks.MockProvider{}
			if test.setupKeychain != nil {
				test.setupKeychain(mockKeychain)
			}

			// Create provider
			p := &Provider{
				keychain:    mockKeychain,
				serviceName: test.serviceName,
				keyUser:     "testuser",
			}

			// Test ValidateRequest
			err := p.ValidateRequest()
			if test.wantErr && err == nil {
				t.Error("ValidateRequest() expected error but got nil")
			}
			if !test.wantErr && err != nil {
				t.Errorf("ValidateRequest() unexpected error: %v", err)
			}
			if test.wantErrMsg != "" && err != nil {
				if err.Error() != test.wantErrMsg {
					t.Errorf("error message = %v, want %v", err.Error(), test.wantErrMsg)
				}
			}
		})
	}
}

func TestProvider_GetCredentials(t *testing.T) {
	tests := map[string]struct {
		serviceName   string
		setupKeychain func(*keychainMocks.MockProvider)
		setupTOTP     func(*totpMocks.MockProvider)
		wantErr       bool
		wantCurrent   string
		wantNext      string
	}{
		"successful TOTP generation": {
			serviceName: "github",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.GetSecretFunc = func(account, service string) ([]byte, error) {
					if account == "testuser" && service == "sesh-totp-github" {
						return []byte("MYSECRET"), nil
					}
					return nil, fmt.Errorf("unexpected call: %s, %s", account, service)
				}
			},
			setupTOTP: func(m *totpMocks.MockProvider) {
				m.GenerateConsecutiveCodesBytesFunc = func(secret []byte) (string, string, error) {
					if string(secret) == "MYSECRET" {
						return "123456", "654321", nil
					}
					return "", "", fmt.Errorf("unexpected secret")
				}
			},
			wantCurrent: "123456",
			wantNext:    "654321",
		},
		"keychain error": {
			serviceName: "gitlab",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.GetSecretFunc = func(account, service string) ([]byte, error) {
					return nil, errors.New("keychain locked")
				}
			},
			setupTOTP: func(m *totpMocks.MockProvider) {
				// Should not be called
				m.GenerateConsecutiveCodesBytesFunc = func(secret []byte) (string, string, error) {
					t.Error("GenerateConsecutiveCodesBytes should not be called")
					return "", "", nil
				}
			},
			wantErr: true,
		},
		"TOTP generation error": {
			serviceName: "bitbucket",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.GetSecretFunc = func(account, service string) ([]byte, error) {
					return []byte("INVALIDSECRET"), nil
				}
			},
			setupTOTP: func(m *totpMocks.MockProvider) {
				m.GenerateConsecutiveCodesBytesFunc = func(secret []byte) (string, string, error) {
					return "", "", errors.New("invalid secret")
				}
			},
			wantErr: true,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			// Capture stderr to suppress debug output
			oldStderr := os.Stderr
			_, w, _ := os.Pipe()
			os.Stderr = w
			defer func() {
				w.Close()
				os.Stderr = oldStderr
			}()

			// Create mocks
			mockKeychain := &keychainMocks.MockProvider{}
			mockTOTP := &totpMocks.MockProvider{}
			test.setupKeychain(mockKeychain)
			test.setupTOTP(mockTOTP)

			// Create provider
			p := &Provider{
				keychain:    mockKeychain,
				totp:        mockTOTP,
				serviceName: test.serviceName,
				keyUser:     "testuser",
			}

			// Test GetCredentials which internally generates TOTP codes
			creds, err := p.GetCredentials()
			if test.wantErr && err == nil {
				t.Error("GetTOTPCodes() expected error but got nil")
			}
			if !test.wantErr && err != nil {
				t.Errorf("GetTOTPCodes() unexpected error: %v", err)
			}
			if !test.wantErr {
				if creds.CopyValue != test.wantCurrent {
					t.Errorf("copy value = %v, want %v", creds.CopyValue, test.wantCurrent)
				}
				// Check that display info contains the codes
				if !strings.Contains(creds.DisplayInfo, test.wantCurrent) {
					t.Error("DisplayInfo should contain current code")
				}
				if !strings.Contains(creds.DisplayInfo, test.wantNext) {
					t.Error("DisplayInfo should contain next code")
				}
			}
		})
	}
}

// GetCredentials is tested above in TestProvider_GetTOTPCodes

func TestProvider_GetClipboardValue(t *testing.T) {
	tests := map[string]struct {
		serviceName   string
		setupKeychain func(*keychainMocks.MockProvider)
		setupTOTP     func(*totpMocks.MockProvider)
		wantErr       bool
		checkResult   func(*testing.T, provider.Credentials)
	}{
		"successful clipboard value": {
			serviceName: "github",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.GetSecretFunc = func(account, service string) ([]byte, error) {
					if account == "testuser" && service == "sesh-totp-github" {
						return []byte("MYSECRET"), nil
					}
					return nil, fmt.Errorf("unexpected call")
				}
			},
			setupTOTP: func(m *totpMocks.MockProvider) {
				m.GenerateConsecutiveCodesBytesFunc = func(secret []byte) (string, string, error) {
					if string(secret) == "MYSECRET" {
						return "123456", "654321", nil
					}
					return "", "", fmt.Errorf("unexpected secret")
				}
			},
			wantErr: false,
			checkResult: func(t *testing.T, creds provider.Credentials) {
				if creds.Provider != "totp" {
					t.Errorf("Provider = %v, want 'totp'", creds.Provider)
				}
				if creds.CopyValue != "123456" {
					t.Errorf("CopyValue = %v, want '123456'", creds.CopyValue)
				}
				// Check that DisplayInfo contains expected text
				if !strings.Contains(creds.DisplayInfo, "123456") {
					t.Errorf("DisplayInfo should contain current code")
				}
				if !strings.Contains(creds.DisplayInfo, "github") {
					t.Errorf("DisplayInfo should contain service name")
				}
				if !strings.Contains(creds.DisplayInfo, "TOTP code") {
					t.Errorf("DisplayInfo should contain 'TOTP code'")
				}
			},
		},
		"error getting secret": {
			serviceName: "gitlab",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.GetSecretFunc = func(account, service string) ([]byte, error) {
					return nil, errors.New("keychain error")
				}
			},
			setupTOTP: func(m *totpMocks.MockProvider) {
				// Should not be called
			},
			wantErr: true,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			// Capture stderr to suppress debug output
			oldStderr := os.Stderr
			_, w, _ := os.Pipe()
			os.Stderr = w
			defer func() {
				w.Close()
				os.Stderr = oldStderr
			}()

			// Create mocks
			mockKeychain := &keychainMocks.MockProvider{}
			mockTOTP := &totpMocks.MockProvider{}
			test.setupKeychain(mockKeychain)
			if test.setupTOTP != nil {
				test.setupTOTP(mockTOTP)
			}

			// Create provider
			p := &Provider{
				keychain:    mockKeychain,
				totp:        mockTOTP,
				serviceName: test.serviceName,
				keyUser:     "testuser",
			}

			// Test GetClipboardValue
			creds, err := p.GetClipboardValue()
			if test.wantErr && err == nil {
				t.Error("GetClipboardValue() expected error but got nil")
			}
			if !test.wantErr && err != nil {
				t.Errorf("GetClipboardValue() unexpected error: %v", err)
			}
			if !test.wantErr && test.checkResult != nil {
				test.checkResult(t, creds)
			}
		})
	}
}

// TOTP provider doesn't implement NewSubshellConfig - it's not a SubshellProvider

func TestProvider_ListEntries(t *testing.T) {
	tests := map[string]struct {
		setupKeychain func(*keychainMocks.MockProvider)
		wantErr       bool
		wantCount     int
		checkEntries  func(*testing.T, []provider.ProviderEntry)
	}{
		"successful list": {
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.ListEntriesFunc = func(prefix string) ([]keychain.KeychainEntry, error) {
					if prefix == "sesh-totp" {
						return []keychain.KeychainEntry{
							{Service: "sesh-totp-github", Account: "testuser"},
							{Service: "sesh-totp-gitlab", Account: "testuser"},
							{Service: "sesh-totp-bitbucket", Account: "testuser"},
						}, nil
					}
					return nil, fmt.Errorf("unexpected prefix: %s", prefix)
				}
			},
			wantErr:   false,
			wantCount: 3,
			checkEntries: func(t *testing.T, entries []provider.ProviderEntry) {
				// Check first entry
				if entries[0].Name != "github" {
					t.Errorf("entries[0].Name = %v, want 'github'", entries[0].Name)
				}
				if entries[0].Description != "TOTP for github" {
					t.Errorf("entries[0].Description = %v, want 'TOTP for github'", entries[0].Description)
				}
				// Check that ID is properly formed
				if !strings.Contains(entries[0].ID, "sesh-totp-github") {
					t.Errorf("entries[0].ID should contain service name")
				}
			},
		},
		"keychain error": {
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.ListEntriesFunc = func(prefix string) ([]keychain.KeychainEntry, error) {
					return nil, errors.New("keychain error")
				}
			},
			wantErr: true,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			// Create mock
			mockKeychain := &keychainMocks.MockProvider{}
			test.setupKeychain(mockKeychain)

			// Create provider
			p := &Provider{
				keychain: mockKeychain,
			}

			// Test ListEntries
			entries, err := p.ListEntries()
			if test.wantErr && err == nil {
				t.Error("ListEntries() expected error but got nil")
			}
			if !test.wantErr && err != nil {
				t.Errorf("ListEntries() unexpected error: %v", err)
			}
			if !test.wantErr {
				if len(entries) != test.wantCount {
					t.Errorf("entries count = %d, want %d", len(entries), test.wantCount)
				}
				if test.checkEntries != nil {
					test.checkEntries(t, entries)
				}
			}
		})
	}
}

func TestProvider_DeleteEntry(t *testing.T) {
	tests := map[string]struct {
		entryID       string
		setupKeychain func(*keychainMocks.MockProvider)
		wantErr       bool
		wantErrMsg    string
	}{
		"successful delete": {
			entryID: "sesh-totp-github:testuser",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.DeleteEntryFunc = func(account, service string) error {
					if account == "testuser" && service == "sesh-totp-github" {
						return nil
					}
					return fmt.Errorf("unexpected delete: %s, %s", account, service)
				}
			},
			wantErr: false,
		},
		"invalid ID format": {
			entryID: "invalid-id",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				// Should not be called
				m.DeleteEntryFunc = func(account, service string) error {
					t.Error("DeleteEntry should not be called with invalid ID")
					return nil
				}
			},
			wantErr:    true,
			wantErrMsg: "invalid entry ID format: expected 'service:account', got \"invalid-id\"",
		},
		"keychain error": {
			entryID: "sesh-totp-gitlab:testuser",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.DeleteEntryFunc = func(account, service string) error {
					return errors.New("keychain error")
				}
			},
			wantErr: true,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			// Create mock
			mockKeychain := &keychainMocks.MockProvider{}
			test.setupKeychain(mockKeychain)

			// Create provider
			p := &Provider{
				keychain: mockKeychain,
			}

			// Test DeleteEntry
			err := p.DeleteEntry(test.entryID)
			if test.wantErr && err == nil {
				t.Error("DeleteEntry() expected error but got nil")
			}
			if !test.wantErr && err != nil {
				t.Errorf("DeleteEntry() unexpected error: %v", err)
			}
			if test.wantErrMsg != "" && err != nil {
				if err.Error() != test.wantErrMsg {
					t.Errorf("error message = %v, want %v", err.Error(), test.wantErrMsg)
				}
			}
		})
	}
}

// formatDisplayInfo is not a method on the TOTP provider - it uses the shared helper functions

// TestNewProvider tests the NewProvider function
func TestNewProvider(t *testing.T) {
	// Create mocks
	mockKeychain := &keychainMocks.MockProvider{}
	mockTOTP := &totpMocks.MockProvider{}

	// Create provider
	p := NewProvider(mockKeychain, mockTOTP)

	// Verify the provider is initialized correctly
	if p == nil {
		t.Fatal("NewProvider returned nil")
	}

	// Verify internal fields are set
	if p.keychain != mockKeychain {
		t.Error("keychain field not set correctly")
	}

	if p.totp != mockTOTP {
		t.Error("totp field not set correctly")
	}

	// Verify the provider implements the ServiceProvider interface
	var _ provider.ServiceProvider = p
}

// TestProvider_GetSetupHandler tests the GetSetupHandler method
func TestProvider_GetSetupHandler(t *testing.T) {
	// Create mocks
	mockKeychain := &keychainMocks.MockProvider{}

	// Create provider
	p := &Provider{
		keychain: mockKeychain,
	}

	// Get setup handler
	handler := p.GetSetupHandler()

	// Verify handler is not nil
	if handler == nil {
		t.Fatal("GetSetupHandler returned nil")
	}

	// Verify it returns a TOTPSetupHandler
	totpHandler, ok := handler.(*setup.TOTPSetupHandler)
	if !ok {
		t.Fatalf("GetSetupHandler returned unexpected type: %T", handler)
	}

	// Verify the handler has the expected service name
	if totpHandler.ServiceName() != "totp" {
		t.Errorf("handler.ServiceName() = %v, want 'totp'", totpHandler.ServiceName())
	}
}