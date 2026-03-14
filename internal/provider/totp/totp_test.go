package totp

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/keychain"
	keychainMocks "github.com/bashhack/sesh/internal/keychain/mocks"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/setup"
	totpMocks "github.com/bashhack/sesh/internal/totp/mocks"
)

func TestNewProvider(t *testing.T) {
	mockKeychain := &keychainMocks.MockProvider{}
	mockTOTP := &totpMocks.MockProvider{}

	p := NewProvider(mockKeychain, mockTOTP)

	if p == nil {
		t.Fatal("NewProvider() returned nil")
	}
	if p.keychain != mockKeychain {
		t.Error("Keychain provider not set correctly")
	}
	if p.totp != mockTOTP {
		t.Error("TOTP provider not set correctly")
	}
}

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
	p := &Provider{}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)

	err := p.SetupFlags(fs)
	if err != nil {
		t.Fatalf("SetupFlags() unexpected error: %v", err)
	}

	if err := fs.Parse([]string{}); err != nil {
		t.Errorf("Parse() error: %v", err)
	}

	if p.keyUser == "" {
		t.Error("keyUser should be set to current user")
	}
}

func TestProvider_GetFlagInfo(t *testing.T) {
	p := &Provider{}
	flags := p.GetFlagInfo()

	if len(flags) != 2 {
		t.Fatalf("GetFlagInfo() returned %d flags, want 2", len(flags))
	}

	if flags[0].Name != "service-name" {
		t.Errorf("flag[0].Name = %v, want 'service-name'", flags[0].Name)
	}
	if !flags[0].Required {
		t.Error("service-name flag should be required")
	}

	if flags[1].Name != "profile" {
		t.Errorf("flag[1].Name = %v, want 'profile'", flags[1].Name)
	}
	if flags[1].Required {
		t.Error("profile flag should not be required")
	}
}

func TestProvider_GetSetupHandler(t *testing.T) {
	mockKeychain := &keychainMocks.MockProvider{}
	p := &Provider{keychain: mockKeychain}

	handler := p.GetSetupHandler()
	if handler == nil {
		t.Fatal("GetSetupHandler() returned nil")
	}

	totpHandler, ok := handler.(*setup.TOTPSetupHandler)
	if !ok {
		t.Fatalf("GetSetupHandler() returned %T, want *setup.TOTPSetupHandler", handler)
	}
	if totpHandler.ServiceName() != "totp" {
		t.Errorf("handler.ServiceName() = %v, want 'totp'", totpHandler.ServiceName())
	}
}

func TestProvider_ValidateRequest(t *testing.T) {
	tests := map[string]struct {
		serviceName   string
		profile       string
		setupKeychain func(*keychainMocks.MockProvider)
		wantErr       bool
		wantErrMsg    string
	}{
		"valid request": {
			serviceName: "github",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.GetSecretFunc = func(account, service string) ([]byte, error) {
					if service == "sesh-totp/github" {
						return []byte("secret"), nil
					}
					return nil, fmt.Errorf("unexpected service: %s", service)
				}
			},
		},
		"valid request with profile": {
			serviceName: "github",
			profile:     "work",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.GetSecretFunc = func(account, service string) ([]byte, error) {
					if service == "sesh-totp/github/work" {
						return []byte("secret"), nil
					}
					return nil, fmt.Errorf("unexpected service: %s", service)
				}
			},
		},
		"no TOTP secret for service": {
			serviceName: "gitlab",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.GetSecretFunc = func(account, service string) ([]byte, error) {
					return nil, keychain.ErrNotFound
				}
			},
			wantErr:    true,
			wantErrMsg: "no TOTP entry found for service 'gitlab'. Run 'sesh --service totp --setup' first",
		},
		"no TOTP secret for service with profile": {
			serviceName: "gitlab",
			profile:     "work",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.GetSecretFunc = func(account, service string) ([]byte, error) {
					return nil, keychain.ErrNotFound
				}
			},
			wantErr:    true,
			wantErrMsg: "no TOTP entry found for service 'gitlab' with profile 'work'. Run 'sesh --service totp --setup' first",
		},
		"keychain error surfaces without fallback message": {
			serviceName: "github",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.GetSecretFunc = func(account, service string) ([]byte, error) {
					return nil, errors.New("keychain locked")
				}
			},
			wantErr:    true,
			wantErrMsg: "failed to read TOTP secret from keychain: keychain locked",
		},
		"empty service name": {
			serviceName: "",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.GetSecretFunc = func(account, service string) ([]byte, error) {
					t.Error("GetSecret should not be called with empty service name")
					return nil, errors.New("should not be called")
				}
			},
			wantErr:    true,
			wantErrMsg: "--service-name is required for TOTP provider",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			mockKeychain := &keychainMocks.MockProvider{}
			tc.setupKeychain(mockKeychain)

			p := &Provider{
				keychain:    mockKeychain,
				serviceName: tc.serviceName,
				profile:     tc.profile,
				keyUser:     "testuser",
			}

			err := p.ValidateRequest()
			if tc.wantErr && err == nil {
				t.Error("ValidateRequest() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidateRequest() unexpected error: %v", err)
			}
			if tc.wantErrMsg != "" && err != nil {
				if err.Error() != tc.wantErrMsg {
					t.Errorf("error message = %v, want %v", err.Error(), tc.wantErrMsg)
				}
			}
		})
	}
}

func TestProvider_GetCredentials_StderrHintQuoting(t *testing.T) {
	tests := map[string]struct {
		serviceName string
		profile     string
		wantSubstr  string
	}{
		"simple service name": {
			serviceName: "github",
			wantSubstr:  `--service-name "github"`,
		},
		"service name with spaces": {
			serviceName: "my service",
			wantSubstr:  `--service-name "my service"`,
		},
		"profile with spaces": {
			serviceName: "github",
			profile:     "work account",
			wantSubstr:  `--profile "work account"`,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			oldStderr := os.Stderr
			r, w, pipeErr := os.Pipe()
			if pipeErr != nil {
				t.Fatalf("os.Pipe() failed: %v", pipeErr)
			}
			os.Stderr = w

			mockKeychain := &keychainMocks.MockProvider{
				GetSecretFunc: func(account, service string) ([]byte, error) {
					return []byte("MYSECRET"), nil
				},
			}
			mockTOTP := &totpMocks.MockProvider{
				GenerateConsecutiveCodesBytesFunc: func(secret []byte) (string, string, error) {
					return "123456", "654321", nil
				},
			}

			p := &Provider{
				keychain:    mockKeychain,
				totp:        mockTOTP,
				serviceName: tc.serviceName,
				profile:     tc.profile,
				keyUser:     "testuser",
				now:         func() time.Time { return time.Unix(5, 0) },
			}

			_, _ = p.GetCredentials()

			w.Close()
			var buf bytes.Buffer
			buf.ReadFrom(r)
			r.Close()
			os.Stderr = oldStderr

			stderr := buf.String()
			if !strings.Contains(stderr, tc.wantSubstr) {
				t.Errorf("stderr = %q, want substring %q", stderr, tc.wantSubstr)
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
					if account == "testuser" && service == "sesh-totp/github" {
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
			setupTOTP: func(m *totpMocks.MockProvider) {},
			wantErr:   true,
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
		"empty service name": {
			serviceName: "",
			setupKeychain: func(m *keychainMocks.MockProvider) {},
			setupTOTP:     func(m *totpMocks.MockProvider) {},
			wantErr:       true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			oldStderr := os.Stderr
			r, w, pipeErr := os.Pipe()
			if pipeErr != nil {
				t.Fatalf("os.Pipe() failed: %v", pipeErr)
			}
			os.Stderr = w
			defer func() {
				w.Close()
				io.Copy(io.Discard, r)
				r.Close()
				os.Stderr = oldStderr
			}()

			mockKeychain := &keychainMocks.MockProvider{}
			mockTOTP := &totpMocks.MockProvider{}
			tc.setupKeychain(mockKeychain)
			tc.setupTOTP(mockTOTP)

			p := &Provider{
				keychain:    mockKeychain,
				totp:        mockTOTP,
				serviceName: tc.serviceName,
				keyUser:     "testuser",
			}

			creds, err := p.GetCredentials()
			if tc.wantErr && err == nil {
				t.Error("GetCredentials() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("GetCredentials() unexpected error: %v", err)
			}
			if !tc.wantErr {
				if creds.CopyValue != tc.wantCurrent {
					t.Errorf("CopyValue = %v, want %v", creds.CopyValue, tc.wantCurrent)
				}
				if creds.ClipboardDescription != "TOTP code" {
					t.Errorf("ClipboardDescription = %v, want 'TOTP code'", creds.ClipboardDescription)
				}
				if !strings.Contains(creds.DisplayInfo, tc.wantCurrent) {
					t.Error("DisplayInfo should contain current code")
				}
				if !strings.Contains(creds.DisplayInfo, tc.wantNext) {
					t.Error("DisplayInfo should contain next code")
				}
			}
		})
	}
}

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
					if account == "testuser" && service == "sesh-totp/github" {
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
			checkResult: func(t *testing.T, creds provider.Credentials) {
				if creds.Provider != "totp" {
					t.Errorf("Provider = %v, want 'totp'", creds.Provider)
				}
				if creds.CopyValue != "123456" {
					t.Errorf("CopyValue = %v, want '123456'", creds.CopyValue)
				}
				if !strings.Contains(creds.DisplayInfo, "123456") {
					t.Error("DisplayInfo should contain current code")
				}
				if !strings.Contains(creds.DisplayInfo, "github") {
					t.Error("DisplayInfo should contain service name")
				}
				if !strings.Contains(creds.DisplayInfo, "TOTP code") {
					t.Error("DisplayInfo should contain 'TOTP code'")
				}
				if creds.ClipboardDescription != "TOTP code" {
					t.Errorf("ClipboardDescription = %v, want 'TOTP code'", creds.ClipboardDescription)
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
			setupTOTP: func(m *totpMocks.MockProvider) {},
			wantErr:   true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			oldStderr := os.Stderr
			r, w, pipeErr := os.Pipe()
			if pipeErr != nil {
				t.Fatalf("os.Pipe() failed: %v", pipeErr)
			}
			os.Stderr = w
			defer func() {
				w.Close()
				io.Copy(io.Discard, r)
				r.Close()
				os.Stderr = oldStderr
			}()

			mockKeychain := &keychainMocks.MockProvider{}
			mockTOTP := &totpMocks.MockProvider{}
			tc.setupKeychain(mockKeychain)
			tc.setupTOTP(mockTOTP)

			p := &Provider{
				keychain:    mockKeychain,
				totp:        mockTOTP,
				serviceName: tc.serviceName,
				keyUser:     "testuser",
			}

			creds, err := p.GetClipboardValue()
			if tc.wantErr && err == nil {
				t.Error("GetClipboardValue() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("GetClipboardValue() unexpected error: %v", err)
			}
			if !tc.wantErr && tc.checkResult != nil {
				tc.checkResult(t, creds)
			}
		})
	}
}

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
							{Service: "sesh-totp/github", Account: "testuser"},
							{Service: "sesh-totp/gitlab", Account: "testuser"},
							{Service: "sesh-totp/bitbucket", Account: "testuser"},
						}, nil
					}
					return nil, fmt.Errorf("unexpected prefix: %s", prefix)
				}
			},
			wantCount: 3,
			checkEntries: func(t *testing.T, entries []provider.ProviderEntry) {
				if entries[0].Name != "github" {
					t.Errorf("entries[0].Name = %v, want 'github'", entries[0].Name)
				}
				if entries[0].Description != "TOTP for github" {
					t.Errorf("entries[0].Description = %v, want 'TOTP for github'", entries[0].Description)
				}
				if entries[0].ID != "sesh-totp/github:testuser" {
					t.Errorf("entries[0].ID = %v, want 'sesh-totp/github:testuser'", entries[0].ID)
				}
			},
		},
		"list with profiles": {
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.ListEntriesFunc = func(prefix string) ([]keychain.KeychainEntry, error) {
					return []keychain.KeychainEntry{
						{Service: "sesh-totp/github/work", Account: "testuser"},
						{Service: "sesh-totp/github/personal", Account: "testuser"},
					}, nil
				}
			},
			wantCount: 2,
			checkEntries: func(t *testing.T, entries []provider.ProviderEntry) {
				if entries[0].Name != "github (work)" {
					t.Errorf("entries[0].Name = %v, want 'github (work)'", entries[0].Name)
				}
				if entries[0].Description != "TOTP for github profile work" {
					t.Errorf("entries[0].Description = %v, want 'TOTP for github profile work'", entries[0].Description)
				}
			},
		},
		"empty list": {
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.ListEntriesFunc = func(prefix string) ([]keychain.KeychainEntry, error) {
					return []keychain.KeychainEntry{}, nil
				}
			},
			wantCount: 0,
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

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			mockKeychain := &keychainMocks.MockProvider{}
			tc.setupKeychain(mockKeychain)

			p := &Provider{keychain: mockKeychain}

			entries, err := p.ListEntries()
			if tc.wantErr && err == nil {
				t.Error("ListEntries() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ListEntries() unexpected error: %v", err)
			}
			if !tc.wantErr {
				if len(entries) != tc.wantCount {
					t.Errorf("entries count = %d, want %d", len(entries), tc.wantCount)
				}
				if tc.checkEntries != nil {
					tc.checkEntries(t, entries)
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
			entryID: "sesh-totp/github:testuser",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.DeleteEntryFunc = func(account, service string) error {
					if account == "testuser" && service == "sesh-totp/github" {
						return nil
					}
					return fmt.Errorf("unexpected delete: %s, %s", account, service)
				}
			},
		},
		"invalid ID format": {
			entryID: "invalid-id",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.DeleteEntryFunc = func(account, service string) error {
					t.Error("DeleteEntry should not be called with invalid ID")
					return nil
				}
			},
			wantErr:    true,
			wantErrMsg: "invalid entry ID format: expected 'service:account', got \"invalid-id\"",
		},
		"keychain error": {
			entryID: "sesh-totp/gitlab:testuser",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.DeleteEntryFunc = func(account, service string) error {
					return errors.New("keychain error")
				}
			},
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			mockKeychain := &keychainMocks.MockProvider{}
			tc.setupKeychain(mockKeychain)

			p := &Provider{keychain: mockKeychain}

			err := p.DeleteEntry(tc.entryID)
			if tc.wantErr && err == nil {
				t.Error("DeleteEntry() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("DeleteEntry() unexpected error: %v", err)
			}
			if tc.wantErrMsg != "" && err != nil {
				if err.Error() != tc.wantErrMsg {
					t.Errorf("error message = %v, want %v", err.Error(), tc.wantErrMsg)
				}
			}
		})
	}
}

func TestBuildServiceKey(t *testing.T) {
	tests := map[string]struct {
		service string
		profile string
		want    string
		wantErr bool
	}{
		"service only": {
			service: "github",
			want:    "sesh-totp/github",
		},
		"service with profile": {
			service: "github",
			profile: "work",
			want:    "sesh-totp/github/work",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := buildServiceKey(tc.service, tc.profile)
			if tc.wantErr && err == nil {
				t.Error("buildServiceKey() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("buildServiceKey() unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("buildServiceKey() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseServiceKey(t *testing.T) {
	tests := map[string]struct {
		serviceKey  string
		wantService string
		wantProfile string
	}{
		"service only": {
			serviceKey:  "sesh-totp/github",
			wantService: "github",
			wantProfile: "",
		},
		"service with profile": {
			serviceKey:  "sesh-totp/github/work",
			wantService: "github",
			wantProfile: "work",
		},
		"invalid prefix": {
			serviceKey:  "invalid-key",
			wantService: "invalid-key",
			wantProfile: "",
		},
		"empty string": {
			serviceKey:  "",
			wantService: "",
			wantProfile: "",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			service, profile := parseServiceKey(tc.serviceKey)
			if service != tc.wantService {
				t.Errorf("parseServiceKey() service = %v, want %v", service, tc.wantService)
			}
			if profile != tc.wantProfile {
				t.Errorf("parseServiceKey() profile = %v, want %v", profile, tc.wantProfile)
			}
		})
	}
}
