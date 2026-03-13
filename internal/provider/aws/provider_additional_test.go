package aws

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	awsMocks "github.com/bashhack/sesh/internal/aws/mocks"
	"github.com/bashhack/sesh/internal/keychain"
	keychainMocks "github.com/bashhack/sesh/internal/keychain/mocks"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/setup"
	totpMocks "github.com/bashhack/sesh/internal/totp/mocks"
)

func TestNewProvider(t *testing.T) {
	mockAWS := &awsMocks.MockProvider{}
	mockKeychain := &keychainMocks.MockProvider{}
	mockTOTP := &totpMocks.MockProvider{}

	p := NewProvider(mockAWS, mockKeychain, mockTOTP)

	if p == nil {
		t.Fatal("NewProvider() returned nil")
	}
	if p.aws != mockAWS {
		t.Error("AWS provider not set correctly")
	}
	if p.keychain != mockKeychain {
		t.Error("Keychain provider not set correctly")
	}
	if p.totp != mockTOTP {
		t.Error("TOTP provider not set correctly")
	}
	if p.keyName != "sesh-aws" {
		t.Errorf("keyName = %v, want 'sesh-aws'", p.keyName)
	}
}

func TestParseServiceKey(t *testing.T) {
	tests := map[string]struct {
		serviceKey string
		want       string
	}{
		"default profile": {
			serviceKey: "sesh-aws/default",
			want:       "default",
		},
		"custom profile": {
			serviceKey: "sesh-aws/production",
			want:       "production",
		},
		"hyphenated profile": {
			serviceKey: "sesh-aws/dev-test",
			want:       "dev-test",
		},
		"invalid prefix": {
			serviceKey: "invalid-prefix-default",
			want:       "",
		},
		"empty string": {
			serviceKey: "",
			want:       "",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := parseServiceKey(tc.serviceKey)
			if got != tc.want {
				t.Errorf("parseServiceKey(%q) = %v, want %v", tc.serviceKey, got, tc.want)
			}
		})
	}
}

func TestProvider_GetProfile(t *testing.T) {
	tests := map[string]struct {
		profile string
		want    string
	}{
		"default profile": {
			profile: "",
			want:    "",
		},
		"custom profile": {
			profile: "dev",
			want:    "dev",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p := &Provider{profile: tc.profile}
			if got := p.GetProfile(); got != tc.want {
				t.Errorf("GetProfile() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestProvider_GetSetupHandler(t *testing.T) {
	mockKeychain := &keychainMocks.MockProvider{}
	p := &Provider{keychain: mockKeychain}

	handler := p.GetSetupHandler()
	if _, ok := handler.(*setup.AWSSetupHandler); !ok {
		t.Errorf("GetSetupHandler() returned %T, want *setup.AWSSetupHandler", handler)
	}
}

func TestProvider_GetTOTPKeyInfo(t *testing.T) {
	tests := map[string]struct {
		profile  string
		keyUser  string
		wantUser string
		wantKey  string
		wantErr  bool
	}{
		"default profile with preset user": {
			profile:  "",
			keyUser:  "testuser",
			wantUser: "testuser",
			wantKey:  "sesh-aws/default",
		},
		"custom profile with preset user": {
			profile:  "dev",
			keyUser:  "testuser",
			wantUser: "testuser",
			wantKey:  "sesh-aws/dev",
		},
		"unset user - should get current": {
			profile:  "",
			keyUser:  "",
			wantUser: "", // Will be set by env.GetCurrentUser
			wantKey:  "sesh-aws/default",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p := &Provider{
				profile: tc.profile,
				keyUser: tc.keyUser,
				keyName: "sesh-aws",
			}

			user, key, err := p.GetTOTPKeyInfo()
			if tc.wantErr && err == nil {
				t.Error("GetTOTPKeyInfo() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("GetTOTPKeyInfo() unexpected error: %v", err)
			}
			if !tc.wantErr {
				if tc.wantUser != "" && user != tc.wantUser {
					t.Errorf("user = %v, want %v", user, tc.wantUser)
				}
				if tc.wantUser == "" && user == "" {
					t.Error("user should have been set by env.GetCurrentUser")
				}
				if key != tc.wantKey {
					t.Errorf("key = %v, want %v", key, tc.wantKey)
				}
			}
		})
	}
}

func TestProvider_GetMFASerialBytes(t *testing.T) {
	tests := map[string]struct {
		profile       string
		keyUser       string
		setupKeychain func(*keychainMocks.MockProvider)
		setupAWS      func(*awsMocks.MockProvider)
		wantSerial    string
		wantErr       bool
	}{
		"serial in keychain": {
			profile: "",
			keyUser: "testuser",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.GetSecretFunc = func(account, service string) ([]byte, error) {
					if account == "testuser" && service == "sesh-aws-serial/default" {
						return []byte("arn:aws:iam::123456789012:mfa/user"), nil
					}
					return nil, fmt.Errorf("unexpected call: %s, %s", account, service)
				}
			},
			setupAWS: func(m *awsMocks.MockProvider) {
				// Should not be called
				m.GetFirstMFADeviceFunc = func(profile string) (string, error) {
					t.Error("GetFirstMFADevice should not be called when serial is in keychain")
					return "", nil
				}
			},
			wantSerial: "arn:aws:iam::123456789012:mfa/user",
		},
		"serial not in keychain - auto-detect": {
			profile: "dev",
			keyUser: "testuser",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.GetSecretFunc = func(account, service string) ([]byte, error) {
					return nil, errors.New("not found")
				}
			},
			setupAWS: func(m *awsMocks.MockProvider) {
				m.GetFirstMFADeviceFunc = func(profile string) (string, error) {
					if profile == "dev" {
						return "arn:aws:iam::123456789012:mfa/auto-detected", nil
					}
					return "", fmt.Errorf("unexpected profile: %s", profile)
				}
			},
			wantSerial: "arn:aws:iam::123456789012:mfa/auto-detected",
		},
		"auto-detect fails": {
			profile: "",
			keyUser: "testuser",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.GetSecretFunc = func(account, service string) ([]byte, error) {
					return nil, errors.New("not found")
				}
			},
			setupAWS: func(m *awsMocks.MockProvider) {
				m.GetFirstMFADeviceFunc = func(profile string) (string, error) {
					return "", errors.New("no MFA device found")
				}
			},
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
					mockKeychain := &keychainMocks.MockProvider{}
			mockAWS := &awsMocks.MockProvider{}
			tc.setupKeychain(mockKeychain)
			tc.setupAWS(mockAWS)

					p := &Provider{
				aws:      mockAWS,
				keychain: mockKeychain,
				profile:  tc.profile,
				keyUser:  tc.keyUser,
			}

			serialBytes, err := p.GetMFASerialBytes()
			if tc.wantErr && err == nil {
				t.Error("GetMFASerialBytes() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("GetMFASerialBytes() unexpected error: %v", err)
			}
			if !tc.wantErr {
				if string(serialBytes) != tc.wantSerial {
					t.Errorf("serial = %v, want %v", string(serialBytes), tc.wantSerial)
				}
			}
		})
	}
}

func TestProvider_ListEntries(t *testing.T) {
	tests := map[string]struct {
		setupKeychain func(*keychainMocks.MockProvider)
		wantErr       bool
		wantCount     int
		checkResult   func(*testing.T, []provider.ProviderEntry)
	}{
		"successful list with multiple profiles": {
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.ListEntriesFunc = func(prefix string) ([]keychain.KeychainEntry, error) {
					if prefix != "sesh-aws" {
						return nil, fmt.Errorf("unexpected prefix: %s", prefix)
					}
					return []keychain.KeychainEntry{
						{Service: "sesh-aws/default", Account: "user1"},
						{Service: "sesh-aws/dev", Account: "user1"},
						{Service: "sesh-aws/prod", Account: "user2"},
						{Service: "sesh-aws-serial/default", Account: "user1"},
						{Service: "sesh-aws-serial/dev", Account: "user1"},
					}, nil
				}
			},
			wantCount: 3,
			checkResult: func(t *testing.T, entries []provider.ProviderEntry) {
				// Check first entry
				if entries[0].Name != "AWS (default)" {
					t.Errorf("entries[0].Name = %v, want 'AWS (default)'", entries[0].Name)
				}
				if entries[0].Description != "AWS MFA for profile (default)" {
					t.Errorf("entries[0].Description = %v, want 'AWS MFA for profile (default)'", entries[0].Description)
				}
				if entries[0].ID != "sesh-aws/default:user1" {
					t.Errorf("entries[0].ID = %v, want 'sesh-aws/default:user1'", entries[0].ID)
				}

				// Check second entry
				if entries[1].Name != "AWS (dev)" {
					t.Errorf("entries[1].Name = %v, want 'AWS (dev)'", entries[1].Name)
				}
				if entries[1].ID != "sesh-aws/dev:user1" {
					t.Errorf("entries[1].ID = %v, want 'sesh-aws/dev:user1'", entries[1].ID)
				}
			},
		},
		"serial entries filtered from results": {
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.ListEntriesFunc = func(prefix string) ([]keychain.KeychainEntry, error) {
					if prefix != "sesh-aws" {
						return nil, fmt.Errorf("unexpected prefix: %s", prefix)
					}
					return []keychain.KeychainEntry{
						{Service: "sesh-aws/default", Account: "user1"},
						{Service: "sesh-aws-serial/default", Account: "user1"},
						{Service: "sesh-aws-serial/dev", Account: "user1"},
					}, nil
				}
			},
			wantCount: 1,
			checkResult: func(t *testing.T, entries []provider.ProviderEntry) {
				if entries[0].Name != "AWS (default)" {
					t.Errorf("entries[0].Name = %v, want 'AWS (default)'", entries[0].Name)
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
					return nil, errors.New("keychain locked")
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
					t.Errorf("ListEntries() returned %d entries, want %d", len(entries), tc.wantCount)
				}
				if tc.checkResult != nil {
					tc.checkResult(t, entries)
				}
			}
		})
	}
}

func TestProvider_DeleteEntry(t *testing.T) {
	tests := map[string]struct {
		id            string
		setupKeychain func(*keychainMocks.MockProvider)
		wantErr       bool
		wantErrMsg    string
	}{
		"successful delete": {
			id: "sesh-aws/default:testuser",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				deleteCalls := 0
				m.DeleteEntryFunc = func(account, service string) error {
					deleteCalls++
					switch deleteCalls {
					case 1:
						if account != "testuser" || service != "sesh-aws/default" {
							return fmt.Errorf("unexpected call 1: %s, %s", account, service)
						}
						return nil
					case 2:
						if account != "testuser" || service != "sesh-aws-serial/default" {
							return fmt.Errorf("unexpected call 2: %s, %s", account, service)
						}
						return nil
					default:
						return fmt.Errorf("unexpected delete call #%d", deleteCalls)
					}
				}
			},
		},
		"delete with profile": {
			id: "sesh-aws/dev:testuser",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				deleteCalls := 0
				m.DeleteEntryFunc = func(account, service string) error {
					deleteCalls++
					switch deleteCalls {
					case 1:
						if account != "testuser" || service != "sesh-aws/dev" {
							return fmt.Errorf("unexpected call 1: %s, %s", account, service)
						}
						return nil
					case 2:
						if account != "testuser" || service != "sesh-aws-serial/dev" {
							return fmt.Errorf("unexpected call 2: %s, %s", account, service)
						}
						return nil
					default:
						return fmt.Errorf("unexpected delete call #%d", deleteCalls)
					}
				}
			},
		},
		"main delete fails": {
			id: "sesh-aws/default:testuser",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.DeleteEntryFunc = func(account, service string) error {
					return errors.New("keychain locked")
				}
			},
			wantErr: true,
		},
		"serial delete fails - should not error": {
			id: "sesh-aws/default:testuser",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				deleteCalls := 0
				m.DeleteEntryFunc = func(account, service string) error {
					deleteCalls++
					if deleteCalls == 1 {
						return nil // Main delete succeeds
					}
					return errors.New("serial delete failed") // Serial delete fails
				}
			},
			wantErr: false, // Should still succeed
		},
		"invalid ID format": {
			id: "invalid-id",
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
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Capture stderr to suppress warning output
			oldStderr := os.Stderr
			_, w, _ := os.Pipe()
			os.Stderr = w
			defer func() {
				w.Close()
				os.Stderr = oldStderr
			}()

			mockKeychain := &keychainMocks.MockProvider{}
			tc.setupKeychain(mockKeychain)

					p := &Provider{keychain: mockKeychain}

			err := p.DeleteEntry(tc.id)
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

func TestProvider_getAWSProfiles(t *testing.T) {
	tests := map[string]struct {
		configContent string
		wantProfiles  []string
		wantErr       bool
	}{
		"standard config file": {
			configContent: `[default]
region = us-east-1

[profile dev]
region = us-west-2

[profile production]
region = eu-west-1
`,
			wantProfiles: []string{"default", "dev", "production"},
		},
		"empty config file": {
			configContent: "",
			wantProfiles:  []string{"default"}, // Always includes default
		},
		"config with comments and extra spaces": {
			configContent: `# This is a comment
[default]
region = us-east-1

# Dev profile
[profile  dev  ]
region = us-west-2

[profile staging]
# Another comment
region = ap-southeast-1
`,
			wantProfiles: []string{"default", "dev", "staging"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "sesh-test-*")
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			awsDir := filepath.Join(tmpDir, ".aws")
			if err := os.MkdirAll(awsDir, 0700); err != nil {
				t.Fatalf("Failed to create .aws dir: %v", err)
			}

			configPath := filepath.Join(awsDir, "config")
			if err := os.WriteFile(configPath, []byte(tc.configContent), 0600); err != nil {
				t.Fatalf("Failed to write config file: %v", err)
			}

			oldHome := os.Getenv("HOME")
			os.Setenv("HOME", tmpDir)
			defer os.Setenv("HOME", oldHome)

					p := &Provider{}

			profiles, err := p.getAWSProfiles()
			if tc.wantErr && err == nil {
				t.Error("getAWSProfiles() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("getAWSProfiles() unexpected error: %v", err)
			}
			if !tc.wantErr {
				if len(profiles) != len(tc.wantProfiles) {
					t.Errorf("got %d profiles, want %d", len(profiles), len(tc.wantProfiles))
				}
				for i, want := range tc.wantProfiles {
					if i >= len(profiles) {
						break
					}
					if profiles[i] != want {
						t.Errorf("profiles[%d] = %v, want %v", i, profiles[i], want)
					}
				}
			}
		})
	}

	t.Run("no config file", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "sesh-test-*")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		oldHome := os.Getenv("HOME")
		os.Setenv("HOME", tmpDir)
		defer os.Setenv("HOME", oldHome)

			p := &Provider{}

		_, err = p.getAWSProfiles()
		if err == nil {
			t.Error("getAWSProfiles() expected error when config doesn't exist")
		}
	})
}
