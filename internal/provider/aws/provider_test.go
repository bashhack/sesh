package aws

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/aws"
	awsMocks "github.com/bashhack/sesh/internal/aws/mocks"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/setup"
	"github.com/bashhack/sesh/internal/subshell"
	"github.com/bashhack/sesh/internal/testutil"
	"github.com/bashhack/sesh/internal/totp"
	totpMocks "github.com/bashhack/sesh/internal/totp/mocks"
	"github.com/bashhack/sesh/internal/vault"
)

const testDevice = "arn:aws:iam::123456789012:mfa/user"

// awsStore is a store holding profile's AWS entry with secret, and device
// as its MFA device ("" for none).
func awsStore(t *testing.T, profile, secret, device string) *vault.MemStore {
	t.Helper()
	store := vault.NewMemStore()
	e := vault.Entry{Key: vault.AWSKey(profile), Settings: vault.Settings{AWSMFADevice: device}}
	if err := store.Save(&e, []byte(secret)); err != nil {
		t.Fatal(err)
	}
	return store
}

// awsStoreWithCodes is awsStore for the default profile, with code settings.
func awsStoreWithCodes(t *testing.T, params totp.Params) *vault.MemStore {
	t.Helper()
	store := vault.NewMemStore()
	e := vault.Entry{Key: vault.AWSKey(""), Settings: vault.Settings{AWSMFADevice: testDevice, TOTP: params}}
	if err := store.Save(&e, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	return store
}

// failingStore is a store whose every read and delete fails with err.
type failingStore struct {
	*vault.MemStore
	err error
}

func (f failingStore) Get(vault.Key) ([]byte, error)            { return nil, f.err }
func (f failingStore) Lookup(vault.Key) (vault.Entry, error)    { return vault.Entry{}, f.err }
func (f failingStore) List(vault.Filter) ([]vault.Entry, error) { return nil, f.err }
func (f failingStore) Delete(vault.Key) error                   { return f.err }
func (f failingStore) DeleteMany([]vault.Key) error             { return f.err }

func TestNewProvider(t *testing.T) {
	mockAWS := &awsMocks.MockProvider{}
	store := vault.NewMemStore()
	mockTOTP := &totpMocks.MockProvider{}

	p := NewProvider(mockAWS, store, mockTOTP)

	if p == nil {
		t.Fatal("NewProvider() returned nil")
	}
	if p.aws != mockAWS {
		t.Error("AWS provider not set correctly")
	}
	if p.store != store {
		t.Error("store not set correctly")
	}
	if p.totp != mockTOTP {
		t.Error("TOTP provider not set correctly")
	}
}

func TestProvider_Name(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "aws" {
		t.Errorf("Name() = %v, want %v", got, "aws")
	}
}

func TestProvider_Description(t *testing.T) {
	p := &Provider{}
	want := "Amazon Web Services CLI authentication"
	if got := p.Description(); got != want {
		t.Errorf("Description() = %v, want %v", got, want)
	}
}

func TestProvider_SetupFlags(t *testing.T) {
	tests := map[string]struct {
		envProfile  string
		wantProfile string
		wantErr     bool
	}{
		"default flags with no env": {
			envProfile:  "",
			wantProfile: "",
		},
		"profile from environment": {
			envProfile:  "dev",
			wantProfile: "dev",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Setenv("AWS_PROFILE", tc.envProfile)

			p := &Provider{}

			fs := flag.NewFlagSet("test", flag.ContinueOnError)

			err := p.SetupFlags(fs)
			if tc.wantErr && err == nil {
				t.Error("SetupFlags() expected error but got nil")
				return
			}
			if !tc.wantErr && err != nil {
				t.Errorf("SetupFlags() unexpected error: %v", err)
				return
			}

			if err := fs.Parse([]string{}); err != nil {
				t.Errorf("Parse() error: %v", err)
			}

			if p.profile != tc.wantProfile {
				t.Errorf("profile = %v, want %v", p.profile, tc.wantProfile)
			}
			if p.noSubshell {
				t.Error("noSubshell should be false by default")
			}
		})
	}
}

func TestProvider_GetFlagInfo(t *testing.T) {
	p := &Provider{}
	flags := p.GetFlagInfo()

	if len(flags) != 3 || flags[2].Name != "force" || flags[2].Type != "bool" {
		t.Fatalf("GetFlagInfo() = %+v, want profile, no-subshell and force", flags)
	}

	if flags[0].Name != "profile" {
		t.Errorf("flag[0].Name = %v, want 'profile'", flags[0].Name)
	}
	if flags[0].Type != "string" {
		t.Errorf("flag[0].Type = %v, want 'string'", flags[0].Type)
	}
	if flags[0].Required {
		t.Error("profile flag should not be required")
	}

	if flags[1].Name != "no-subshell" {
		t.Errorf("flag[1].Name = %v, want 'no-subshell'", flags[1].Name)
	}
	if flags[1].Type != "bool" {
		t.Errorf("flag[1].Type = %v, want 'bool'", flags[1].Type)
	}
	if flags[1].Required {
		t.Error("no-subshell flag should not be required")
	}
}

func TestProvider_ShouldUseSubshell(t *testing.T) {
	tests := map[string]struct {
		noSubshell bool
		want       bool
	}{
		"default should use subshell": {
			noSubshell: false,
			want:       true,
		},
		"no-subshell flag set": {
			noSubshell: true,
			want:       false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p := &Provider{noSubshell: tc.noSubshell}
			if got := p.ShouldUseSubshell(); got != tc.want {
				t.Errorf("ShouldUseSubshell() = %v, want %v", got, tc.want)
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
	p := &Provider{store: vault.NewMemStore()}

	handler := p.GetSetupHandler()
	if _, ok := handler.(*setup.AWSSetupHandler); !ok {
		t.Errorf("GetSetupHandler() returned %T, want *setup.AWSSetupHandler", handler)
	}
}

func TestProvider_ValidateRequest(t *testing.T) {
	tests := map[string]struct {
		store       func(t *testing.T) vault.Store
		profile     string
		wantErrMsg  string
		wantWarning bool
	}{
		"valid request with default profile": {
			store: func(t *testing.T) vault.Store { return awsStore(t, "", "secret", testDevice) },
		},
		"valid request with custom profile": {
			profile: "dev",
			store:   func(t *testing.T) vault.Store { return awsStore(t, "dev", "secret", testDevice) },
		},
		"no entry for profile": {
			store:      func(t *testing.T) vault.Store { return awsStore(t, "dev", "secret", testDevice) },
			wantErrMsg: "no AWS entry found for profile (default). Run 'sesh --service aws --setup' first",
		},
		"store error surfaces without the setup hint": {
			store: func(*testing.T) vault.Store {
				return failingStore{MemStore: vault.NewMemStore(), err: errors.New("vault locked")}
			},
			wantErrMsg: "failed to look up the AWS entry: vault locked",
		},
		"no MFA device stored (warning only)": {
			store:       func(t *testing.T) vault.Store { return awsStore(t, "", "secret", "") },
			wantWarning: true,
		},
		"AWS's code settings spelled out": {
			store: func(t *testing.T) vault.Store {
				return awsStoreWithCodes(t, totp.Params{Issuer: "Amazon Web Services", Algorithm: "sha1", Digits: 6, Period: 30})
			},
		},
		"code settings AWS doesn't use": {
			store: func(t *testing.T) vault.Store {
				return awsStoreWithCodes(t, totp.Params{Algorithm: "SHA256", Digits: 8})
			},
			wantErrMsg: "the AWS entry for profile (default) has code settings AWS doesn't use (SHA256, 8 digits, 30s); set it up again with 'sesh --service aws --setup'",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			restore := testutil.RedirectStderr(t)
			p := &Provider{store: tc.store(t), profile: tc.profile}

			err := p.ValidateRequest()
			stderr := restore()
			switch {
			case tc.wantErrMsg == "" && err != nil:
				t.Errorf("ValidateRequest() unexpected error: %v", err)
			case tc.wantErrMsg != "" && (err == nil || err.Error() != tc.wantErrMsg):
				t.Errorf("ValidateRequest() = %v, want %q", err, tc.wantErrMsg)
			}
			if got := strings.Contains(stderr, "No MFA device stored"); got != tc.wantWarning {
				t.Errorf("stderr = %q, want the no-device warning: %v", stderr, tc.wantWarning)
			}
		})
	}
}

func TestProvider_GetTOTPCodes(t *testing.T) {
	tests := map[string]struct {
		store       func(t *testing.T) vault.Store
		setupTOTP   func(*totpMocks.MockProvider)
		profile     string
		wantCurrent string
		wantNext    string
		wantErr     bool
	}{
		"successful TOTP generation": {
			store: func(t *testing.T) vault.Store { return awsStore(t, "", "MYSECRET", testDevice) },
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
		"another profile's entry isn't used": {
			profile: "dev",
			store:   func(t *testing.T) vault.Store { return awsStore(t, "", "MYSECRET", testDevice) },
			setupTOTP: func(m *totpMocks.MockProvider) {
				m.GenerateConsecutiveCodesBytesFunc = func(secret []byte) (string, string, error) {
					t.Error("GenerateConsecutiveCodesBytes should not be called")
					return "", "", nil
				}
			},
			wantErr: true,
		},
		"store error": {
			store: func(*testing.T) vault.Store {
				return failingStore{MemStore: vault.NewMemStore(), err: errors.New("vault locked")}
			},
			setupTOTP: func(m *totpMocks.MockProvider) {
				m.GenerateConsecutiveCodesBytesFunc = func(secret []byte) (string, string, error) {
					t.Error("GenerateConsecutiveCodesBytes should not be called")
					return "", "", nil
				}
			},
			wantErr: true,
		},
		"TOTP generation error": {
			store: func(t *testing.T) vault.Store { return awsStore(t, "", "INVALIDSECRET", testDevice) },
			setupTOTP: func(m *totpMocks.MockProvider) {
				m.GenerateConsecutiveCodesBytesFunc = func(secret []byte) (string, string, error) {
					return "", "", errors.New("invalid secret")
				}
			},
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			defer testutil.DiscardStderr(t)()

			mockTOTP := &totpMocks.MockProvider{}
			tc.setupTOTP(mockTOTP)

			p := &Provider{store: tc.store(t), totp: mockTOTP, profile: tc.profile}

			current, next, secondsLeft, err := p.GetTOTPCodes()
			if tc.wantErr && err == nil {
				t.Error("GetTOTPCodes() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("GetTOTPCodes() unexpected error: %v", err)
			}
			if !tc.wantErr {
				if current != tc.wantCurrent {
					t.Errorf("current code = %v, want %v", current, tc.wantCurrent)
				}
				if next != tc.wantNext {
					t.Errorf("next code = %v, want %v", next, tc.wantNext)
				}
				if secondsLeft <= 0 || secondsLeft > 30 {
					t.Errorf("secondsLeft = %v, want between 1 and 30", secondsLeft)
				}
			}
		})
	}
}

func TestProvider_GetMFASerialBytes(t *testing.T) {
	tests := map[string]struct {
		store      func(t *testing.T) vault.Store
		setupAWS   func(*awsMocks.MockProvider)
		profile    string
		wantSerial string
		wantErr    bool
	}{
		"device in the entry's settings": {
			store: func(t *testing.T) vault.Store { return awsStore(t, "", "s", testDevice) },
			setupAWS: func(m *awsMocks.MockProvider) {
				m.GetFirstMFADeviceFunc = func(profile string) (string, error) {
					t.Error("GetFirstMFADevice should not be called when the device is stored")
					return "", nil
				}
			},
			wantSerial: testDevice,
		},
		"no device stored - auto-detect": {
			profile: "dev",
			store:   func(t *testing.T) vault.Store { return awsStore(t, "dev", "s", "") },
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
		"no entry - auto-detect": {
			profile: "dev",
			store:   func(t *testing.T) vault.Store { return awsStore(t, "", "s", testDevice) },
			setupAWS: func(m *awsMocks.MockProvider) {
				m.GetFirstMFADeviceFunc = func(profile string) (string, error) {
					return "arn:aws:iam::123456789012:mfa/auto-detected", nil
				}
			},
			wantSerial: "arn:aws:iam::123456789012:mfa/auto-detected",
		},
		"auto-detect fails": {
			store: func(t *testing.T) vault.Store { return awsStore(t, "", "s", "") },
			setupAWS: func(m *awsMocks.MockProvider) {
				m.GetFirstMFADeviceFunc = func(profile string) (string, error) {
					return "", errors.New("no MFA device found")
				}
			},
			wantErr: true,
		},
		"store error surfaces without fallback": {
			store: func(*testing.T) vault.Store {
				return failingStore{MemStore: vault.NewMemStore(), err: errors.New("vault locked")}
			},
			setupAWS: func(m *awsMocks.MockProvider) {
				m.GetFirstMFADeviceFunc = func(profile string) (string, error) {
					t.Error("GetFirstMFADevice should not be called on a store error other than not found")
					return "", nil
				}
			},
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			mockAWS := &awsMocks.MockProvider{}
			tc.setupAWS(mockAWS)

			p := &Provider{aws: mockAWS, store: tc.store(t), profile: tc.profile}

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

func TestProvider_GetCredentials(t *testing.T) {
	tests := map[string]struct {
		now         func() time.Time
		setupTOTP   func(*totpMocks.MockProvider)
		setupAWS    func(*awsMocks.MockProvider)
		checkResult func(*testing.T, provider.Credentials)
		profile     string
		device      string // the MFA device stored with the entry; "" for none
		wantErr     bool
	}{
		"successful credential generation": {
			profile: "",
			device:  testDevice,
			setupTOTP: func(m *totpMocks.MockProvider) {
				m.GenerateConsecutiveCodesBytesFunc = func(secret []byte) (string, string, error) {
					return "123456", "654321", nil
				}
			},
			setupAWS: func(m *awsMocks.MockProvider) {
				m.GetSessionTokenFunc = func(profile, serial string, code []byte) (aws.Credentials, error) {
					if profile == "" && serial == "arn:aws:iam::123456789012:mfa/user" && string(code) == "123456" {
						return aws.Credentials{
							AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
							SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
							SessionToken:    "AQoDYXdzEJr...",
							Expiration:      time.Now().Add(time.Hour).Format(time.RFC3339),
						}, nil
					}
					return aws.Credentials{}, fmt.Errorf("unexpected call")
				}
			},
			wantErr: false,
			checkResult: func(t *testing.T, creds provider.Credentials) {
				if creds.Provider != "aws" {
					t.Errorf("Provider = %v, want 'aws'", creds.Provider)
				}
				if !creds.MFAAuthenticated {
					t.Error("MFAAuthenticated should be true")
				}
				if len(creds.Variables) != 3 {
					t.Errorf("Variables count = %d, want 3", len(creds.Variables))
				}
				if _, ok := creds.Variables["AWS_ACCESS_KEY_ID"]; !ok {
					t.Error("Missing AWS_ACCESS_KEY_ID")
				}
				if _, ok := creds.Variables["AWS_SECRET_ACCESS_KEY"]; !ok {
					t.Error("Missing AWS_SECRET_ACCESS_KEY")
				}
				if _, ok := creds.Variables["AWS_SESSION_TOKEN"]; !ok {
					t.Error("Missing AWS_SESSION_TOKEN")
				}
			},
		},
		"no MFA device stored - auto-detect": {
			profile: "",
			setupTOTP: func(m *totpMocks.MockProvider) {
				m.GenerateConsecutiveCodesBytesFunc = func(secret []byte) (string, string, error) {
					return "123456", "654321", nil
				}
			},
			setupAWS: func(m *awsMocks.MockProvider) {
				m.GetFirstMFADeviceFunc = func(profile string) (string, error) {
					return "arn:aws:iam::123456789012:mfa/autodetected", nil
				}
				m.GetSessionTokenFunc = func(profile, serial string, code []byte) (aws.Credentials, error) {
					if profile == "" && serial == "arn:aws:iam::123456789012:mfa/autodetected" && string(code) == "123456" {
						return aws.Credentials{
							AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
							SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
							SessionToken:    "AQoDYXdzEJr...",
							Expiration:      time.Now().Add(time.Hour).Format(time.RFC3339),
						}, nil
					}
					return aws.Credentials{}, fmt.Errorf("unexpected call")
				}
			},
			wantErr: false,
		},
		"retry with next code on invalid MFA": {
			profile: "",
			device:  testDevice,
			setupTOTP: func(m *totpMocks.MockProvider) {
				m.GenerateConsecutiveCodesBytesFunc = func(secret []byte) (string, string, error) {
					return "123456", "654321", nil
				}
			},
			setupAWS: func(m *awsMocks.MockProvider) {
				callCount := 0
				m.GetSessionTokenFunc = func(profile, serial string, code []byte) (aws.Credentials, error) {
					callCount++
					if callCount == 1 && string(code) == "123456" {
						return aws.Credentials{}, fmt.Errorf("MultiFactorAuthentication failed with invalid MFA one time pass code")
					}
					if callCount == 2 && string(code) == "654321" {
						return aws.Credentials{
							AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
							SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
							SessionToken:    "AQoDYXdzEJr...",
							Expiration:      time.Now().Add(time.Hour).Format(time.RFC3339),
						}, nil
					}
					return aws.Credentials{}, fmt.Errorf("unexpected call")
				}
			},
			wantErr: false,
		},
		"second attempt non-MFA error skips future-window retry": {
			profile: "",
			device:  testDevice,
			setupTOTP: func(m *totpMocks.MockProvider) {
				m.GenerateConsecutiveCodesBytesFunc = func(secret []byte) (string, string, error) {
					return "123456", "654321", nil
				}
				m.GenerateForTimeBytesFunc = func(secret []byte, _ time.Time) (string, error) {
					return "", fmt.Errorf("GenerateForTimeBytes should not be called when second error is not invalid MFA")
				}
			},
			setupAWS: func(m *awsMocks.MockProvider) {
				callCount := 0
				m.GetSessionTokenFunc = func(profile, serial string, code []byte) (aws.Credentials, error) {
					callCount++
					if callCount == 1 {
						return aws.Credentials{}, fmt.Errorf("MultiFactorAuthentication failed with invalid MFA one time pass code")
					}
					// Second attempt fails with a different error
					return aws.Credentials{}, fmt.Errorf("network timeout")
				}
			},
			wantErr: true,
		},
		"both MFA codes rejected triggers future-window retry": {
			profile: "",
			now: func() time.Time {
				// Second 5 of a 30s window → freshSecondsLeft = 25
				return time.Unix(5, 0)
			},
			device: testDevice,
			setupTOTP: func(m *totpMocks.MockProvider) {
				m.GenerateConsecutiveCodesBytesFunc = func(secret []byte) (string, string, error) {
					return "123456", "654321", nil
				}
				m.GenerateForTimeBytesFunc = func(secret []byte, _ time.Time) (string, error) {
					return "999999", nil
				}
			},
			setupAWS: func(m *awsMocks.MockProvider) {
				callCount := 0
				m.GetSessionTokenFunc = func(profile, serial string, code []byte) (aws.Credentials, error) {
					callCount++
					if callCount <= 2 {
						return aws.Credentials{}, fmt.Errorf("MultiFactorAuthentication failed with invalid MFA one time pass code")
					}
					if string(code) == "999999" {
						return aws.Credentials{
							AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
							SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
							SessionToken:    "AQoDYXdzEJr...",
							Expiration:      time.Now().Add(time.Hour).Format(time.RFC3339),
						}, nil
					}
					return aws.Credentials{}, fmt.Errorf("unexpected call")
				}
			},
			wantErr: false,
			checkResult: func(t *testing.T, creds provider.Credentials) {
				if !creds.MFAAuthenticated {
					t.Error("MFAAuthenticated should be true after future-window retry")
				}
			},
		},
		"both codes fail": {
			profile: "",
			device:  testDevice,
			setupTOTP: func(m *totpMocks.MockProvider) {
				m.GenerateConsecutiveCodesBytesFunc = func(secret []byte) (string, string, error) {
					return "123456", "654321", nil
				}
			},
			setupAWS: func(m *awsMocks.MockProvider) {
				m.GetSessionTokenFunc = func(profile, serial string, code []byte) (aws.Credentials, error) {
					return aws.Credentials{}, errors.New("access denied")
				}
			},
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			defer testutil.DiscardStderr(t)()

			mockTOTP := &totpMocks.MockProvider{}
			mockAWS := &awsMocks.MockProvider{}
			tc.setupTOTP(mockTOTP)
			tc.setupAWS(mockAWS)

			p := &Provider{
				aws:     mockAWS,
				store:   awsStore(t, tc.profile, "MYSECRET", tc.device),
				totp:    mockTOTP,
				profile: tc.profile,
				Now:     tc.now,
			}

			creds, err := p.GetCredentials()
			if tc.wantErr && err == nil {
				t.Error("GetCredentials() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("GetCredentials() unexpected error: %v", err)
			}
			if !tc.wantErr && tc.checkResult != nil {
				tc.checkResult(t, creds)
			}
		})
	}
}

func TestProvider_GetClipboardValue(t *testing.T) {
	mockTOTP := &totpMocks.MockProvider{
		GenerateConsecutiveCodesBytesFunc: func(secret []byte) (string, string, error) {
			if string(secret) == "MYSECRET" {
				return "123456", "654321", nil
			}
			return "", "", fmt.Errorf("unexpected secret")
		},
	}

	defer testutil.DiscardStderr(t)()

	p := &Provider{store: awsStore(t, "", "MYSECRET", testDevice), totp: mockTOTP}

	creds, err := p.GetClipboardValue()
	if err != nil {
		t.Errorf("GetClipboardValue() unexpected error: %v", err)
	}
	if creds.Provider != "aws" {
		t.Errorf("Provider = %v, want 'aws'", creds.Provider)
	}
	if creds.CopyValue != "123456" {
		t.Errorf("CopyValue = %v, want '123456'", creds.CopyValue)
	}
	if !strings.Contains(creds.DisplayInfo, "123456") {
		t.Errorf("DisplayInfo should contain current code")
	}
	if !strings.Contains(creds.DisplayInfo, "AWS MFA code") {
		t.Errorf("DisplayInfo should contain 'AWS MFA code'")
	}
	if creds.ClipboardDescription != "AWS MFA code" {
		t.Errorf("ClipboardDescription = %v, want 'AWS MFA code'", creds.ClipboardDescription)
	}
}

func TestProvider_NewSubshellConfig(t *testing.T) {
	p := &Provider{}
	creds := provider.Credentials{
		Provider: "aws",
		Expiry:   time.Now().Add(time.Hour),
		Variables: map[string]string{
			"AWS_ACCESS_KEY_ID":     "AKIAIOSFODNN7EXAMPLE",
			"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			"AWS_SESSION_TOKEN":     "AQoDYXdzEJr...",
		},
	}

	config := p.NewSubshellConfig(&creds)
	sc, ok := config.(subshell.Config)
	if !ok {
		t.Fatal("NewSubshellConfig() did not return subshell.Config")
	}
	if sc.ServiceName != "aws" {
		t.Errorf("ServiceName = %v, want 'aws'", sc.ServiceName)
	}
	if len(sc.Variables) != 3 {
		t.Errorf("Variables count = %d, want 3", len(sc.Variables))
	}
	if sc.ShellCustomizer == nil {
		t.Error("ShellCustomizer should not be nil")
	}
}

func TestProvider_ListEntries(t *testing.T) {
	tests := map[string]struct {
		store       func(t *testing.T) vault.Store
		checkResult func(*testing.T, []provider.ProviderEntry)
		wantCount   int
		wantErr     bool
	}{
		"multiple profiles": {
			store: func(t *testing.T) vault.Store {
				store := awsStore(t, "", "s", testDevice)
				for _, profile := range []string{"dev", "prod"} {
					if err := store.Save(&vault.Entry{Key: vault.AWSKey(profile)}, []byte("s")); err != nil {
						t.Fatal(err)
					}
				}
				// A TOTP entry named aws with no username isn't a profile.
				if err := store.Save(&vault.Entry{Kind: vault.KindTOTP, Service: "aws"}, []byte("s")); err != nil {
					t.Fatal(err)
				}
				return store
			},
			wantCount: 3,
			checkResult: func(t *testing.T, entries []provider.ProviderEntry) {
				if entries[0].Name != "AWS (default)" {
					t.Errorf("entries[0].Name = %v, want 'AWS (default)'", entries[0].Name)
				}
				if entries[0].Description != "AWS MFA for profile (default)" {
					t.Errorf("entries[0].Description = %v, want 'AWS MFA for profile (default)'", entries[0].Description)
				}
				if entries[0].ID != "totp/aws/default" {
					t.Errorf("entries[0].ID = %v, want 'totp/aws/default'", entries[0].ID)
				}
				if entries[2].Name != "AWS (prod)" || entries[2].ID != "totp/aws/prod" {
					t.Errorf("entries[2] = %+v, want AWS (prod), totp/aws/prod", entries[2])
				}
			},
		},
		"other entries are left out": {
			store: func(t *testing.T) vault.Store {
				store := awsStore(t, "", "s", testDevice)
				for _, k := range []vault.Key{
					{Kind: vault.KindTOTP, Service: "github", Username: "alice"},
					{Kind: vault.KindTOTP, Service: "aws-console", Username: "admin"},
					{Kind: vault.KindPassword, Service: "aws", Username: "default"},
				} {
					if err := store.Put(k, []byte("s")); err != nil {
						t.Fatal(err)
					}
				}
				return store
			},
			wantCount: 1,
			checkResult: func(t *testing.T, entries []provider.ProviderEntry) {
				if entries[0].ID != "totp/aws/default" {
					t.Errorf("entries[0].ID = %v, want 'totp/aws/default'", entries[0].ID)
				}
			},
		},
		"empty list": {
			store:     func(*testing.T) vault.Store { return vault.NewMemStore() },
			wantCount: 0,
		},
		"store error": {
			store: func(*testing.T) vault.Store {
				return failingStore{MemStore: vault.NewMemStore(), err: errors.New("vault locked")}
			},
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p := &Provider{store: tc.store(t)}

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
	github := vault.Key{Kind: vault.KindTOTP, Service: "github"}
	tests := map[string]struct {
		store      func(t *testing.T) vault.Store
		id         string
		wantGone   vault.Key // deleted by the call
		wantErrSub string
	}{
		"default profile": {
			id:       "totp/aws/default",
			store:    func(t *testing.T) vault.Store { return awsStore(t, "", "s", testDevice) },
			wantGone: vault.AWSKey(""),
		},
		"named profile": {
			id:       "totp/aws/dev",
			store:    func(t *testing.T) vault.Store { return awsStore(t, "dev", "s", testDevice) },
			wantGone: vault.AWSKey("dev"),
		},
		"missing entry": {
			id:         "totp/aws/prod",
			store:      func(t *testing.T) vault.Store { return awsStore(t, "", "s", testDevice) },
			wantErrSub: "entry not found: totp/aws/prod",
		},
		"store error": {
			id: "totp/aws/default",
			store: func(*testing.T) vault.Store {
				return failingStore{MemStore: vault.NewMemStore(), err: errors.New("vault locked")}
			},
			wantErrSub: "vault locked",
		},
		"invalid ID format": {
			id:         "invalid-id",
			store:      func(t *testing.T) vault.Store { return awsStore(t, "", "s", testDevice) },
			wantErrSub: "want kind/service",
		},
		"another TOTP entry": {
			id:         "totp/github",
			store:      func(t *testing.T) vault.Store { return awsStore(t, "", "s", testDevice) },
			wantErrSub: "isn't an AWS entry",
		},
		"a password named aws": {
			id:         "password/aws/default",
			store:      func(t *testing.T) vault.Store { return awsStore(t, "", "s", testDevice) },
			wantErrSub: "isn't an AWS entry",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			store := tc.store(t)
			// An unrelated entry that no delete may touch.
			if ms, ok := store.(*vault.MemStore); ok {
				if err := ms.Put(github, []byte("s")); err != nil {
					t.Fatal(err)
				}
			}
			p := &Provider{store: store}

			err := deleteOne(p, tc.id)
			if tc.wantErrSub == "" && err != nil {
				t.Errorf("DeleteEntry() unexpected error: %v", err)
			}
			if tc.wantErrSub != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErrSub)) {
				t.Errorf("DeleteEntry() = %v, want it to contain %q", err, tc.wantErrSub)
			}
			ms, ok := store.(*vault.MemStore)
			if !ok {
				return
			}
			if tc.wantGone != (vault.Key{}) {
				if _, err := ms.Lookup(tc.wantGone); !errors.Is(err, vault.ErrNotFound) {
					t.Errorf("%s is still there: %v", tc.wantGone, err)
				}
			}
			entries, err := ms.List(vault.Filter{})
			if err != nil {
				t.Fatal(err)
			}
			want := 2 // the AWS entry and github
			if tc.wantGone != (vault.Key{}) {
				want = 1
			}
			if len(entries) != want {
				t.Errorf("%d entries left, want %d: %+v", len(entries), want, entries)
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
			defer func() {
				if err := os.RemoveAll(tmpDir); err != nil {
					t.Errorf("failed to clean up tmpDir: %v", err)
				}
			}()

			awsDir := filepath.Join(tmpDir, ".aws")
			if err := os.MkdirAll(awsDir, 0o700); err != nil {
				t.Fatalf("Failed to create .aws dir: %v", err)
			}

			configPath := filepath.Join(awsDir, "config")
			if err := os.WriteFile(configPath, []byte(tc.configContent), 0o600); err != nil {
				t.Fatalf("Failed to write config file: %v", err)
			}

			t.Setenv("HOME", tmpDir)

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
		defer func() {
			if err := os.RemoveAll(tmpDir); err != nil {
				t.Errorf("failed to clean up tmpDir: %v", err)
			}
		}()

		t.Setenv("HOME", tmpDir)

		p := &Provider{}

		_, err = p.getAWSProfiles()
		if err == nil {
			t.Error("getAWSProfiles() expected error when config doesn't exist")
		}
	})
}

func TestFormatProfile(t *testing.T) {
	tests := map[string]struct {
		profile string
		want    string
	}{
		"empty profile": {
			profile: "",
			want:    "profile (default)",
		},
		"custom profile": {
			profile: "dev",
			want:    "profile (dev)",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := formatProfile(tc.profile)
			if got != tc.want {
				t.Errorf("formatProfile() = %v, want %v", got, tc.want)
			}
		})
	}
}

// deleteOne deletes the entry id names, answering yes when asked.
func deleteOne(p *Provider, id string) error {
	_, err := p.DeleteEntries([]string{id}, func([]string) (bool, error) { return true, nil })
	return err
}
