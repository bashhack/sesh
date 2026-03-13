package aws

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/aws"
	awsMocks "github.com/bashhack/sesh/internal/aws/mocks"
	keychainMocks "github.com/bashhack/sesh/internal/keychain/mocks"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/subshell"
	totpMocks "github.com/bashhack/sesh/internal/totp/mocks"
)

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
			if tc.envProfile != "" {
				os.Setenv("AWS_PROFILE", tc.envProfile)
				defer os.Unsetenv("AWS_PROFILE")
			}

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
			if p.keyUser == "" {
				t.Error("keyUser should be set to current user")
			}
		})
	}
}

func TestProvider_GetFlagInfo(t *testing.T) {
	p := &Provider{}
	flags := p.GetFlagInfo()

	if len(flags) != 2 {
		t.Errorf("GetFlagInfo() returned %d flags, want 2", len(flags))
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

func TestProvider_ValidateRequest(t *testing.T) {
	tests := map[string]struct {
		profile       string
		setupKeychain func(*keychainMocks.MockProvider)
		wantErr       bool
		wantErrMsg    string
	}{
		"valid request with default profile": {
			profile: "",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.GetSecretFunc = func(account, service string) ([]byte, error) {
					switch service {
					case "sesh-aws/default":
						return []byte("secret"), nil
					case "sesh-aws-serial/default":
						return []byte("arn:aws:iam::123456789012:mfa/user"), nil
					default:
						return nil, fmt.Errorf("unexpected service: %s", service)
					}
				}
			},
			wantErr: false,
		},
		"valid request with custom profile": {
			profile: "dev",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.GetSecretFunc = func(account, service string) ([]byte, error) {
					switch service {
					case "sesh-aws/dev":
						return []byte("secret"), nil
					case "sesh-aws-serial/dev":
						return []byte("arn:aws:iam::123456789012:mfa/user"), nil
					default:
						return nil, fmt.Errorf("unexpected service: %s", service)
					}
				}
			},
			wantErr: false,
		},
		"no TOTP secret for profile": {
			profile: "",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.GetSecretFunc = func(account, service string) ([]byte, error) {
					return nil, errors.New("not found")
				}
			},
			wantErr:    true,
			wantErrMsg: "no AWS entry found for profile 'default'. Run 'sesh --service aws --setup' first",
		},
		"no MFA serial (warning only)": {
			profile: "",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.GetSecretFunc = func(account, service string) ([]byte, error) {
					if service == "sesh-aws/default" {
						return []byte("secret"), nil
					}
					// MFA serial not found
					return nil, errors.New("not found")
				}
			},
			wantErr: false, // Should just warn, not error
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

			p := &Provider{
				keychain: mockKeychain,
				profile:  tc.profile,
				keyUser:  "testuser",
				keyName:  "sesh-aws",
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

func TestProvider_GetTOTPCodes(t *testing.T) {
	tests := map[string]struct {
		profile       string
		setupKeychain func(*keychainMocks.MockProvider)
		setupTOTP     func(*totpMocks.MockProvider)
		wantErr       bool
		wantCurrent   string
		wantNext      string
	}{
		"successful TOTP generation": {
			profile: "",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.GetSecretFunc = func(account, service string) ([]byte, error) {
					if account == "testuser" && service == "sesh-aws/default" {
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
			profile: "",
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
			profile: "",
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

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Capture stderr to suppress debug output
			oldStderr := os.Stderr
			_, w, _ := os.Pipe()
			os.Stderr = w
			defer func() {
				w.Close()
				os.Stderr = oldStderr
			}()

			mockKeychain := &keychainMocks.MockProvider{}
			mockTOTP := &totpMocks.MockProvider{}
			tc.setupKeychain(mockKeychain)
			tc.setupTOTP(mockTOTP)

			p := &Provider{
				keychain: mockKeychain,
				totp:     mockTOTP,
				profile:  tc.profile,
				keyUser:  "testuser",
				keyName:  "sesh-aws",
			}

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

func TestProvider_GetCredentials(t *testing.T) {
	tests := map[string]struct {
		profile       string
		setupKeychain func(*keychainMocks.MockProvider)
		setupTOTP     func(*totpMocks.MockProvider)
		setupAWS      func(*awsMocks.MockProvider)
		wantErr       bool
		checkResult   func(*testing.T, provider.Credentials)
	}{
		"successful credential generation": {
			profile: "",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.GetSecretFunc = func(account, service string) ([]byte, error) {
					switch service {
					case "sesh-aws-serial/default":
						return []byte("arn:aws:iam::123456789012:mfa/user"), nil
					case "sesh-aws/default":
						return []byte("MYSECRET"), nil
					default:
						return nil, fmt.Errorf("unexpected service: %s", service)
					}
				}
			},
			setupTOTP: func(m *totpMocks.MockProvider) {
				m.GenerateConsecutiveCodesBytesFunc = func(secret []byte) (string, string, error) {
					return "123456", "654321", nil
				}
			},
			setupAWS: func(m *awsMocks.MockProvider) {
				m.GetSessionTokenFunc = func(profile, serial string, code []byte) (aws.Credentials, error) {
					if profile == "" && serial == "arn:aws:iam::123456789012:mfa/user" && string(code) == "123456" {
						return aws.Credentials{
							AccessKeyId:     "AKIAIOSFODNN7EXAMPLE",
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
		"MFA serial not in keychain - auto-detect": {
			profile: "",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.GetSecretFunc = func(account, service string) ([]byte, error) {
					switch service {
					case "sesh-aws-serial/default":
						return nil, errors.New("not found")
					case "sesh-aws/default":
						return []byte("MYSECRET"), nil
					default:
						return nil, fmt.Errorf("unexpected service: %s", service)
					}
				}
			},
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
							AccessKeyId:     "AKIAIOSFODNN7EXAMPLE",
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
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.GetSecretFunc = func(account, service string) ([]byte, error) {
					switch service {
					case "sesh-aws-serial/default":
						return []byte("arn:aws:iam::123456789012:mfa/user"), nil
					case "sesh-aws/default":
						return []byte("MYSECRET"), nil
					default:
						return nil, fmt.Errorf("unexpected service: %s", service)
					}
				}
			},
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
							AccessKeyId:     "AKIAIOSFODNN7EXAMPLE",
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
		"both codes fail": {
			profile: "",
			setupKeychain: func(m *keychainMocks.MockProvider) {
				m.GetSecretFunc = func(account, service string) ([]byte, error) {
					switch service {
					case "sesh-aws-serial/default":
						return []byte("arn:aws:iam::123456789012:mfa/user"), nil
					case "sesh-aws/default":
						return []byte("MYSECRET"), nil
					default:
						return nil, fmt.Errorf("unexpected service: %s", service)
					}
				}
			},
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
			// Redirect stderr to capture debug output
			oldStderr := os.Stderr
			_, w, _ := os.Pipe()
			os.Stderr = w
			defer func() {
				w.Close()
				os.Stderr = oldStderr
			}()

			mockKeychain := &keychainMocks.MockProvider{}
			mockTOTP := &totpMocks.MockProvider{}
			mockAWS := &awsMocks.MockProvider{}
			tc.setupKeychain(mockKeychain)
			tc.setupTOTP(mockTOTP)
			tc.setupAWS(mockAWS)

			p := &Provider{
				aws:      mockAWS,
				keychain: mockKeychain,
				totp:     mockTOTP,
				profile:  tc.profile,
				keyUser:  "testuser",
				keyName:  "sesh-aws",
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
	mockKeychain := &keychainMocks.MockProvider{
		GetSecretFunc: func(account, service string) ([]byte, error) {
			if account == "testuser" && service == "sesh-aws/default" {
				return []byte("MYSECRET"), nil
			}
			return nil, fmt.Errorf("unexpected call")
		},
	}
	mockTOTP := &totpMocks.MockProvider{
		GenerateConsecutiveCodesBytesFunc: func(secret []byte) (string, string, error) {
			if string(secret) == "MYSECRET" {
				return "123456", "654321", nil
			}
			return "", "", fmt.Errorf("unexpected secret")
		},
	}

	// Capture stderr to suppress debug output
	oldStderr := os.Stderr
	_, w, _ := os.Pipe()
	os.Stderr = w
	defer func() {
		w.Close()
		os.Stderr = oldStderr
	}()

	p := &Provider{
		keychain: mockKeychain,
		totp:     mockTOTP,
		profile:  "",
		keyUser:  "testuser",
		keyName:  "sesh-aws",
	}

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

	config := p.NewSubshellConfig(creds)
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

func TestBuildServiceKey(t *testing.T) {
	tests := map[string]struct {
		prefix  string
		profile string
		want    string
		wantErr bool
	}{
		"default profile": {
			prefix:  "sesh-aws",
			profile: "",
			want:    "sesh-aws/default",
		},
		"custom profile": {
			prefix:  "sesh-aws",
			profile: "dev",
			want:    "sesh-aws/dev",
		},
		"MFA prefix with profile": {
			prefix:  "sesh-aws-serial",
			profile: "prod",
			want:    "sesh-aws-serial/prod",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := buildServiceKey(tc.prefix, tc.profile)
			if tc.wantErr && err == nil {
				t.Error("buildServiceKey() expected error but got nil")
				return
			}
			if !tc.wantErr && err != nil {
				t.Errorf("buildServiceKey() unexpected error: %v", err)
				return
			}
			if got != tc.want {
				t.Errorf("buildServiceKey() = %v, want %v", got, tc.want)
			}
		})
	}
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
