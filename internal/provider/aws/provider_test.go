package aws

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/aws"
	awsMocks "github.com/bashhack/sesh/internal/aws/mocks"
	"github.com/bashhack/sesh/internal/keychain"
	keychainMocks "github.com/bashhack/sesh/internal/keychain/mocks"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/totp"
	totpMocks "github.com/bashhack/sesh/internal/totp/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestProvider_Name(t *testing.T) {
	p := &Provider{}
	assert.Equal(t, "aws", p.Name())
}

func TestProvider_Description(t *testing.T) {
	p := &Provider{}
	assert.Equal(t, "Amazon Web Services CLI authentication", p.Description())
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

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			// Set up environment
			if test.envProfile != "" {
				os.Setenv("AWS_PROFILE", test.envProfile)
				defer os.Unsetenv("AWS_PROFILE")
			}

			// Create provider
			p := &Provider{}

			// Create flag set
			fs := flag.NewFlagSet("test", flag.ContinueOnError)

			// Setup flags
			err := p.SetupFlags(fs)
			if test.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			// Parse empty args to get defaults
			err = fs.Parse([]string{})
			assert.NoError(t, err)

			// Check values
			assert.Equal(t, test.wantProfile, p.profile)
			assert.False(t, p.noSubshell)
			assert.NotEmpty(t, p.keyUser) // Should be set to current user
		})
	}
}

func TestProvider_GetFlagInfo(t *testing.T) {
	p := &Provider{}
	flags := p.GetFlagInfo()

	assert.Len(t, flags, 2)

	// Check profile flag
	assert.Equal(t, "profile", flags[0].Name)
	assert.Equal(t, "string", flags[0].Type)
	assert.False(t, flags[0].Required)

	// Check no-subshell flag
	assert.Equal(t, "no-subshell", flags[1].Name)
	assert.Equal(t, "bool", flags[1].Type)
	assert.False(t, flags[1].Required)
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

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			p := &Provider{noSubshell: test.noSubshell}
			assert.Equal(t, test.want, p.ShouldUseSubshell())
		})
	}
}

func TestProvider_ValidateRequest(t *testing.T) {
	tests := map[string]struct {
		profile       string
		setupKeychain func(*keychainMocks.SecureKeychain)
		wantErr       bool
		wantErrMsg    string
	}{
		"valid request with default profile": {
			profile: "",
			setupKeychain: func(m *keychainMocks.SecureKeychain) {
				// TOTP secret exists
				m.On("GetSecret", mock.Anything, "sesh-aws-default").
					Return([]byte("secret"), nil)
				// MFA serial exists
				m.On("GetSecret", mock.Anything, "sesh-aws-mfa-default").
					Return([]byte("arn:aws:iam::123456789012:mfa/user"), nil)
			},
			wantErr: false,
		},
		"valid request with custom profile": {
			profile: "dev",
			setupKeychain: func(m *keychainMocks.SecureKeychain) {
				// TOTP secret exists
				m.On("GetSecret", mock.Anything, "sesh-aws-dev").
					Return([]byte("secret"), nil)
				// MFA serial exists
				m.On("GetSecret", mock.Anything, "sesh-aws-mfa-dev").
					Return([]byte("arn:aws:iam::123456789012:mfa/user"), nil)
			},
			wantErr: false,
		},
		"no TOTP secret for profile": {
			profile: "",
			setupKeychain: func(m *keychainMocks.SecureKeychain) {
				// TOTP secret does not exist
				m.On("GetSecret", mock.Anything, "sesh-aws-default").
					Return(nil, errors.New("not found"))
			},
			wantErr:    true,
			wantErrMsg: "no AWS entry found for profile 'default'. Run 'sesh --service aws --setup' first",
		},
		"no MFA serial (warning only)": {
			profile: "",
			setupKeychain: func(m *keychainMocks.SecureKeychain) {
				// TOTP secret exists
				m.On("GetSecret", mock.Anything, "sesh-aws-default").
					Return([]byte("secret"), nil)
				// MFA serial does not exist
				m.On("GetSecret", mock.Anything, "sesh-aws-mfa-default").
					Return(nil, errors.New("not found"))
			},
			wantErr: false, // Should just warn, not error
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			// Create mocks
			mockKeychain := new(keychainMocks.SecureKeychain)
			test.setupKeychain(mockKeychain)

			// Create provider
			p := &Provider{
				keychain: mockKeychain,
				profile:  test.profile,
				keyUser:  "testuser",
				keyName:  "sesh-aws",
			}

			// Test ValidateRequest
			err := p.ValidateRequest()
			if test.wantErr {
				assert.Error(t, err)
				if test.wantErrMsg != "" {
					assert.Contains(t, err.Error(), test.wantErrMsg)
				}
			} else {
				assert.NoError(t, err)
			}

			mockKeychain.AssertExpectations(t)
		})
	}
}

func TestProvider_GetTOTPCodes(t *testing.T) {
	tests := map[string]struct {
		profile       string
		setupKeychain func(*keychainMocks.SecureKeychain)
		setupTOTP     func(*totpMocks.Service)
		wantErr       bool
		wantCurrent   string
		wantNext      string
	}{
		"successful TOTP generation": {
			profile: "",
			setupKeychain: func(m *keychainMocks.SecureKeychain) {
				m.On("GetSecret", "testuser", "sesh-aws-default").
					Return([]byte("MYSECRET"), nil)
			},
			setupTOTP: func(m *totpMocks.Service) {
				m.On("GenerateConsecutiveCodesBytes", []byte("MYSECRET")).
					Return("123456", "654321", nil)
			},
			wantCurrent: "123456",
			wantNext:    "654321",
		},
		"keychain error": {
			profile: "",
			setupKeychain: func(m *keychainMocks.SecureKeychain) {
				m.On("GetSecret", "testuser", "sesh-aws-default").
					Return(nil, errors.New("keychain locked"))
			},
			setupTOTP: func(m *totpMocks.Service) {},
			wantErr:   true,
		},
		"TOTP generation error": {
			profile: "",
			setupKeychain: func(m *keychainMocks.SecureKeychain) {
				m.On("GetSecret", "testuser", "sesh-aws-default").
					Return([]byte("INVALIDSECRET"), nil)
			},
			setupTOTP: func(m *totpMocks.Service) {
				m.On("GenerateConsecutiveCodesBytes", []byte("INVALIDSECRET")).
					Return("", "", errors.New("invalid secret"))
			},
			wantErr: true,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			// Create mocks
			mockKeychain := new(keychainMocks.SecureKeychain)
			mockTOTP := new(totpMocks.Service)
			test.setupKeychain(mockKeychain)
			test.setupTOTP(mockTOTP)

			// Create provider
			p := &Provider{
				keychain: mockKeychain,
				totp:     mockTOTP,
				profile:  test.profile,
				keyUser:  "testuser",
				keyName:  "sesh-aws",
			}

			// Test GetTOTPCodes
			current, next, secondsLeft, err := p.GetTOTPCodes()
			if test.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.wantCurrent, current)
				assert.Equal(t, test.wantNext, next)
				assert.Greater(t, secondsLeft, int64(0))
				assert.LessOrEqual(t, secondsLeft, int64(30))
			}

			mockKeychain.AssertExpectations(t)
			mockTOTP.AssertExpectations(t)
		})
	}
}

func TestProvider_GetCredentials(t *testing.T) {
	// This is a complex integration test - we'll test the key scenarios
	tests := map[string]struct {
		profile       string
		setupKeychain func(*keychainMocks.SecureKeychain)
		setupTOTP     func(*totpMocks.Service)
		setupAWS      func(*awsMocks.Provider)
		wantErr       bool
		checkResult   func(*testing.T, provider.Credentials)
	}{
		"successful credential generation": {
			profile: "",
			setupKeychain: func(m *keychainMocks.SecureKeychain) {
				// GetMFASerialBytes flow
				m.On("GetSecret", "testuser", "sesh-aws-mfa-default").
					Return([]byte("arn:aws:iam::123456789012:mfa/user"), nil)
				// GetTOTPCodes flow
				m.On("GetSecret", "testuser", "sesh-aws-default").
					Return([]byte("MYSECRET"), nil)
			},
			setupTOTP: func(m *totpMocks.Service) {
				m.On("GenerateConsecutiveCodesBytes", []byte("MYSECRET")).
					Return("123456", "654321", nil)
			},
			setupAWS: func(m *awsMocks.Provider) {
				creds := aws.Credentials{
					AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
					SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
					SessionToken:    "AQoDYXdzEJr...",
					Expiry:          time.Now().Add(time.Hour),
				}
				m.On("GetSessionToken", "", "arn:aws:iam::123456789012:mfa/user", []byte("123456")).
					Return(creds, nil)
			},
			wantErr: false,
			checkResult: func(t *testing.T, creds provider.Credentials) {
				assert.Equal(t, "aws", creds.Provider)
				assert.True(t, creds.MFAAuthenticated)
				assert.Len(t, creds.Variables, 3) // Should have 3 AWS env vars
				assert.Contains(t, creds.Variables, "AWS_ACCESS_KEY_ID")
				assert.Contains(t, creds.Variables, "AWS_SECRET_ACCESS_KEY")
				assert.Contains(t, creds.Variables, "AWS_SESSION_TOKEN")
			},
		},
		"MFA serial not in keychain - auto-detect": {
			profile: "",
			setupKeychain: func(m *keychainMocks.SecureKeychain) {
				// GetMFASerialBytes - not found in keychain
				m.On("GetSecret", "testuser", "sesh-aws-mfa-default").
					Return(nil, errors.New("not found"))
				// GetTOTPCodes flow
				m.On("GetSecret", "testuser", "sesh-aws-default").
					Return([]byte("MYSECRET"), nil)
			},
			setupTOTP: func(m *totpMocks.Service) {
				m.On("GenerateConsecutiveCodesBytes", []byte("MYSECRET")).
					Return("123456", "654321", nil)
			},
			setupAWS: func(m *awsMocks.Provider) {
				// Auto-detect MFA device
				m.On("GetFirstMFADevice", "").
					Return("arn:aws:iam::123456789012:mfa/autodetected", nil)
				// Then get session token
				creds := aws.Credentials{
					AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
					SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
					SessionToken:    "AQoDYXdzEJr...",
					Expiry:          time.Now().Add(time.Hour),
				}
				m.On("GetSessionToken", "", "arn:aws:iam::123456789012:mfa/autodetected", []byte("123456")).
					Return(creds, nil)
			},
			wantErr: false,
		},
		"retry with next code on invalid MFA": {
			profile: "",
			setupKeychain: func(m *keychainMocks.SecureKeychain) {
				// GetMFASerialBytes flow
				m.On("GetSecret", "testuser", "sesh-aws-mfa-default").
					Return([]byte("arn:aws:iam::123456789012:mfa/user"), nil)
				// GetTOTPCodes flow
				m.On("GetSecret", "testuser", "sesh-aws-default").
					Return([]byte("MYSECRET"), nil)
			},
			setupTOTP: func(m *totpMocks.Service) {
				m.On("GenerateConsecutiveCodesBytes", []byte("MYSECRET")).
					Return("123456", "654321", nil)
			},
			setupAWS: func(m *awsMocks.Provider) {
				// First attempt fails with invalid MFA
				m.On("GetSessionToken", "", "arn:aws:iam::123456789012:mfa/user", []byte("123456")).
					Return(aws.Credentials{}, fmt.Errorf("MultiFactorAuthentication failed with invalid MFA one time pass code"))
				// Second attempt succeeds
				creds := aws.Credentials{
					AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
					SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
					SessionToken:    "AQoDYXdzEJr...",
					Expiry:          time.Now().Add(time.Hour),
				}
				m.On("GetSessionToken", "", "arn:aws:iam::123456789012:mfa/user", []byte("654321")).
					Return(creds, nil)
			},
			wantErr: false,
		},
		"both codes fail": {
			profile: "",
			setupKeychain: func(m *keychainMocks.SecureKeychain) {
				// GetMFASerialBytes flow
				m.On("GetSecret", "testuser", "sesh-aws-mfa-default").
					Return([]byte("arn:aws:iam::123456789012:mfa/user"), nil)
				// GetTOTPCodes flow
				m.On("GetSecret", "testuser", "sesh-aws-default").
					Return([]byte("MYSECRET"), nil)
			},
			setupTOTP: func(m *totpMocks.Service) {
				m.On("GenerateConsecutiveCodesBytes", []byte("MYSECRET")).
					Return("123456", "654321", nil)
			},
			setupAWS: func(m *awsMocks.Provider) {
				// Both attempts fail
				m.On("GetSessionToken", "", "arn:aws:iam::123456789012:mfa/user", []byte("123456")).
					Return(aws.Credentials{}, errors.New("access denied"))
				m.On("GetSessionToken", "", "arn:aws:iam::123456789012:mfa/user", []byte("654321")).
					Return(aws.Credentials{}, errors.New("access denied"))
			},
			wantErr: true,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			// Redirect stderr to capture debug output
			oldStderr := os.Stderr
			_, w, _ := os.Pipe()
			os.Stderr = w
			defer func() {
				w.Close()
				os.Stderr = oldStderr
			}()

			// Create mocks
			mockKeychain := new(keychainMocks.SecureKeychain)
			mockTOTP := new(totpMocks.Service)
			mockAWS := new(awsMocks.Provider)
			test.setupKeychain(mockKeychain)
			test.setupTOTP(mockTOTP)
			test.setupAWS(mockAWS)

			// Create provider
			p := &Provider{
				aws:      mockAWS,
				keychain: mockKeychain,
				totp:     mockTOTP,
				profile:  test.profile,
				keyUser:  "testuser",
				keyName:  "sesh-aws",
			}

			// Test GetCredentials
			creds, err := p.GetCredentials()
			if test.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if test.checkResult != nil {
					test.checkResult(t, creds)
				}
			}

			mockKeychain.AssertExpectations(t)
			mockTOTP.AssertExpectations(t)
			mockAWS.AssertExpectations(t)
		})
	}
}

func TestProvider_GetClipboardValue(t *testing.T) {
	// Create mocks
	mockKeychain := new(keychainMocks.SecureKeychain)
	mockTOTP := new(totpMocks.Service)

	// Setup expectations
	mockKeychain.On("GetSecret", "testuser", "sesh-aws-default").
		Return([]byte("MYSECRET"), nil)
	mockTOTP.On("GenerateConsecutiveCodesBytes", []byte("MYSECRET")).
		Return("123456", "654321", nil)

	// Create provider
	p := &Provider{
		keychain: mockKeychain,
		totp:     mockTOTP,
		profile:  "",
		keyUser:  "testuser",
		keyName:  "sesh-aws",
	}

	// Test GetClipboardValue
	creds, err := p.GetClipboardValue()
	assert.NoError(t, err)
	assert.Equal(t, "aws", creds.Provider)
	assert.True(t, creds.DisplayInfo.IsClipboard)
	assert.Equal(t, "123456", creds.DisplayInfo.ClipboardValue)
	assert.Equal(t, "AWS MFA code", creds.DisplayInfo.ClipboardTitle)

	mockKeychain.AssertExpectations(t)
	mockTOTP.AssertExpectations(t)
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
	assert.NotNil(t, config)
	// We can't easily test the internals of the config without exposing them
	// but we can verify it returns something
}

func TestBuildServiceKey(t *testing.T) {
	tests := map[string]struct {
		prefix  string
		profile string
		want    string
	}{
		"default profile": {
			prefix:  "sesh-aws",
			profile: "",
			want:    "sesh-aws-default",
		},
		"custom profile": {
			prefix:  "sesh-aws",
			profile: "dev",
			want:    "sesh-aws-dev",
		},
		"MFA prefix with profile": {
			prefix:  "sesh-aws-mfa",
			profile: "prod",
			want:    "sesh-aws-mfa-prod",
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			got := buildServiceKey(test.prefix, test.profile)
			assert.Equal(t, test.want, got)
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

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			got := formatProfile(test.profile)
			assert.Equal(t, test.want, got)
		})
	}
}