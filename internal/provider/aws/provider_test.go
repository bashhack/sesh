package aws

import (
	"errors"
	"flag"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/aws"
	awsMocks "github.com/bashhack/sesh/internal/aws/mocks"
	"github.com/bashhack/sesh/internal/provider"
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

func (f failingStore) Get(vault.Key) ([]byte, error)             { return nil, f.err }
func (f failingStore) Lookup(vault.Key) (vault.Entry, error)     { return vault.Entry{}, f.err }
func (f failingStore) Exists(vault.Key) error                    { return f.err }
func (f failingStore) List(*vault.Filter) ([]vault.Entry, error) { return nil, f.err }
func (f failingStore) Delete(vault.Key) error                    { return f.err }
func (f failingStore) DeleteMany([]vault.Key) error              { return f.err }

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

	if len(flags) != 4 || flags[0].Name != "profile" || flags[1].Name != "no-subshell" || flags[2].Name != "folder" || flags[3].Name != "tag" {
		t.Fatalf("GetFlagInfo() = %+v, want profile, no-subshell, folder and tag", flags)
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
			wantErrMsg: "no AWS entry found for profile (default). Run 'sesh aws setup' first",
		},
		"store error surfaces without the setup hint": {
			store: func(*testing.T) vault.Store {
				return failingStore{MemStore: vault.NewMemStore(), err: errors.New("vault locked")}
			},
			wantErrMsg: "failed to look up the AWS entry: vault locked",
		},
		"no MFA device stored (warning only)": {
			// Said only when AWS is asked for the device (not for --clip).
			store:       func(t *testing.T) vault.Store { return awsStore(t, "", "secret", "") },
			wantWarning: false,
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
			wantErrMsg: "the AWS entry for profile (default) has code settings AWS doesn't use (SHA256, 8 digits, 30s); set it up again with 'sesh aws setup'",
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

// testClock is a clock that sleeping moves on, and codes that name their
// 30-second window, so a test can tell which window's code AWS was given.
type testClock struct {
	now   time.Time
	slept []time.Duration
}

func (c *testClock) Now() time.Time { return c.now }

func (c *testClock) Sleep(d time.Duration) {
	c.slept = append(c.slept, d)
	c.now = c.now.Add(d)
}

func windowCode(t time.Time) string { return fmt.Sprintf("w%d", t.Unix()/30) }

// GetCredentials asks AWS with the current code; when AWS refuses it, it
// waits for the next window and tries once with that window's code.
func TestProvider_GetCredentials(t *testing.T) {
	session := aws.Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "AQoDYXdzEJr...",
		Expiration:      "2026-10-16T13:00:00Z",
	}
	refused := fmt.Errorf("aws sts get-session-token: An error occurred (AccessDenied) when calling the GetSessionToken operation: %s", aws.InvalidMFAMessage)
	start := time.Date(2026, 10, 16, 12, 0, 20, 0, time.UTC) // 10s left in its window
	first, next := windowCode(start), windowCode(start.Add(30*time.Second))

	tests := map[string]struct {
		device    string  // the MFA device stored with the entry; "" for none
		wantSub   string  // in the error; "" for none
		answers   []error // AWS's answer to each try; nil is a session
		wantCodes []string
		wantSlept []time.Duration
	}{
		"accepted":               {answers: []error{nil}, device: testDevice, wantCodes: []string{first}},
		"device asked of AWS":    {answers: []error{nil}, wantCodes: []string{first}},
		"refused, then the next": {answers: []error{refused, nil}, device: testDevice, wantCodes: []string{first, next}, wantSlept: []time.Duration{11 * time.Second}},
		"refused twice": {answers: []error{refused, refused}, device: testDevice, wantCodes: []string{first, next}, wantSlept: []time.Duration{11 * time.Second},
			wantSub: "AWS refused the next code too. Just after sesh aws setup"},
		"temporary credentials": {answers: []error{fmt.Errorf("aws sts get-session-token: An error occurred (AccessDenied) when calling the GetSessionToken operation: %s", aws.SessionCredentialsMessage)},
			device: testDevice, wantCodes: []string{first}, wantSub: "signs in with temporary credentials (aws login, SSO or a role)"},
		"refused, then another error": {answers: []error{refused, errors.New("network timeout")}, device: testDevice, wantCodes: []string{first, next}, wantSlept: []time.Duration{11 * time.Second},
			wantSub: "failed to get session token: network timeout"},
		"another error isn't tried again": {answers: []error{errors.New("ExpiredToken: the security token included in the request is expired")}, device: testDevice, wantCodes: []string{first},
			wantSub: "ExpiredToken"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			defer testutil.DiscardStderr(t)()
			clock := &testClock{now: start}
			var codes []string
			mockAWS := &awsMocks.MockProvider{
				GetFirstMFADeviceFunc: func(string) (string, error) { return testDevice, nil },
				GetSessionTokenFunc: func(profile, serial string, code []byte) (aws.Credentials, error) {
					if serial != testDevice {
						t.Errorf("serial = %q", serial)
					}
					codes = append(codes, string(code))
					if err := tc.answers[len(codes)-1]; err != nil {
						return aws.Credentials{}, err
					}
					return session, nil
				},
			}
			mockTOTP := &totpMocks.MockProvider{
				GenerateForTimeBytesFunc: func(secret []byte, at time.Time) (string, error) {
					if string(secret) != "MYSECRET" {
						return "", fmt.Errorf("secret = %q", secret)
					}
					return windowCode(at), nil
				},
			}
			p := &Provider{aws: mockAWS, store: awsStore(t, "", "MYSECRET", tc.device), totp: mockTOTP, Sleep: clock.Sleep}
			p.Now = clock.Now

			creds, err := p.GetCredentials()
			if tc.wantSub == "" && err != nil || tc.wantSub != "" && (err == nil || !strings.Contains(err.Error(), tc.wantSub)) {
				t.Fatalf("GetCredentials() = %v, want an error containing %q", err, tc.wantSub)
			}
			if !slices.Equal(codes, tc.wantCodes) || !slices.Equal(clock.slept, tc.wantSlept) {
				t.Errorf("codes tried %q after sleeping %v; want %q after %v", codes, clock.slept, tc.wantCodes, tc.wantSlept)
			}
			if err == nil && (!creds.MFAAuthenticated || creds.Variables["AWS_SESSION_TOKEN"] != session.SessionToken || !creds.Expiry.Equal(time.Date(2026, 10, 16, 13, 0, 0, 0, time.UTC))) {
				t.Errorf("creds = %+v", creds)
			}
		})
	}
}

// The wait after a refused code ends in the next window, from either end
// of the window it was refused in.
func TestProvider_GetCredentials_WaitAtWindowEdges(t *testing.T) {
	defer testutil.DiscardStderr(t)()
	for _, tc := range []struct {
		at   time.Time
		want time.Duration
	}{
		{time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC), 31 * time.Second},
		{time.Date(2026, 10, 16, 12, 0, 29, 999_000_000, time.UTC), 2 * time.Second},
	} {
		clock := &testClock{now: tc.at}
		var codes []string
		mockAWS := &awsMocks.MockProvider{
			GetSessionTokenFunc: func(_, _ string, code []byte) (aws.Credentials, error) {
				codes = append(codes, string(code))
				if len(codes) == 1 {
					return aws.Credentials{}, fmt.Errorf("aws sts get-session-token: %s", aws.InvalidMFAMessage)
				}
				return aws.Credentials{SessionToken: "t", Expiration: "2026-10-16T13:00:00Z"}, nil
			},
		}
		mockTOTP := &totpMocks.MockProvider{GenerateForTimeBytesFunc: func(_ []byte, at time.Time) (string, error) { return windowCode(at), nil }}
		p := &Provider{aws: mockAWS, store: awsStore(t, "", "MYSECRET", testDevice), totp: mockTOTP, Sleep: clock.Sleep}
		p.Now = clock.Now
		if _, err := p.GetCredentials(); err != nil {
			t.Fatalf("at %s: %v", tc.at.Format("05.000"), err)
		}
		next := windowCode(tc.at.Truncate(30 * time.Second).Add(30 * time.Second))
		if !slices.Equal(clock.slept, []time.Duration{tc.want}) || codes[1] != next {
			t.Errorf("at %s: slept %v and sent %q; want %v and the next window's %q", tc.at.Format("05.000"), clock.slept, codes[1], tc.want, next)
		}
	}
}

// The profile is --profile, else AWS_PROFILE, else AWS_DEFAULT_PROFILE, as
// the AWS CLI reads them.
func TestProvider_ProfileFromEnvironment(t *testing.T) {
	for _, tc := range []struct{ profile, defaultProfile, want string }{
		{"work", "old", "work"},
		{"", "old", "old"},
		{"", "", ""},
	} {
		t.Setenv("AWS_PROFILE", tc.profile)
		t.Setenv("AWS_DEFAULT_PROFILE", tc.defaultProfile)
		p := NewProvider(nil, nil, nil)
		fs := flag.NewFlagSet("aws", flag.ContinueOnError)
		if err := p.SetupFlags(fs); err != nil {
			t.Fatal(err)
		}
		if err := fs.Parse(nil); err != nil {
			t.Fatal(err)
		}
		if got := p.GetProfile(); got != tc.want {
			t.Errorf("AWS_PROFILE=%q AWS_DEFAULT_PROFILE=%q: profile %q, want %q", tc.profile, tc.defaultProfile, got, tc.want)
		}
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
