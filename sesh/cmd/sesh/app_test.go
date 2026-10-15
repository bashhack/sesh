package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/clipboard"
	"github.com/bashhack/sesh/internal/provider"
)

// MockProvider is a mock implementation of provider.ServiceProvider
type MockProvider struct {
	NameFunc              func() string
	SetupFlagsFunc        func(fs provider.FlagSet) error
	GetCredentialsFunc    func() (provider.Credentials, error)
	GetClipboardValueFunc func() (provider.Credentials, error)
	ValidateRequestFunc   func() error
	GetFlagInfoFunc       func() []provider.FlagInfo
}

// Name implements provider.ServiceProvider
func (m *MockProvider) Name() string {
	if m.NameFunc != nil {
		return m.NameFunc()
	}
	return "mock"
}

// SetupFlags implements provider.ServiceProvider
func (m *MockProvider) SetupFlags(fs provider.FlagSet) error {
	if m.SetupFlagsFunc != nil {
		return m.SetupFlagsFunc(fs)
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
	app := NewDefaultApp(VersionInfo{Version: "test"}, AppSettings{ClipboardTimeout: 30 * time.Second})
	if app.ExecLookPath == nil || app.Exit == nil || app.ClipboardCopy == nil || app.ClipboardCheck == nil ||
		app.TimeNow == nil || app.Stdout == nil || app.Stderr == nil || app.StdinIsTerminal == nil {
		t.Errorf("an app function or stream is nil: %+v", app)
	}
	if app.settings.ClipboardTimeout != 30*time.Second {
		t.Errorf("settings = %+v", app.settings)
	}
}

func TestApp_GenerateCredentials(t *testing.T) {
	tests := map[string]struct {
		newProvider func() provider.ServiceProvider
		wantErrMsg  string
		wantStdout  []string
		wantStderr  []string
		wantErr     bool
	}{
		"successful generation": {
			newProvider: func() provider.ServiceProvider {
				mockProvider := &MockProvider{
					NameFunc:            func() string { return "totp" },
					ValidateRequestFunc: func() error { return nil },
					GetCredentialsFunc: func() (provider.Credentials, error) {
						return provider.Credentials{
							Provider:    "totp",
							DisplayInfo: "TOTP code: 123456",
							Variables:   map[string]string{},
						}, nil
					},
				}
				return mockProvider
			},
			wantStderr: []string{
				"Generating credentials for totp",
				"Credentials acquired",
				"TOTP code: 123456",
			},
		},
		"validate request error": {
			newProvider: func() provider.ServiceProvider {
				mockProvider := &MockProvider{
					NameFunc:            func() string { return "totp" },
					ValidateRequestFunc: func() error { return errors.New("missing --service-name") },
				}
				return mockProvider
			},
			wantErr:    true,
			wantErrMsg: "missing --service-name",
		},
		"get credentials error": {
			newProvider: func() provider.ServiceProvider {
				mockProvider := &MockProvider{
					NameFunc:            func() string { return "totp" },
					ValidateRequestFunc: func() error { return nil },
					GetCredentialsFunc: func() (provider.Credentials, error) {
						return provider.Credentials{}, errors.New("secret not found")
					},
				}
				return mockProvider
			},
			wantErr:    true,
			wantErrMsg: "failed to generate credentials",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			stdoutBuf := &bytes.Buffer{}
			stderrBuf := &bytes.Buffer{}
			app := &App{
				TimeNow: time.Now,
				Stdout:  stdoutBuf,
				Stderr:  stderrBuf,
			}
			err := app.GenerateCredentials(tc.newProvider())

			if tc.wantErr && err == nil {
				t.Error("GenerateCredentials() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("GenerateCredentials() unexpected error: %v", err)
			}
			if tc.wantErrMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tc.wantErrMsg) {
					t.Errorf("error message = %v, want to contain %v", err.Error(), tc.wantErrMsg)
				}
			}
			for _, expected := range tc.wantStdout {
				if !strings.Contains(stdoutBuf.String(), expected) {
					t.Errorf("stdout missing expected string: %q", expected)
				}
			}
			for _, expected := range tc.wantStderr {
				if !strings.Contains(stderrBuf.String(), expected) {
					t.Errorf("stderr missing expected string: %q", expected)
				}
			}
		})
	}
}

func TestApp_CopyToClipboard(t *testing.T) {
	tests := map[string]struct {
		clipboardErr error
		newProvider  func() provider.ServiceProvider
		wantErrMsg   string
		wantStderr   []string
		wantErr      bool
	}{
		"successful copy": {
			newProvider: func() provider.ServiceProvider {
				mockProvider := &MockProvider{
					NameFunc:            func() string { return "totp" },
					ValidateRequestFunc: func() error { return nil },
					GetClipboardValueFunc: func() (provider.Credentials, error) {
						return provider.Credentials{
							Provider:             "totp",
							CopyValue:            "123456",
							ClipboardDescription: "TOTP code",
							DisplayInfo:          "TOTP code for github",
						}, nil
					},
				}
				return mockProvider
			},
			wantStderr: []string{
				"Generating credentials for totp",
				"TOTP code copied to clipboard",
				"TOTP code for github",
			},
		},
		"validate request error": {
			newProvider: func() provider.ServiceProvider {
				mockProvider := &MockProvider{
					NameFunc:            func() string { return "totp" },
					ValidateRequestFunc: func() error { return errors.New("missing --service-name") },
				}
				return mockProvider
			},
			wantErr:    true,
			wantErrMsg: "missing --service-name",
		},
		"get clipboard value error": {
			newProvider: func() provider.ServiceProvider {
				mockProvider := &MockProvider{
					NameFunc:            func() string { return "totp" },
					ValidateRequestFunc: func() error { return nil },
					GetClipboardValueFunc: func() (provider.Credentials, error) {
						return provider.Credentials{}, errors.New("secret not found")
					},
				}
				return mockProvider
			},
			wantErr:    true,
			wantErrMsg: "failed to generate credentials",
		},
		"empty copy value": {
			newProvider: func() provider.ServiceProvider {
				mockProvider := &MockProvider{
					NameFunc:            func() string { return "totp" },
					ValidateRequestFunc: func() error { return nil },
					GetClipboardValueFunc: func() (provider.Credentials, error) {
						return provider.Credentials{CopyValue: ""}, nil
					},
				}
				return mockProvider
			},
			wantErr:    true,
			wantErrMsg: "no content available to copy to clipboard",
		},
		"clipboard copy error": {
			clipboardErr: errors.New("pbcopy failed"),
			newProvider: func() provider.ServiceProvider {
				mockProvider := &MockProvider{
					NameFunc:            func() string { return "totp" },
					ValidateRequestFunc: func() error { return nil },
					GetClipboardValueFunc: func() (provider.Credentials, error) {
						return provider.Credentials{CopyValue: "123456", ClipboardDescription: "TOTP code"}, nil
					},
				}
				return mockProvider
			},
			wantErr:    true,
			wantErrMsg: "failed to copy to clipboard",
		},
		"default clipboard description": {
			newProvider: func() provider.ServiceProvider {
				mockProvider := &MockProvider{
					NameFunc:            func() string { return "totp" },
					ValidateRequestFunc: func() error { return nil },
					GetClipboardValueFunc: func() (provider.Credentials, error) {
						return provider.Credentials{
							CopyValue:   "123456",
							DisplayInfo: "some info",
						}, nil
					},
				}
				return mockProvider
			},
			wantStderr: []string{
				"value copied to clipboard",
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			stderrBuf := &bytes.Buffer{}
			app := &App{
				Stdout: &bytes.Buffer{},
				Stderr: stderrBuf,
				ClipboardCopy: func(text string) error {
					return tc.clipboardErr
				},
			}
			err := app.CopyToClipboard(tc.newProvider())

			if tc.wantErr && err == nil {
				t.Error("CopyToClipboard() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("CopyToClipboard() unexpected error: %v", err)
			}
			if tc.wantErrMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tc.wantErrMsg) {
					t.Errorf("error message = %v, want to contain %v", err.Error(), tc.wantErrMsg)
				}
			}
			for _, expected := range tc.wantStderr {
				if !strings.Contains(stderrBuf.String(), expected) {
					t.Errorf("stderr missing expected string: %q", expected)
				}
			}
		})
	}
}

// clipCheckingMock is a provider that copies for only some requests.
type clipCheckingMock struct {
	*MockProvider
	checkClip func() error
}

func (m clipCheckingMock) CheckClip() error { return m.checkClip() }

// With no clipboard to copy to, --clip fails before fetching the secret,
// so nobody unlocks the vault or answers an MFA prompt for nothing. Over
// SSH it says what to do instead; a request the provider can't copy for is
// refused as that first.
func TestApp_CopyToClipboard_NoClipboard(t *testing.T) {
	showFlag := func() []provider.FlagInfo { return []provider.FlagInfo{{Name: "show", Type: "bool"}} }
	tests := map[string]struct {
		clipErr   error
		checkClip func() error
		flags     func() []provider.FlagInfo
		wantErr   string
	}{
		"over SSH, with --show": {clipErr: clipboard.ErrNoDisplay, flags: showFlag, wantErr: "can't copy: " + clipboard.ErrNoDisplay.Error() + "; use --show to print it instead"},
		"over SSH, no --show":   {clipErr: clipboard.ErrNoDisplay, wantErr: "can't copy: " + clipboard.ErrNoDisplay.Error() + "; run it without --clip"},
		"no tool":               {clipErr: &clipboard.MissingToolError{Install: "xclip or xsel"}, flags: showFlag, wantErr: "can't copy: no clipboard tool found: install xclip or xsel"},
		"request can't copy":    {clipErr: clipboard.ErrNoDisplay, checkClip: func() error { return errors.New("--clip works with --action get, not store") }, wantErr: "--clip works with --action get, not store"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fetched := false
			app := &App{
				Stdout:         &bytes.Buffer{},
				Stderr:         &bytes.Buffer{},
				ClipboardCheck: func() error { return tc.clipErr },
				ClipboardCopy:  func(string) error { return nil },
			}
			mock := &MockProvider{
				NameFunc:            func() string { return "totp" },
				ValidateRequestFunc: func() error { return nil },
				GetFlagInfoFunc:     tc.flags,
				GetClipboardValueFunc: func() (provider.Credentials, error) {
					fetched = true
					return provider.Credentials{CopyValue: "123456"}, nil
				},
			}
			var p provider.ServiceProvider = mock
			if tc.checkClip != nil {
				p = clipCheckingMock{mock, tc.checkClip}
			}
			err := app.CopyToClipboard(p)
			if err == nil || err.Error() != tc.wantErr {
				t.Errorf("err = %v, want %q", err, tc.wantErr)
			}
			if fetched {
				t.Error("the secret was fetched before the clipboard was checked")
			}
		})
	}
}

// A delete names what it will remove and asks once; nobody at a terminal
// is a refusal that points at --force.
func TestApp_ConfirmDelete(t *testing.T) {
	tests := map[string]struct {
		stdin    string
		wantErr  string
		wantAsk  string
		ids      []string
		terminal bool
		want     bool
	}{
		"one entry, yes":  {ids: []string{"password/github"}, stdin: "y\n", terminal: true, want: true, wantAsk: `Delete "password/github"? [y/N]: `},
		"several, listed": {ids: []string{"password/a", "api_key/b"}, stdin: "y\n", terminal: true, want: true, wantAsk: "These entries will be deleted:\n  password/a\n  api_key/b\nDelete these 2 entries? [y/N]: "},
		"no":              {ids: []string{"password/a"}, stdin: "n\n", terminal: true},
		"just enter":      {ids: []string{"password/a"}, stdin: "\n", terminal: true},
		"nobody to ask":   {ids: []string{"password/a"}, stdin: "y\n", wantErr: "add --force to delete without asking"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			stderr := &bytes.Buffer{}
			app := &App{Stdin: strings.NewReader(tc.stdin), Stderr: stderr, StdinIsTerminal: func() bool { return tc.terminal }}
			ok, err := app.confirmDelete(tc.ids, false)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || ok != tc.want {
				t.Errorf("confirmDelete = %v, %v; want %v", ok, err, tc.want)
			}
			if tc.wantAsk != "" && stderr.String() != tc.wantAsk {
				t.Errorf("asked %q, want %q", stderr.String(), tc.wantAsk)
			}
		})
	}
}

func TestApp_PrintCredentials_ValueAloneOnStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := &App{TimeNow: time.Now, Stdout: &stdout, Stderr: &stderr}
	creds := provider.Credentials{
		Provider:    "totp",
		DisplayInfo: "Next: 654321  |  Time left: 12s\n🔑 TOTP code for github",
		Value:       "123456",
		Variables:   map[string]string{},
	}
	if err := app.PrintCredentials(&creds); err != nil {
		t.Fatalf("PrintCredentials: %v", err)
	}
	if stdout.String() != "123456\n" {
		t.Errorf("stdout = %q, want only the value", stdout.String())
	}
	if strings.Contains(stderr.String(), "123456") {
		t.Errorf("stderr = %q, shouldn't repeat the value", stderr.String())
	}
}

func TestApp_PrintCredentials(t *testing.T) {
	fixedNow := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)

	tests := map[string]struct {
		creds         provider.Credentials
		wantStdout    []string
		wantStderr    []string
		notWantStderr []string // substrings that must NOT appear
	}{
		"aws credentials with MFA": {
			creds: provider.Credentials{
				Provider:         "aws",
				MFAAuthenticated: true,
				Expiry:           fixedNow.Add(12 * time.Hour),
				DisplayInfo:      "Using profile: default",
				Variables: map[string]string{
					"AWS_ACCESS_KEY_ID":     "AKIAIOSFODNN7EXAMPLE",
					"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
					"AWS_SESSION_TOKEN":     "FwoGZXIvYXdzEBYaDEXAMPLE",
				},
			},
			wantStdout: []string{
				"# --------- ENVIRONMENT VARIABLES ---------",
				"export AWS_ACCESS_KEY_ID='AKIAIOSFODNN7EXAMPLE'",
				"export AWS_SECRET_ACCESS_KEY='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
				"export AWS_SESSION_TOKEN='FwoGZXIvYXdzEBYaDEXAMPLE'",
				"# ----------------------------------------",
			},
			wantStderr: []string{
				"⏳ Expires at:",
				"(valid for 12h0m)",
				"✅ MFA-authenticated session established",
				"Using profile: default",
			},
		},
		"totp credentials": {
			creds: provider.Credentials{
				Provider:    "totp",
				DisplayInfo: "TOTP code for github: 123456",
				Variables:   map[string]string{},
			},
			wantStderr: []string{
				"TOTP code for github: 123456",
			},
			// TOTP codes don't expire in a session sense; omit the line
			// entirely rather than printing "unknown".
			notWantStderr: []string{"⏳ Expires at:"},
		},
		"expired credentials": {
			creds: provider.Credentials{
				Provider:    "aws",
				Expiry:      fixedNow.Add(-1 * time.Hour),
				DisplayInfo: "Using profile: default",
				Variables:   map[string]string{},
			},
			wantStderr: []string{
				"⏳ Expires at:",
				"(expired)",
			},
		},
		"credentials without expiry": {
			creds: provider.Credentials{
				Provider:    "test",
				DisplayInfo: "Test credentials",
				Variables: map[string]string{
					"TEST_VAR": "test_value",
				},
			},
			wantStdout: []string{
				"# --------- ENVIRONMENT VARIABLES ---------",
				"export TEST_VAR='test_value'",
				"# ----------------------------------------",
			},
			wantStderr: []string{
				"Test credentials",
			},
			notWantStderr: []string{"⏳ Expires at:"},
		},
		"minutes-only expiry": {
			creds: provider.Credentials{
				Provider:  "test",
				Expiry:    fixedNow.Add(5*time.Minute + 30*time.Second),
				Variables: map[string]string{},
			},
			wantStderr: []string{
				"⏳ Expires at:",
				"(valid for 5m30s)",
			},
		},
		"seconds-only expiry": {
			creds: provider.Credentials{
				Provider:  "test",
				Expiry:    fixedNow.Add(15 * time.Second),
				Variables: map[string]string{},
			},
			wantStderr: []string{
				"⏳ Expires at:",
				"(valid for 15s)",
			},
		},
		"invalid variable name is skipped": {
			creds: provider.Credentials{
				Provider: "test",
				Variables: map[string]string{
					"VALID_KEY":   "good",
					"bad;key":     "injected",
					"$(whoami)":   "injected",
					"1STARTS_NUM": "bad",
					"_UNDERSCORE": "ok",
				},
			},
			wantStdout: []string{
				"export VALID_KEY='good'",
				"export _UNDERSCORE='ok'",
			},
			wantStderr: []string{
				"Skipping invalid variable name: \"bad;key\"",
				"Skipping invalid variable name: \"$(whoami)\"",
				"Skipping invalid variable name: \"1STARTS_NUM\"",
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			stdoutBuf := &bytes.Buffer{}
			stderrBuf := &bytes.Buffer{}
			app := &App{
				TimeNow: func() time.Time { return fixedNow },
				Stdout:  stdoutBuf,
				Stderr:  stderrBuf,
			}

			if err := app.PrintCredentials(&tc.creds); err != nil {
				t.Fatalf("PrintCredentials failed: %v", err)
			}

			stdout := stdoutBuf.String()
			for _, expected := range tc.wantStdout {
				if !strings.Contains(stdout, expected) {
					t.Errorf("PrintCredentials() stdout missing expected string: %q", expected)
				}
			}

			stderr := stderrBuf.String()
			for _, expected := range tc.wantStderr {
				if !strings.Contains(stderr, expected) {
					t.Errorf("PrintCredentials() stderr missing expected string: %q", expected)
				}
			}
			for _, unwanted := range tc.notWantStderr {
				if strings.Contains(stderr, unwanted) {
					t.Errorf("PrintCredentials() stderr contains unwanted string: %q\nfull stderr:\n%s", unwanted, stderr)
				}
			}
		})
	}
}
