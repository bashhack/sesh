package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/setup"
)

// MockSetupService is a mock implementation of setup.SetupService
type MockSetupService struct {
	RegisterHandlerFunc      func(handler setup.SetupHandler)
	SetupServiceFunc         func(serviceName string) error
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
	NameFunc              func() string
	DescriptionFunc       func() string
	SetupFlagsFunc        func(fs provider.FlagSet) error
	GetSetupHandlerFunc   func() interface{}
	GetCredentialsFunc    func() (provider.Credentials, error)
	GetClipboardValueFunc func() (provider.Credentials, error)
	ListEntriesFunc       func() ([]provider.ProviderEntry, error)
	DeleteEntryFunc       func(id string) error
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
	versionInfo := VersionInfo{
		Version: "test",
		Commit:  "unknown",
		Date:    "unknown",
	}
	app := NewDefaultApp(versionInfo)

	if app.Registry == nil {
		t.Error("Registry is nil")
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

	providers := app.Registry.ListProviders()
	if len(providers) == 0 {
		t.Error("No providers registered")
	}

	awsP, err := app.Registry.GetProvider("aws")
	if err != nil {
		t.Error("AWS provider not registered")
	}
	if awsP == nil {
		t.Error("AWS provider is nil")
	}

	totpP, err := app.Registry.GetProvider("totp")
	if err != nil {
		t.Error("TOTP provider not registered")
	}
	if totpP == nil {
		t.Error("TOTP provider is nil")
	}

	services := app.SetupService.GetAvailableServices()
	if len(services) < 2 {
		t.Errorf("Expected at least 2 setup services, got %d", len(services))
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
					NameFunc: func() string {
						return "totp"
					},
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
					NameFunc: func() string {
						return "totp"
					},
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

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			app := &App{
				Registry: provider.NewRegistry(),
				Stdout:   &bytes.Buffer{},
				Stderr:   &bytes.Buffer{},
			}
			tc.setupApp(app)

			err := app.DeleteEntry(tc.serviceName, tc.entryID)

			if tc.wantErr && err == nil {
				t.Error("DeleteEntry() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("DeleteEntry() unexpected error: %v", err)
			}
			if tc.wantErrMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tc.wantErrMsg) {
					t.Errorf("error message = %v, want to contain %v", err.Error(), tc.wantErrMsg)
				}
			}
			if tc.wantOutput != "" {
				output := app.Stdout.(*bytes.Buffer).String()
				if output != tc.wantOutput {
					t.Errorf("output = %v, want %v", output, tc.wantOutput)
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

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			app := &App{
				Registry: provider.NewRegistry(),
				Stdout:   &bytes.Buffer{},
				Stderr:   &bytes.Buffer{},
			}
			tc.setupApp(app)

			err := app.RunSetup(tc.serviceName)

			if tc.wantErr && err == nil {
				t.Error("RunSetup() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("RunSetup() unexpected error: %v", err)
			}
			if tc.wantErrMsg != "" && err != nil {
				if err.Error() != tc.wantErrMsg {
					t.Errorf("error message = %v, want %v", err.Error(), tc.wantErrMsg)
				}
			}
		})
	}
}

func TestApp_PrintCredentials(t *testing.T) {
	tests := map[string]struct {
		creds      provider.Credentials
		wantStdout []string
		wantStderr []string
	}{
		"aws credentials with MFA": {
			creds: provider.Credentials{
				Provider:         "aws",
				MFAAuthenticated: true,
				Expiry:           time.Now().Add(12 * time.Hour),
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
				"(valid for 11h",
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
				"⏳ Expires at: unknown",
				"TOTP code for github: 123456",
			},
		},
		"expired credentials": {
			creds: provider.Credentials{
				Provider:    "aws",
				Expiry:      time.Now().Add(-1 * time.Hour),
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
				"⏳ Expires at: unknown",
				"Test credentials",
			},
		},
		"invalid variable name is skipped": {
			creds: provider.Credentials{
				Provider: "test",
				Variables: map[string]string{
					"VALID_KEY":    "good",
					"bad;key":      "injected",
					"$(whoami)":    "injected",
					"1STARTS_NUM":  "bad",
					"_UNDERSCORE":  "ok",
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
				Stdout: stdoutBuf,
				Stderr: stderrBuf,
			}

			app.PrintCredentials(tc.creds)

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
		})
	}
}
