package main

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/subshell"
)

// mockShellCustomizer implements subshell.ShellCustomizer
type mockShellCustomizer struct{}

func (m *mockShellCustomizer) GetZshInitScript() string {
	return `
# Mock Zsh prompt customization
PROMPT="(sesh:test) %~ %# "
`
}

func (m *mockShellCustomizer) GetBashInitScript() string {
	return `
# Mock Bash prompt customization
PS1="(sesh:test) \w \$ "
`
}

func (m *mockShellCustomizer) GetFallbackInitScript() string {
	return `
# Mock fallback shell
echo "Entering sesh environment"
`
}

func (m *mockShellCustomizer) GetPromptPrefix() string {
	return "(sesh:test) "
}

func (m *mockShellCustomizer) GetWelcomeMessage() string {
	return "🔐 Secure shell with test credentials activated."
}

// MockSubshellProvider is a mock that implements both ServiceProvider and SubshellProvider
type MockSubshellProvider struct {
	MockProvider
	NewSubshellConfigFunc func(creds provider.Credentials) interface{}
	ShouldUseSubshellFunc func() bool
}

// NewSubshellConfig implements provider.SubshellProvider
func (m *MockSubshellProvider) NewSubshellConfig(creds provider.Credentials) interface{} {
	if m.NewSubshellConfigFunc != nil {
		return m.NewSubshellConfigFunc(creds)
	}
	return nil
}

// ShouldUseSubshell implements provider.SubshellProvider
func (m *MockSubshellProvider) ShouldUseSubshell() bool {
	if m.ShouldUseSubshellFunc != nil {
		return m.ShouldUseSubshellFunc()
	}
	return true
}

func TestApp_LaunchSubshell(t *testing.T) {
	tests := map[string]struct {
		serviceName string
		setupEnv    map[string]string
		setupApp    func(*App)
		wantErr     bool
		wantErrMsg  string
		checkOutput func(*testing.T, string, string) // stdout, stderr
	}{
		"already in sesh environment": {
			serviceName: "aws",
			setupEnv: map[string]string{
				"SESH_ACTIVE": "1",
			},
			wantErr:    true,
			wantErrMsg: "already in a sesh environment",
		},
		"provider not found": {
			serviceName: "unknown",
			setupApp:    func(app *App) {},
			wantErr:     true,
			wantErrMsg:  "provider not found",
		},
		"validate request fails": {
			serviceName: "aws",
			setupApp: func(app *App) {
				mockProvider := &MockSubshellProvider{
					MockProvider: MockProvider{
						NameFunc: func() string {
							return "aws"
						},
						ValidateRequestFunc: func() error {
							return errors.New("validation failed")
						},
					},
				}
				app.Registry.RegisterProvider(mockProvider)
			},
			wantErr:    true,
			wantErrMsg: "validation failed",
		},
		"get credentials fails": {
			serviceName: "aws",
			setupApp: func(app *App) {
				mockProvider := &MockSubshellProvider{
					MockProvider: MockProvider{
						NameFunc: func() string {
							return "aws"
						},
						ValidateRequestFunc: func() error {
							return nil
						},
						GetCredentialsFunc: func() (provider.Credentials, error) {
							return provider.Credentials{}, errors.New("failed to get credentials")
						},
					},
				}
				app.Registry.RegisterProvider(mockProvider)
			},
			wantErr:    true,
			wantErrMsg: "failed to generate credentials",
		},
		"provider does not support subshell": {
			serviceName: "totp",
			setupApp: func(app *App) {
				// Regular provider without subshell support
				mockProvider := &MockProvider{
					NameFunc: func() string {
						return "totp"
					},
					ValidateRequestFunc: func() error {
						return nil
					},
					GetCredentialsFunc: func() (provider.Credentials, error) {
						return provider.Credentials{}, nil
					},
				}
				app.Registry.RegisterProvider(mockProvider)
			},
			wantErr:    true,
			wantErrMsg: "provider totp does not support subshell customization",
		},
		"invalid subshell configuration": {
			serviceName: "aws",
			setupApp: func(app *App) {
				mockProvider := &MockSubshellProvider{
					MockProvider: MockProvider{
						NameFunc: func() string {
							return "aws"
						},
						ValidateRequestFunc: func() error {
							return nil
						},
						GetCredentialsFunc: func() (provider.Credentials, error) {
							return provider.Credentials{
								Provider: "aws",
								Variables: map[string]string{
									"AWS_ACCESS_KEY_ID": "test",
								},
							}, nil
						},
					},
					NewSubshellConfigFunc: func(creds provider.Credentials) interface{} {
						// Return something that's not a subshell.Config
						return "invalid config"
					},
				}
				app.Registry.RegisterProvider(mockProvider)
			},
			wantErr:    true,
			wantErrMsg: "provider aws returned invalid subshell configuration",
		},
		"successful subshell launch": {
			serviceName: "aws",
			setupEnv: map[string]string{
				"SHELL": "/bin/echo", // Use echo as shell for testing
			},
			setupApp: func(app *App) {
				mockProvider := &MockSubshellProvider{
					MockProvider: MockProvider{
						NameFunc: func() string {
							return "aws"
						},
						ValidateRequestFunc: func() error {
							return nil
						},
						GetCredentialsFunc: func() (provider.Credentials, error) {
							return provider.Credentials{
								Provider: "aws",
								Expiry:   time.Now().Add(12 * time.Hour),
								Variables: map[string]string{
									"AWS_ACCESS_KEY_ID":     "AKIAIOSFODNN7EXAMPLE",
									"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
									"AWS_SESSION_TOKEN":     "FwoGZXIvYXdzEBYaDEXAMPLE",
								},
							}, nil
						},
					},
					NewSubshellConfigFunc: func(creds provider.Credentials) interface{} {
						return subshell.Config{
							ServiceName: "aws",
							Variables:   creds.Variables,
							Expiry:      creds.Expiry,
							ShellCustomizer: &mockShellCustomizer{},
						}
					},
				}
				app.Registry.RegisterProvider(mockProvider)
			},
			wantErr: false,
			checkOutput: func(t *testing.T, stdout, stderr string) {
				if !strings.Contains(stdout, "Starting secure shell with aws credentials") {
					t.Error("Expected stdout to contain startup message")
				}
				if !strings.Contains(stdout, "Exited secure shell") {
					t.Error("Expected stdout to contain exit message")
				}
			},
		},
		"subshell exits with error": {
			serviceName: "aws",
			setupEnv: map[string]string{
				"SHELL": "/usr/bin/false", // Shell that always exits with error
			},
			setupApp: func(app *App) {
				mockProvider := &MockSubshellProvider{
					MockProvider: MockProvider{
						NameFunc: func() string {
							return "aws"
						},
						ValidateRequestFunc: func() error {
							return nil
						},
						GetCredentialsFunc: func() (provider.Credentials, error) {
							return provider.Credentials{
								Provider: "aws",
							}, nil
						},
					},
					NewSubshellConfigFunc: func(creds provider.Credentials) interface{} {
						return subshell.Config{
							ServiceName: "aws",
							Variables:   creds.Variables,
							Expiry:      creds.Expiry,
							ShellCustomizer: &mockShellCustomizer{},
						}
					},
				}
				app.Registry.RegisterProvider(mockProvider)
			},
			wantErr: false, // ExitError is expected and handled
			checkOutput: func(t *testing.T, stdout, stderr string) {
				if !strings.Contains(stdout, "Starting secure shell") {
					t.Error("Expected stdout to contain startup message")
				}
				if !strings.Contains(stdout, "Exited secure shell") {
					t.Error("Expected stdout to contain exit message")
				}
			},
		},
		"subshell command not found": {
			serviceName: "aws",
			setupEnv: map[string]string{
				"SHELL": "/nonexistent/shell", // Non-existent shell
			},
			setupApp: func(app *App) {
				mockProvider := &MockSubshellProvider{
					MockProvider: MockProvider{
						NameFunc: func() string {
							return "aws"
						},
						ValidateRequestFunc: func() error {
							return nil
						},
						GetCredentialsFunc: func() (provider.Credentials, error) {
							return provider.Credentials{
								Provider: "aws",
							}, nil
						},
					},
					NewSubshellConfigFunc: func(creds provider.Credentials) interface{} {
						return subshell.Config{
							ServiceName: "aws",
							Variables:   creds.Variables,
							Expiry:      creds.Expiry,
							ShellCustomizer: &mockShellCustomizer{},
						}
					},
				}
				app.Registry.RegisterProvider(mockProvider)
			},
			wantErr:    true,
			wantErrMsg: "subshell encountered an unexpected error",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Save and restore environment
			for key, value := range test.setupEnv {
				oldValue := os.Getenv(key)
				os.Setenv(key, value)
				defer os.Setenv(key, oldValue)
			}

			// Create app with mocks
			app := &App{
				Registry: provider.NewRegistry(),
				Stdout:   &bytes.Buffer{},
				Stderr:   &bytes.Buffer{},
			}

			// Setup test-specific configuration
			if test.setupApp != nil {
				test.setupApp(app)
			}

			// Test LaunchSubshell
			err := app.LaunchSubshell(test.serviceName)

			// Check error
			if test.wantErr && err == nil {
				t.Error("LaunchSubshell() expected error but got nil")
			}
			if !test.wantErr && err != nil {
				t.Errorf("LaunchSubshell() unexpected error: %v", err)
			}
			if test.wantErrMsg != "" && err != nil {
				if !strings.Contains(err.Error(), test.wantErrMsg) {
					t.Errorf("error message = %v, want to contain %v", err.Error(), test.wantErrMsg)
				}
			}

			// Check output
			if test.checkOutput != nil {
				stdout := app.Stdout.(*bytes.Buffer).String()
				stderr := app.Stderr.(*bytes.Buffer).String()
				test.checkOutput(t, stdout, stderr)
			}
		})
	}
}

// mockExitErrorShellCustomizer implements a shell customizer that causes the shell to exit with error
type mockExitErrorShellCustomizer struct {
	mockShellCustomizer
}

func (m *mockExitErrorShellCustomizer) GetBashInitScript() string {
	return `exit 1`
}

func (m *mockExitErrorShellCustomizer) GetFallbackInitScript() string {
	return `exit 1`
}

// TestApp_LaunchSubshell_RealExitError tests handling of real exit errors
func TestApp_LaunchSubshell_RealExitError(t *testing.T) {
	// Save and restore SHELL env var
	oldShell := os.Getenv("SHELL")
	os.Setenv("SHELL", "/bin/bash") // Use bash for predictable behavior
	defer os.Setenv("SHELL", oldShell)

	// This test simulates a shell that exits with a non-zero status
	app := &App{
		Registry: provider.NewRegistry(),
		Stdout:   &bytes.Buffer{},
		Stderr:   &bytes.Buffer{},
	}

	mockProvider := &MockSubshellProvider{
		MockProvider: MockProvider{
			NameFunc: func() string {
				return "aws"
			},
			ValidateRequestFunc: func() error {
				return nil
			},
			GetCredentialsFunc: func() (provider.Credentials, error) {
				return provider.Credentials{
					Provider: "aws",
				}, nil
			},
		},
		NewSubshellConfigFunc: func(creds provider.Credentials) interface{} {
			return subshell.Config{
				ServiceName: "aws",
				Variables:   creds.Variables,
				Expiry:      creds.Expiry,
				ShellCustomizer: &mockExitErrorShellCustomizer{},
			}
		},
	}
	app.Registry.RegisterProvider(mockProvider)

	// This should not return an error even though the shell exits with status 1
	err := app.LaunchSubshell("aws")
	if err != nil {
		t.Errorf("LaunchSubshell() should handle ExitError gracefully, got: %v", err)
	}

	output := app.Stdout.(*bytes.Buffer).String()
	if !strings.Contains(output, "Exited secure shell") {
		t.Error("Expected exit message even with non-zero exit status")
	}
}