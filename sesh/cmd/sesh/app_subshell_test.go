package main

import (
	"bytes"
	"errors"
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
	return "sesh"
}

// MockSubshellProvider is a mock that implements both ServiceProvider and SubshellProvider
type MockSubshellProvider struct {
	MockProvider
	NewSubshellConfigFunc func(creds *provider.Credentials) any
	ShouldUseSubshellFunc func() bool
}

// NewSubshellConfig implements provider.SubshellProvider
func (m *MockSubshellProvider) NewSubshellConfig(creds *provider.Credentials) any {
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
		setupEnv    map[string]string
		newProvider func() provider.ServiceProvider
		checkOutput func(*testing.T, string, string)
		wantErrMsg  string
		wantErr     bool
	}{
		"already in sesh environment": {
			setupEnv: map[string]string{
				"SESH_ACTIVE": "1",
			},
			wantErr:    true,
			wantErrMsg: "already in a sesh environment",
		},
		"validate request fails": {
			newProvider: func() provider.ServiceProvider {
				mockProvider := &MockSubshellProvider{
					NameFunc: func() string {
						return "aws"
					},
					ValidateRequestFunc: func() error {
						return errors.New("validation failed")
					},
				}
				return mockProvider
			},
			wantErr:    true,
			wantErrMsg: "validation failed",
		},
		"get credentials fails": {
			newProvider: func() provider.ServiceProvider {
				mockProvider := &MockSubshellProvider{
					NameFunc: func() string {
						return "aws"
					},
					ValidateRequestFunc: func() error {
						return nil
					},
					GetCredentialsFunc: func() (provider.Credentials, error) {
						return provider.Credentials{}, errors.New("failed to get credentials")
					},
				}
				return mockProvider
			},
			wantErr:    true,
			wantErrMsg: "failed to generate credentials",
		},
		"provider does not support subshell": {
			newProvider: func() provider.ServiceProvider {
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
				return mockProvider
			},
			wantErr:    true,
			wantErrMsg: "provider totp does not support subshell customization",
		},
		"invalid subshell configuration": {
			newProvider: func() provider.ServiceProvider {
				mockProvider := &MockSubshellProvider{
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
					NewSubshellConfigFunc: func(creds *provider.Credentials) any {
						// Return something that's not a subshell.Config
						return "invalid config"
					},
				}
				return mockProvider
			},
			wantErr:    true,
			wantErrMsg: "provider aws returned invalid subshell configuration",
		},
		"successful subshell launch": {
			setupEnv: map[string]string{
				"SHELL": "/bin/echo", // Use echo as shell for testing
			},
			newProvider: func() provider.ServiceProvider {
				mockProvider := &MockSubshellProvider{
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
					NewSubshellConfigFunc: func(creds *provider.Credentials) any {
						return subshell.Config{
							ServiceName:     "aws",
							Variables:       creds.Variables,
							Expiry:          creds.Expiry,
							ShellCustomizer: &mockShellCustomizer{},
						}
					},
				}
				return mockProvider
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
			setupEnv: map[string]string{
				"SHELL": "/usr/bin/false", // Shell that always exits with error
			},
			newProvider: func() provider.ServiceProvider {
				mockProvider := &MockSubshellProvider{
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
					NewSubshellConfigFunc: func(creds *provider.Credentials) any {
						return subshell.Config{
							ServiceName:     "aws",
							Variables:       creds.Variables,
							Expiry:          creds.Expiry,
							ShellCustomizer: &mockShellCustomizer{},
						}
					},
				}
				return mockProvider
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
			setupEnv: map[string]string{
				"SHELL": "/nonexistent/shell", // Non-existent shell
			},
			newProvider: func() provider.ServiceProvider {
				mockProvider := &MockSubshellProvider{
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
					NewSubshellConfigFunc: func(creds *provider.Credentials) any {
						return subshell.Config{
							ServiceName:     "aws",
							Variables:       creds.Variables,
							Expiry:          creds.Expiry,
							ShellCustomizer: &mockShellCustomizer{},
						}
					},
				}
				return mockProvider
			},
			wantErr:    true,
			wantErrMsg: "subshell encountered an unexpected error",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			for key, value := range tc.setupEnv {
				t.Setenv(key, value)
			}

			app := &App{
				Stdout: &bytes.Buffer{},
				Stderr: &bytes.Buffer{},
			}

			var p provider.ServiceProvider = &MockSubshellProvider{NameFunc: func() string { return "aws" }}
			if tc.newProvider != nil {
				p = tc.newProvider()
			}
			err := app.LaunchSubshell(p)

			if tc.wantErr && err == nil {
				t.Error("LaunchSubshell() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("LaunchSubshell() unexpected error: %v", err)
			}
			if tc.wantErrMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tc.wantErrMsg) {
					t.Errorf("error message = %v, want to contain %v", err.Error(), tc.wantErrMsg)
				}
			}

			if tc.checkOutput != nil {
				stdout := app.Stdout.(*bytes.Buffer).String()
				stderr := app.Stderr.(*bytes.Buffer).String()
				tc.checkOutput(t, stdout, stderr)
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

func TestApp_LaunchSubshell_RealExitError(t *testing.T) {
	t.Setenv("SHELL", "/bin/bash")

	app := &App{
		Stdout: &bytes.Buffer{},
		Stderr: &bytes.Buffer{},
	}

	mockProvider := &MockSubshellProvider{
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
		NewSubshellConfigFunc: func(creds *provider.Credentials) any {
			return subshell.Config{
				ServiceName:     "aws",
				Variables:       creds.Variables,
				Expiry:          creds.Expiry,
				ShellCustomizer: &mockExitErrorShellCustomizer{},
			}
		},
	}

	err := app.LaunchSubshell(mockProvider)
	if err != nil {
		t.Errorf("LaunchSubshell() should handle ExitError gracefully, got: %v", err)
	}

	output := app.Stdout.(*bytes.Buffer).String()
	if !strings.Contains(output, "Exited secure shell") {
		t.Error("Expected exit message even with non-zero exit status")
	}
}
