package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/subshell"
)

// mockShellCustomizer implements subshell.ShellCustomizer: no helpers.
type mockShellCustomizer struct{}

func (m *mockShellCustomizer) Functions() string    { return "" }
func (m *mockShellCustomizer) PromptPrefix() string { return "(sesh:test) " }

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
			wantErr:    true, // the shell's exit status is sesh's
			wantErrMsg: "exit status 1",
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
			wantErrMsg: "can't run /nonexistent/shell",
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
			err := app.LaunchSubshell(p, nil)

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

// scriptedCustomizer is a customizer whose helpers are script, run as the
// shell starts.
type scriptedCustomizer struct{ script string }

func (m *scriptedCustomizer) Functions() string    { return m.script }
func (m *scriptedCustomizer) PromptPrefix() string { return "(sesh:test) " }

// The shell's exit status is sesh's; the vault is let go of before the
// shell starts; SESH_MASTER_PASSWORD doesn't reach it.
func TestApp_LaunchSubshell_ExitStatus(t *testing.T) {
	for _, sh := range []string{"bash", "sh"} {
		t.Run(sh, func(t *testing.T) {
			// Without a terminal the shell isn't interactive, and wouldn't
			// read its startup files: a wrapper of the same name makes it
			// (-i after bash's long options, which come first).
			wrapper := filepath.Join(t.TempDir(), sh)
			if err := os.WriteFile(wrapper, []byte("#!/bin/sh\nexec /bin/"+sh+" \"$@\" -i 2>/dev/null\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("SHELL", wrapper)
			t.Setenv("HOME", t.TempDir())
			t.Setenv("SESH_MASTER_PASSWORD", "hunter2-hunter2")
			released := false
			app := &App{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
			p := &MockSubshellProvider{
				NameFunc:            func() string { return "aws" },
				ValidateRequestFunc: func() error { return nil },
				GetCredentialsFunc: func() (provider.Credentials, error) {
					if released {
						t.Error("the vault was let go of before the credentials were read")
					}
					return provider.Credentials{Provider: "aws"}, nil
				},
				NewSubshellConfigFunc: func(creds *provider.Credentials) any {
					if !released {
						t.Error("the shell is being set up with the vault still held")
					}
					return subshell.Config{ServiceName: "aws", ShellCustomizer: &scriptedCustomizer{
						script: `[ -z "$SESH_MASTER_PASSWORD" ] || exit 7
exit 3`,
					}}
				},
			}
			err := app.LaunchSubshell(p, func() { released = true })
			if status, ok := errors.AsType[exitStatus](err); !ok || status != 3 {
				t.Errorf("LaunchSubshell() = %v, want exit status 3", err)
			}
			if !strings.Contains(app.Stdout.(*bytes.Buffer).String(), "Exited secure shell") {
				t.Error("no exit message")
			}
		})
	}
}
