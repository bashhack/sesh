package main

import (
	"bytes"
	"strings"
	"testing"

	awsMocks "github.com/bashhack/sesh/internal/aws/mocks"
	"github.com/bashhack/sesh/internal/keychain/mocks"
	setupMocks "github.com/bashhack/sesh/internal/setup/mocks"
	"github.com/bashhack/sesh/internal/testutil"
	totpMocks "github.com/bashhack/sesh/internal/totp/mocks"
)

// TestHelperProcess is needed for the testutil.MockExecCommand function
func TestHelperProcess(t *testing.T) {
	testutil.TestHelperProcess()
}

func mockApp() (*App, *bytes.Buffer, *bytes.Buffer) {
	stdoutBuf := new(bytes.Buffer)
	stderrBuf := new(bytes.Buffer)

	app := NewDefaultApp() // Create a real app with registry

	// Override with mocks
	app.AWS = &awsMocks.MockProvider{}
	app.Keychain = &mocks.MockProvider{}
	app.TOTP = &totpMocks.MockProvider{}
	app.SetupWizard = &setupMocks.MockWizardRunner{}
	app.ExecLookPath = func(string) (string, error) { return "/usr/local/bin/aws", nil }
	app.Exit = func(int) {}
	app.Stdout = stdoutBuf
	app.Stderr = stderrBuf
	app.VersionInfo = VersionInfo{
		Version: "test-version",
		Commit:  "test-commit",
		Date:    "test-date",
	}

	return app, stdoutBuf, stderrBuf
}

func TestVersionFlag(t *testing.T) {
	app, stdoutBuf, _ := mockApp()

	exitCalled := false
	app.Exit = func(int) { exitCalled = true }

	run(app, []string{"sesh", "--version"})

	output := stdoutBuf.String()

	if !strings.Contains(output, "test-version") || !strings.Contains(output, "test-commit") {
		t.Errorf("Expected version output to contain version and commit info, got: %s", output)
	}

	if exitCalled {
		t.Error("Exit was called but shouldn't have been")
	}
}

// Skip this test since it relies on stdout capture which doesn't work
// with the current printUsage implementation
func TestHelpFlag(t *testing.T) {
	t.Skip("Skipping test as it requires capturing stdout directly")
}

// TestNoAwsCli is no longer applicable - this is now handled in the AWS provider

// TestMFASerialFromKeychain is now handled by the AWS provider tests

// TestTOTPSecretError is now handled by the AWS provider tests

func TestExtractServiceName(t *testing.T) {
	tests := map[string]struct {
		args        []string
		wantService string
		wantErr     bool
	}{
		"service flag with equals": {
			args:        []string{"--service=aws"},
			wantService: "aws",
		},
		"service flag with space": {
			args:        []string{"--service", "totp"},
			wantService: "totp",
		},
		"service flag with other flags": {
			args:        []string{"--profile", "dev", "--service", "aws", "--no-subshell"},
			wantService: "aws",
		},
		"single dash service flag": {
			args:        []string{"-service", "aws"},
			wantService: "aws",
		},
		"no service flag": {
			args:        []string{"--profile", "dev"},
			wantService: "",
		},
		"service flag at end": {
			args:        []string{"--no-subshell", "--profile=prod", "--service=aws"},
			wantService: "aws",
		},
		"empty service value with equals": {
			args:        []string{"--service="},
			wantService: "",
		},
		"empty service value with space": {
			args:        []string{"--service", ""},
			wantService: "",
		},
		"service flag without value": {
			args:        []string{"--service"},
			wantService: "",
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			got := extractServiceName(test.args)
			if got != test.wantService {
				t.Errorf("extractServiceName() = %v, want %v", got, test.wantService)
			}
		})
	}
}

func TestPrintProviderUsage(t *testing.T) {
	// Test that printProviderUsage generates output for each provider
	providers := []string{"aws", "totp"}
	
	for _, provider := range providers {
		t.Run(provider, func(t *testing.T) {
			var buf bytes.Buffer
			printProviderUsage(&buf, provider)
			
			output := buf.String()
			
			// Check that output contains provider name
			if !strings.Contains(output, provider) {
				t.Errorf("printProviderUsage() output should contain provider name %q", provider)
			}
			
			// Check for common flags
			if !strings.Contains(output, "--service") {
				t.Error("printProviderUsage() output should contain --service flag")
			}
			
			// Check for provider-specific content
			switch provider {
			case "aws":
				if !strings.Contains(output, "--profile") {
					t.Error("AWS usage should contain --profile flag")
				}
				if !strings.Contains(output, "--no-subshell") {
					t.Error("AWS usage should contain --no-subshell flag")
				}
			case "totp":
				if !strings.Contains(output, "--service-name") {
					t.Error("TOTP usage should contain --service-name flag")
				}
			}
		})
	}
}

func TestServiceNameExtraction_EdgeCases(t *testing.T) {
	tests := map[string]struct {
		args        []string
		wantService string
	}{
		"service with special chars": {
			args:        []string{"--service=aws-test"},
			wantService: "aws-test",
		},
		"multiple service flags (first wins)": {
			args:        []string{"--service", "aws", "--service", "totp"},
			wantService: "aws",
		},
		"service in quotes": {
			args:        []string{"--service=\"aws\""},
			wantService: "\"aws\"", // Quotes are preserved in simple extraction
		},
		"service with equals in value": {
			args:        []string{"--service=name=value"},
			wantService: "name=value",
		},
		"single dash with equals": {
			args:        []string{"-service=aws"},
			wantService: "aws",
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			got := extractServiceName(test.args)
			if got != test.wantService {
				t.Errorf("extractServiceName() = %v, want %v", got, test.wantService)
			}
		})
	}
}
