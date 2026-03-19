package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	awsMocks "github.com/bashhack/sesh/internal/aws/mocks"
	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/keychain/mocks"
	"github.com/bashhack/sesh/internal/provider"
	awsProvider "github.com/bashhack/sesh/internal/provider/aws"
	totpProvider "github.com/bashhack/sesh/internal/provider/totp"
	"github.com/bashhack/sesh/internal/testutil"
	totpMocks "github.com/bashhack/sesh/internal/totp/mocks"
)

// TestHelperProcess is needed for the testutil.MockExecCommand function
func TestHelperProcess(_ *testing.T) {
	testutil.TestHelperProcess()
}

// testHarness bundles a test App with its mock dependencies and output buffers.
type testHarness struct {
	app      *App
	stdout   *bytes.Buffer
	stderr   *bytes.Buffer
	keychain *mocks.MockProvider
	aws      *awsMocks.MockProvider
	totp     *totpMocks.MockProvider
}

func newTestHarness() *testHarness {
	mockKC := &mocks.MockProvider{}
	mockAWS := &awsMocks.MockProvider{}
	mockTOTP := &totpMocks.MockProvider{}

	registry := provider.NewRegistry()
	registry.RegisterProvider(awsProvider.NewProvider(mockAWS, mockKC, mockTOTP))
	registry.RegisterProvider(totpProvider.NewProvider(mockKC, mockTOTP))

	stdoutBuf := new(bytes.Buffer)
	stderrBuf := new(bytes.Buffer)

	return &testHarness{
		app: &App{
			Registry:      registry,
			SetupService:  &MockSetupService{},
			ExecLookPath:  func(string) (string, error) { return "/usr/local/bin/aws", nil },
			Exit:          func(int) {},
			ClipboardCopy: func(string) error { return nil },
			TimeNow:       time.Now,
			Stdout:        stdoutBuf,
			Stderr:        stderrBuf,
			VersionInfo:   VersionInfo{Version: "test-version", Commit: "test-commit", Date: "test-date"},
		},
		stdout:   stdoutBuf,
		stderr:   stderrBuf,
		keychain: mockKC,
		aws:      mockAWS,
		totp:     mockTOTP,
	}
}

func TestVersionFlag(t *testing.T) {
	h := newTestHarness()

	exitCalled := false
	h.app.Exit = func(int) { exitCalled = true }

	run(h.app, []string{"sesh", "--version"})

	output := h.stdout.String()

	if !strings.Contains(output, "test-version") || !strings.Contains(output, "test-commit") {
		t.Errorf("Expected version output to contain version and commit info, got: %s", output)
	}

	if exitCalled {
		t.Error("Exit was called but shouldn't have been")
	}
}

func TestPrintUsage(t *testing.T) {
	h := newTestHarness()
	if err := h.app.PrintUsage(); err != nil {
		t.Fatalf("PrintUsage failed: %v", err)
	}

	output := h.stdout.String()
	expectedStrings := []string{
		"Usage: sesh [options]",
		"Common options:",
		"--service",
		"--list",
		"--delete",
		"--setup",
		"--clip",
		"--list-services",
		"--version",
		"--help",
		"Examples:",
		"sesh --service aws",
		"sesh --service totp --service-name github",
		"For provider-specific help:",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("PrintUsage() output missing expected string: %q", expected)
		}
	}
}

func TestExtractServiceName(t *testing.T) {
	tests := map[string]struct {
		wantService string
		args        []string
	}{
		"service flag with equals": {
			args:        []string{"sesh", "--service=aws"},
			wantService: "aws",
		},
		"service flag with space": {
			args:        []string{"sesh", "--service", "totp"},
			wantService: "totp",
		},
		"service flag with other flags": {
			args:        []string{"sesh", "--profile", "dev", "--service", "aws", "--no-subshell"},
			wantService: "aws",
		},
		"single dash service flag": {
			args:        []string{"sesh", "-service", "aws"},
			wantService: "aws",
		},
		"no service flag": {
			args:        []string{"sesh", "--profile", "dev"},
			wantService: "",
		},
		"service flag at end": {
			args:        []string{"sesh", "--no-subshell", "--profile=prod", "--service=aws"},
			wantService: "aws",
		},
		"empty service value with equals": {
			args:        []string{"sesh", "--service="},
			wantService: "",
		},
		"empty service value with space": {
			args:        []string{"sesh", "--service", ""},
			wantService: "",
		},
		"service flag without value": {
			args:        []string{"sesh", "--service"},
			wantService: "",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := extractServiceName(tc.args)
			if got != tc.wantService {
				t.Errorf("extractServiceName() = %v, want %v", got, tc.wantService)
			}
		})
	}
}

func TestPrintProviderUsage(t *testing.T) {
	h := newTestHarness()

	tests := map[string]struct {
		provider    provider.ServiceProvider
		serviceName string
	}{}

	if awsP, err := h.app.Registry.GetProvider("aws"); err == nil {
		tests["aws"] = struct {
			provider    provider.ServiceProvider
			serviceName string
		}{awsP, "aws"}
	}
	if totpP, err := h.app.Registry.GetProvider("totp"); err == nil {
		tests["totp"] = struct {
			provider    provider.ServiceProvider
			serviceName string
		}{totpP, "totp"}
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			h := newTestHarness()
			if err := h.app.PrintProviderUsage(tc.serviceName, tc.provider); err != nil {
				t.Fatalf("PrintProviderUsage failed: %v", err)
			}

			output := h.stdout.String()
			if !strings.Contains(output, tc.serviceName) {
				t.Errorf("PrintProviderUsage() output should contain provider name %q", tc.serviceName)
			}
			if !strings.Contains(output, "--service") {
				t.Error("printProviderUsage() output should contain --service flag")
			}

			switch tc.serviceName {
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
		wantService string
		args        []string
	}{
		"service with special chars": {
			args:        []string{"sesh", "--service=aws-test"},
			wantService: "aws-test",
		},
		"multiple service flags (first wins)": {
			args:        []string{"sesh", "--service", "aws", "--service", "totp"},
			wantService: "aws",
		},
		"service in quotes": {
			args:        []string{"sesh", "--service=\"aws\""},
			wantService: "\"aws\"", // Quotes are preserved in simple extraction
		},
		"service with equals in value": {
			args:        []string{"sesh", "--service=name=value"},
			wantService: "name=value",
		},
		"single dash with equals": {
			args:        []string{"sesh", "-service=aws"},
			wantService: "aws",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := extractServiceName(tc.args)
			if got != tc.wantService {
				t.Errorf("extractServiceName() = %v, want %v", got, tc.wantService)
			}
		})
	}
}

func TestRun_ProviderSpecificFlags(t *testing.T) {
	tests := map[string]struct {
		setupMocks   func(*testHarness)
		checkOutput  func(*testing.T, string, string)
		args         []string
		wantExitCode int
	}{
		"aws with valid profile flag": {
			args: []string{"sesh", "--service", "aws", "--profile", "dev", "--list"},
			setupMocks: func(h *testHarness) {
				h.keychain.ListEntriesFunc = func(prefix string) ([]keychain.KeychainEntry, error) {
					return []keychain.KeychainEntry{
						{Service: "sesh-aws-default", Account: "testuser"},
						{Service: "sesh-aws-dev", Account: "testuser"},
					}, nil
				}
			},
			wantExitCode: 0,
		},
		"totp with service-name flag": {
			args: []string{"sesh", "--service", "totp", "--service-name", "github", "--clip"},
			setupMocks: func(h *testHarness) {
				h.keychain.GetSecretFunc = func(account, service string) ([]byte, error) {
					if service == "sesh-totp/github" {
						return []byte("JBSWY3DPEHPK3PXP"), nil // Example TOTP secret
					}
					return nil, fmt.Errorf("not found")
				}

				h.totp.GenerateConsecutiveCodesBytesFunc = func(secret []byte) (string, string, error) {
					return "123456", "654321", nil
				}
			},
			wantExitCode: 0, // Should succeed with proper mocks
		},
		"aws with totp-specific flag should fail": {
			args: []string{"sesh", "--service", "aws", "--service-name", "github"},
			setupMocks: func(h *testHarness) {
				// Should fail during flag parsing
			},
			wantExitCode: 1,
			checkOutput: func(t *testing.T, stdout, stderr string) {
				if !strings.Contains(stderr, "flag provided but not defined") || !strings.Contains(stderr, "service-name") {
					t.Error("Expected error about undefined flag --service-name")
				}
			},
		},
		"totp with aws-specific flag should fail": {
			args: []string{"sesh", "--service", "totp", "--no-subshell"},
			setupMocks: func(h *testHarness) {
				// Should fail during flag parsing
			},
			wantExitCode: 1,
			checkOutput: func(t *testing.T, stdout, stderr string) {
				if !strings.Contains(stderr, "flag provided but not defined") || !strings.Contains(stderr, "no-subshell") {
					t.Error("Expected error about undefined flag --no-subshell")
				}
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			h := newTestHarness()

			exitCode := -1
			h.app.Exit = func(code int) { exitCode = code }

			if tc.setupMocks != nil {
				tc.setupMocks(h)
			}

			run(h.app, tc.args)

			if exitCode == -1 {
				exitCode = 0
			}

			if exitCode != tc.wantExitCode {
				t.Errorf("Exit code = %d, want %d", exitCode, tc.wantExitCode)
				t.Logf("stdout: %q", h.stdout.String())
				t.Logf("stderr: %q", h.stderr.String())
			}

			if tc.checkOutput != nil {
				tc.checkOutput(t, h.stdout.String(), h.stderr.String())
			}
		})
	}
}

func TestRun_Commands(t *testing.T) {
	tests := map[string]struct {
		setupMocks   func(*testHarness)
		checkStdout  func(*testing.T, string)
		checkStderr  func(*testing.T, string)
		args         []string
		wantExitCode int
	}{
		"list-services early exit": {
			args:         []string{"sesh", "--list-services"},
			wantExitCode: 0,
			checkStdout: func(t *testing.T, stdout string) {
				if !strings.Contains(stdout, "Available service providers") {
					t.Error("Expected provider list output")
				}
			},
		},
		"help without service": {
			args:         []string{"sesh", "--help"},
			wantExitCode: 0,
			checkStdout: func(t *testing.T, stdout string) {
				if !strings.Contains(stdout, "Usage: sesh") {
					t.Error("Expected general usage output")
				}
			},
		},
		"help with service": {
			args:         []string{"sesh", "--service", "aws", "--help"},
			wantExitCode: 0,
			checkStdout: func(t *testing.T, stdout string) {
				if !strings.Contains(stdout, "Usage: sesh --service aws") {
					t.Error("Expected provider-specific usage output")
				}
			},
		},
		"version after service parsing": {
			args:         []string{"sesh", "--service", "aws", "--version"},
			wantExitCode: 0,
			checkStdout: func(t *testing.T, stdout string) {
				if !strings.Contains(stdout, "test-version") {
					t.Error("Expected version output")
				}
			},
		},
		"list-services after service parsing": {
			args:         []string{"sesh", "--service", "aws", "--list-services"},
			wantExitCode: 0,
			checkStdout: func(t *testing.T, stdout string) {
				if !strings.Contains(stdout, "Available service providers") {
					t.Error("Expected provider list output")
				}
			},
		},
		"list entries": {
			args: []string{"sesh", "--service", "aws", "--list"},
			setupMocks: func(h *testHarness) {
				h.keychain.ListEntriesFunc = func(prefix string) ([]keychain.KeychainEntry, error) {
					return []keychain.KeychainEntry{}, nil
				}
			},
			wantExitCode: 0,
			checkStdout: func(t *testing.T, stdout string) {
				if !strings.Contains(stdout, "Entries for aws") {
					t.Error("Expected entries list output")
				}
			},
		},
		"list entries error": {
			args: []string{"sesh", "--service", "aws", "--list"},
			setupMocks: func(h *testHarness) {
				h.keychain.ListEntriesFunc = func(prefix string) ([]keychain.KeychainEntry, error) {
					return nil, fmt.Errorf("keychain error")
				}
			},
			wantExitCode: 1,
		},
		"delete entry": {
			args: []string{"sesh", "--service", "totp", "--delete", "sesh-totp/github:user"},
			setupMocks: func(h *testHarness) {
				h.keychain.DeleteEntryFunc = func(account, service string) error {
					return nil
				}
			},
			wantExitCode: 0,
		},
		"delete entry invalid id": {
			args:         []string{"sesh", "--service", "totp", "--delete", "bad-id"},
			wantExitCode: 1,
		},
		"delete entry keychain error": {
			args: []string{"sesh", "--service", "totp", "--delete", "sesh-totp/github:user"},
			setupMocks: func(h *testHarness) {
				h.keychain.DeleteEntryFunc = func(account, service string) error {
					return fmt.Errorf("keychain delete failed")
				}
			},
			wantExitCode: 1,
			checkStderr: func(t *testing.T, stderr string) {
				if !strings.Contains(stderr, "delete") {
					t.Error("Expected error about delete failure")
				}
			},
		},
		"setup": {
			args:         []string{"sesh", "--service", "aws", "--setup"},
			wantExitCode: 0,
		},
		"clip error": {
			args: []string{"sesh", "--service", "totp", "--service-name", "github", "--clip"},
			setupMocks: func(h *testHarness) {
				h.keychain.GetSecretFunc = func(account, service string) ([]byte, error) {
					return nil, fmt.Errorf("secret not found")
				}
				h.app.ClipboardCopy = func(text string) error {
					return fmt.Errorf("clipboard unavailable")
				}
			},
			wantExitCode: 1,
		},
		"generate credentials error": {
			args: []string{"sesh", "--service", "totp", "--service-name", "github"},
			setupMocks: func(h *testHarness) {
				h.keychain.GetSecretFunc = func(account, service string) ([]byte, error) {
					return nil, fmt.Errorf("secret not found")
				}
			},
			wantExitCode: 1,
		},
		"setup error": {
			args: []string{"sesh", "--service", "aws", "--setup"},
			setupMocks: func(h *testHarness) {
				h.app.SetupService = &MockSetupService{
					SetupServiceFunc: func(serviceName string) error {
						return fmt.Errorf("setup wizard failed")
					},
				}
			},
			wantExitCode: 1,
			checkStderr: func(t *testing.T, stderr string) {
				if !strings.Contains(stderr, "setup failed") {
					t.Error("Expected setup failure message")
				}
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			h := newTestHarness()

			exitCode := -1
			h.app.Exit = func(code int) { exitCode = code }

			if tc.setupMocks != nil {
				tc.setupMocks(h)
			}

			run(h.app, tc.args)

			if exitCode == -1 {
				exitCode = 0
			}

			if exitCode != tc.wantExitCode {
				t.Errorf("Exit code = %d, want %d", exitCode, tc.wantExitCode)
				t.Logf("stdout: %q", h.stdout.String())
				t.Logf("stderr: %q", h.stderr.String())
			}

			if tc.checkStdout != nil {
				tc.checkStdout(t, h.stdout.String())
			}
			if tc.checkStderr != nil {
				tc.checkStderr(t, h.stderr.String())
			}
		})
	}
}

func TestRun_FlagValidation(t *testing.T) {
	tests := map[string]struct {
		setupMocks   func(*testHarness)
		checkStderr  func(*testing.T, string)
		args         []string
		wantExitCode int
	}{
		"missing required service flag": {
			args:         []string{"sesh", "--profile", "dev"},
			wantExitCode: 1,
			checkStderr: func(t *testing.T, stderr string) {
				if !strings.Contains(stderr, "service") {
					t.Error("Expected error about missing service flag")
				}
			},
		},
		"invalid service name": {
			args:         []string{"sesh", "--service", "invalid"},
			wantExitCode: 1,
			checkStderr: func(t *testing.T, stderr string) {
				if !strings.Contains(stderr, "unknown service") && !strings.Contains(stderr, "invalid") {
					t.Errorf("Expected error about unknown service, got: %q", stderr)
				}
			},
		},
		"totp without required service-name": {
			args: []string{"sesh", "--service", "totp"},
			setupMocks: func(h *testHarness) {
				// TOTP provider's ValidateRequest should fail
			},
			wantExitCode: 1,
			checkStderr: func(t *testing.T, stderr string) {
				if !strings.Contains(stderr, "service-name") {
					t.Error("Expected error about missing service-name")
				}
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			h := newTestHarness()

			exitCode := -1
			h.app.Exit = func(code int) { exitCode = code }

			if tc.setupMocks != nil {
				tc.setupMocks(h)
			}

			run(h.app, tc.args)

			if exitCode == -1 {
				exitCode = 0
			}

			if exitCode != tc.wantExitCode {
				t.Errorf("Exit code = %d, want %d", exitCode, tc.wantExitCode)
				t.Logf("stdout: %q", h.stdout.String())
				t.Logf("stderr: %q", h.stderr.String())
			}

			if tc.checkStderr != nil {
				tc.checkStderr(t, h.stderr.String())
			}
		})
	}
}
