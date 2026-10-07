package main

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	awsMocks "github.com/bashhack/sesh/internal/aws/mocks"
	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/provider"
	awsProvider "github.com/bashhack/sesh/internal/provider/aws"
	passwordProvider "github.com/bashhack/sesh/internal/provider/password"
	totpProvider "github.com/bashhack/sesh/internal/provider/totp"
	"github.com/bashhack/sesh/internal/testutil"
	totpMocks "github.com/bashhack/sesh/internal/totp/mocks"
	"github.com/bashhack/sesh/internal/vault"
)

// TestHelperProcess is needed for the testutil.MockExecCommand function
func TestHelperProcess(_ *testing.T) {
	testutil.TestHelperProcess()
}

// testHarness bundles a test App with its mock dependencies and output buffers.
type testHarness struct {
	app    *App
	stdout *bytes.Buffer
	stderr *bytes.Buffer
	store  *harnessStore
	aws    *awsMocks.MockProvider
	totp   *totpMocks.MockProvider
}

// harnessStore is an in-memory vault whose List and Delete can be made to
// fail.
type harnessStore struct {
	*vault.MemStore
	listErr, deleteErr error
}

func (s *harnessStore) List(f *vault.Filter) ([]vault.Entry, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.MemStore.List(f)
}

func (s *harnessStore) Delete(k vault.Key) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	return s.MemStore.Delete(k)
}

func (s *harnessStore) DeleteMany(keys []vault.Key) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	return s.MemStore.DeleteMany(keys)
}

// put stores a TOTP secret under the entry id names (kind/service[/username]).
func (s *harnessStore) put(id string) {
	k, err := vault.ParseKey(id)
	if err != nil {
		panic(err)
	}
	if err := s.Put(k, []byte("JBSWY3DPEHPK3PXP")); err != nil {
		panic(err)
	}
}

func newTestHarness() *testHarness {
	mockKC := &harnessStore{MemStore: vault.NewMemStore()}
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
			Stdin:         bytes.NewReader(nil),
			Stdout:        stdoutBuf,
			Stderr:        stderrBuf,
			VersionInfo:   VersionInfo{Version: "test-version", Commit: "test-commit", Date: "test-date"},
		},
		stdout: stdoutBuf,
		stderr: stderrBuf,
		store:  mockKC,
		aws:    mockAWS,
		totp:   mockTOTP,
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
				h.store.put("totp/aws/default")
				h.store.put("totp/aws/dev")
			},
			wantExitCode: 0,
		},
		"totp with service-name flag": {
			args: []string{"sesh", "--service", "totp", "--service-name", "github", "--clip"},
			setupMocks: func(h *testHarness) {
				h.store.put("totp/github")

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
			args:         []string{"sesh", "--service", "aws", "--list"},
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
				h.store.listErr = fmt.Errorf("store error")
			},
			wantExitCode: 1,
		},
		"delete entry": {
			args: []string{"sesh", "--service", "totp", "--force", "--delete", "totp/github"},
			setupMocks: func(h *testHarness) {
				h.store.put("totp/github")
			},
			wantExitCode: 0,
		},
		"delete several entries": {
			args: []string{"sesh", "--service", "totp", "--force", "--delete", "totp/github", "totp/gitlab"},
			setupMocks: func(h *testHarness) {
				h.store.put("totp/github")
				h.store.put("totp/gitlab")
			},
			wantExitCode: 0,
			checkStdout: func(t *testing.T, stdout string) {
				if !strings.Contains(stdout, "Deleted 2 entries") {
					t.Errorf("stdout = %q", stdout)
				}
			},
		},
		"delete without a terminal or --force": {
			args: []string{"sesh", "--service", "totp", "--delete", "totp/github"},
			setupMocks: func(h *testHarness) {
				h.store.put("totp/github")
			},
			wantExitCode: 1,
			checkStderr: func(t *testing.T, stderr string) {
				if !strings.Contains(stderr, "add --force to delete without asking") {
					t.Errorf("stderr = %q", stderr)
				}
			},
		},
		"delete with several bad IDs": {
			args:         []string{"sesh", "--service", "totp", "--force", "--delete", "bad1", "totp/ok", "bad2"},
			wantExitCode: 1,
			checkStderr: func(t *testing.T, stderr string) {
				if !strings.Contains(stderr, "nothing was deleted:") || !strings.Contains(stderr, `"bad1"`) || !strings.Contains(stderr, `"bad2"`) {
					t.Errorf("stderr = %q, want both bad IDs named", stderr)
				}
			},
		},
		"delete with a flag after the IDs": {
			args:         []string{"sesh", "--service", "totp", "--delete", "totp/github", "totp/gitlab", "--force"},
			wantExitCode: 1,
			checkStderr: func(t *testing.T, stderr string) {
				if !strings.Contains(stderr, `"--force" looks like a flag: put flags before the entry IDs`) {
					t.Errorf("stderr = %q", stderr)
				}
			},
		},
		"delete entry invalid id": {
			args:         []string{"sesh", "--service", "totp", "--delete", "bad-id"},
			wantExitCode: 1,
		},
		"delete entry store error": {
			args: []string{"sesh", "--service", "totp", "--force", "--delete", "totp/github"},
			setupMocks: func(h *testHarness) {
				h.store.put("totp/github")
				h.store.deleteErr = fmt.Errorf("store delete failed")
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
				h.app.ClipboardCopy = func(text string) error {
					return fmt.Errorf("clipboard unavailable")
				}
			},
			wantExitCode: 1,
		},
		"generate credentials error": {
			args: []string{"sesh", "--service", "totp", "--service-name", "github"},
			setupMocks: func(h *testHarness) {
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

func TestArgsParse(t *testing.T) {
	for name, tt := range map[string]struct {
		args []string
		want bool
	}{
		"a service and its flags":      {args: []string{"sesh", "--service", "password", "--action", "search", "--query", "x"}, want: true},
		"an unknown flag":              {args: []string{"sesh", "--service", "password", "--bogus"}, want: false},
		"an unknown flag, no service":  {args: []string{"sesh", "--bogus"}, want: false},
		"an unknown service":           {args: []string{"sesh", "--service", "nope"}, want: false},
		"help for a service":           {args: []string{"sesh", "--service", "password", "--help"}, want: false},
		"a provider's flag on another": {args: []string{"sesh", "--service", "aws", "--action", "get"}, want: false},
		"the = form":                   {args: []string{"sesh", "--service=password", "--action=list"}, want: true},
		"help with a value":            {args: []string{"sesh", "--service", "password", "--help=true"}, want: false},
		"a bad value for a typed flag": {args: []string{"sesh", "--service", "password", "--length", "abc"}, want: false},
		"two services":                 {args: []string{"sesh", "--service", "totp", "--service", "aws"}, want: false},
		"version with a value":         {args: []string{"sesh", "--service", "password", "--version=true"}, want: false},
		"list services with a value":   {args: []string{"sesh", "--service", "password", "--list-services=true"}, want: false},
		"a name no entry can have":     {args: []string{"sesh", "--service", "password", "--action", "store", "--service-name", "github "}, want: false},
		"a negative limit":             {args: []string{"sesh", "--service", "password", "--list", "--limit", "-1"}, want: false},
		"a bad entry ID to delete":     {args: []string{"sesh", "--service", "password", "--delete", "password/github "}, want: false},
		"a bad second ID to delete":    {args: []string{"sesh", "--service", "password", "--force", "--delete", "password/github", "bad"}, want: false},
		"a flag after the IDs":         {args: []string{"sesh", "--service", "totp", "--delete", "totp/a", "totp/b", "--force"}, want: false},
		"delete, forced":               {args: []string{"sesh", "--service", "totp", "--force", "--delete", "totp/a", "totp/b"}, want: true},
		"delete, nobody to ask":        {args: []string{"sesh", "--service", "aws", "--delete", "totp/aws/dev"}, want: false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := argsParse(tt.args); got != tt.want {
				t.Errorf("argsParse(%q) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

func TestNeedsCredentialStore(t *testing.T) {
	tests := map[string]struct {
		args []string
		want bool
	}{
		"no args":               {args: []string{"sesh"}, want: false},
		"just --help":           {args: []string{"sesh", "--help"}, want: false},
		"short -h":              {args: []string{"sesh", "-h"}, want: false},
		"--version":             {args: []string{"sesh", "--version"}, want: false},
		"--list-services":       {args: []string{"sesh", "--list-services"}, want: false},
		"--service aws":         {args: []string{"sesh", "--service", "aws"}, want: true},
		"--service aws --help":  {args: []string{"sesh", "--service", "aws", "--help"}, want: false},
		"--service aws --list":  {args: []string{"sesh", "--service", "aws", "--list"}, want: true},
		"--service aws --setup": {args: []string{"sesh", "--service", "aws", "--setup"}, want: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := needsCredentialStore(tc.args); got != tc.want {
				t.Errorf("needsCredentialStore(%v) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

func TestResolvePasswordPrompt_EnvVarYieldsConstantNonInteractive(t *testing.T) {
	// SESH_MASTER_PASSWORD short-circuits the terminal read with a
	// constant-bytes prompt. Such a prompt cannot meaningfully retry —
	// it would derive the same wrong key N times — so interactive must
	// be false to keep the retry budget off.
	t.Setenv("SESH_MASTER_PASSWORD", "secret-from-env")
	cfg := resolvePasswordPrompt()
	if cfg.interactive {
		t.Error("env-var prompt must not be marked interactive")
	}
	pw, err := cfg.prompt("ignored")
	if err != nil {
		t.Fatalf("env-var prompt should not error: %v", err)
	}
	if string(pw) != "secret-from-env" {
		t.Errorf("env-var prompt returned %q, want %q", pw, "secret-from-env")
	}
}

func TestResolvePasswordPrompt_NonTTYIsTerminalPromptButNotInteractive(t *testing.T) {
	// `go test` runs with stdin not attached to a terminal. We still pick
	// the terminal-read prompt (so a TTY-bound caller would work), but
	// interactive stays false — no retry budget for piped/scripted callers.
	t.Setenv("SESH_MASTER_PASSWORD", "")
	cfg := resolvePasswordPrompt()
	if cfg.interactive {
		t.Error("non-TTY stdin must not be marked interactive")
	}
	if cfg.prompt == nil {
		t.Fatal("prompt callback should be set even when not interactive")
	}
}

// --list checks its paging flags like the other actions, rather than
// failing on the vault it was right not to open.
func TestList_RefusesNegativePaging(t *testing.T) {
	for _, args := range [][]string{
		{"sesh", "--service", "password", "--list", "--limit", "-1"},
		{"sesh", "--service", "password", "--list", "--offset", "-3"},
	} {
		h := newTestHarness()
		h.app.Registry.RegisterProvider(passwordProvider.NewProvider(vault.NewMemStore()))
		code := 0
		h.app.Exit = func(c int) { code = c }
		run(h.app, args)
		if code == 0 || !strings.Contains(h.stderr.String(), "wants 0") {
			t.Errorf("%q: exit %d, stderr %q; want the flag refused", args, code, h.stderr.String())
		}
	}
}

// Whatever the early check refuses is reported as itself on every path,
// never as the missing store the CLI was right not to open.
func TestRun_ReportsWhatTheEarlyCheckRefuses(t *testing.T) {
	for name, args := range map[string][]string{
		"--list, negative limit":   {"--service", "password", "--list", "--limit", "-1"},
		"--delete, negative limit": {"--service", "password", "--delete", "password/a", "--limit", "-1"},
		"--clip, bad name":         {"--service", "password", "--service-name", "github ", "--clip"},
		"get, bad name":            {"--service", "password", "--action", "get", "--service-name", "github "},
		"totp, bad name":           {"--service", "totp", "--service-name", "github "},
		"aws, bad profile":         {"--service", "aws", "--profile", "prod "},
		"--delete, bad entry ID":   {"--service", "password", "--delete", "password/github "},
	} {
		t.Run(name, func(t *testing.T) {
			full := append([]string{"sesh"}, args...)
			if argsParse(full) {
				t.Errorf("argsParse(%q) = true, want the early check to refuse", full)
			}
			app := NewDefaultApp(VersionInfo{}, unavailableStore{err: errNoStore}, AppSettings{ClipboardTimeout: config.DefaultClipboardTimeout})
			var stderr bytes.Buffer
			app.Stdout, app.Stderr = io.Discard, &stderr
			code := 0
			app.Exit = func(c int) { code = c }
			run(app, full)
			if code == 0 || strings.Contains(stderr.String(), "no credential store opened") {
				t.Errorf("exit %d, stderr %q; want the real error", code, stderr.String())
			}
		})
	}
}

// The early check covers only what the selected command uses: setup asks
// for its own names, and --list and --delete don't use a profile.
func TestEarlyCheck_OnlyWhatTheCommandUses(t *testing.T) {
	t.Setenv("AWS_PROFILE", "Prod/Admin")
	for name, tt := range map[string]struct {
		wantSub string
		args    []string
	}{
		"aws setup":            {args: []string{"sesh", "--service", "aws", "--setup"}},
		"aws list":             {args: []string{"sesh", "--service", "aws", "--list"}},
		"aws delete":           {args: []string{"sesh", "--service", "aws", "--force", "--delete", "totp/aws/dev"}},
		"aws credentials":      {args: []string{"sesh", "--service", "aws"}, wantSub: `AWS_PROFILE: the AWS profile "Prod/Admin" contains "/"`},
		"password list paging": {args: []string{"sesh", "--service", "password", "--list", "--limit", "-1"}, wantSub: "--limit wants 0"},
		"list with a bad ID":   {args: []string{"sesh", "--service", "totp", "--list", "--delete", "bad"}, wantSub: `entry ID "bad"`},
	} {
		t.Run(name, func(t *testing.T) {
			if got := argsParse(tt.args); got != (tt.wantSub == "") {
				t.Errorf("argsParse = %v, want %v", got, tt.wantSub == "")
			}
			if tt.wantSub == "" {
				return
			}
			app := NewDefaultApp(VersionInfo{}, unavailableStore{err: errNoStore}, AppSettings{ClipboardTimeout: config.DefaultClipboardTimeout})
			var stderr bytes.Buffer
			app.Stdout, app.Stderr = io.Discard, &stderr
			app.Exit = func(int) {}
			run(app, tt.args)
			if !strings.Contains(stderr.String(), tt.wantSub) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantSub)
			}
		})
	}
}

// --folder and --tag go only with a command that stores an entry or lists
// entries, and a name no folder or tag can have is refused before the
// vault opens.
func TestEarlyCheck_FolderAndTag(t *testing.T) {
	const pwWhere = "--folder and --tag file an entry as it's stored, or narrow a list: use them with --action store, generate, totp-store, search, or export, or with --list"
	const withDelete = "--folder and --tag don't go with --delete: name the entries to delete by ID"
	for name, tt := range map[string]struct {
		wantSub string
		args    []string
	}{
		"password store":        {args: []string{"sesh", "--service", "password", "--action", "store", "--service-name", "x", "--folder", "work/dev", "--tag", "a", "--tag", "b"}},
		"password generate":     {args: []string{"sesh", "--service", "password", "--action", "generate", "--service-name", "x", "--tag", "a"}},
		"password totp-store":   {args: []string{"sesh", "--service", "password", "--action", "totp-store", "--service-name", "x", "--folder", ""}},
		"password search":       {args: []string{"sesh", "--service", "password", "--action", "search", "--query", "x", "--folder", "work"}},
		"password export":       {args: []string{"sesh", "--service", "password", "--action", "export", "--tag", "a"}},
		"password list":         {args: []string{"sesh", "--service", "password", "--list", "--tag", "a"}},
		"totp list":             {args: []string{"sesh", "--service", "totp", "--list", "--folder", "work"}},
		"aws list":              {args: []string{"sesh", "--service", "aws", "--list", "--tag", "a"}},
		"totp setup":            {args: []string{"sesh", "--service", "totp", "--setup", "--folder", "work", "--tag", "a"}},
		"aws setup":             {args: []string{"sesh", "--service", "aws", "--setup", "--tag", "a"}},
		"password get":          {args: []string{"sesh", "--service", "password", "--action", "get", "--service-name", "x", "--folder", "w"}, wantSub: pwWhere},
		"password import":       {args: []string{"sesh", "--service", "password", "--action", "import", "--tag", "a"}, wantSub: pwWhere},
		"password delete":       {args: []string{"sesh", "--service", "password", "--force", "--delete", "password/x", "--tag", "a"}, wantSub: withDelete},
		"list and delete":       {args: []string{"sesh", "--service", "totp", "--list", "--force", "--delete", "totp/x", "--tag", "a"}, wantSub: withDelete},
		"totp code":             {args: []string{"sesh", "--service", "totp", "--service-name", "github", "--folder", "work"}, wantSub: "use them with --setup or --list"},
		"a bad folder":          {args: []string{"sesh", "--service", "password", "--action", "store", "--service-name", "x", "--folder", "/work"}, wantSub: `the folder "/work" has an empty part`},
		"a bad tag, with setup": {args: []string{"sesh", "--service", "aws", "--setup", "--tag", "a b"}, wantSub: `the tag "a b" contains ' '`},
		"a bad tag, listing":    {args: []string{"sesh", "--service", "totp", "--list", "--tag", "-x"}, wantSub: `the tag "-x" can't start with "-"`},
	} {
		t.Run(name, func(t *testing.T) {
			if got := argsParse(tt.args); got != (tt.wantSub == "") {
				t.Errorf("argsParse = %v, want %v", got, tt.wantSub == "")
			}
			if tt.wantSub == "" {
				return
			}
			app := NewDefaultApp(VersionInfo{}, unavailableStore{err: errNoStore}, AppSettings{ClipboardTimeout: config.DefaultClipboardTimeout})
			var stderr bytes.Buffer
			app.Stdout, app.Stderr = io.Discard, &stderr
			app.Exit = func(int) {}
			run(app, tt.args)
			if !strings.Contains(stderr.String(), tt.wantSub) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantSub)
			}
		})
	}
}

// --folder and --tag narrow --list, and a list that finds nothing says
// when the folder or tag differs only by case.
func TestRun_ListByFolderAndTag(t *testing.T) {
	for name, tt := range map[string]struct {
		want string
		args []string
	}{
		"a folder": {args: []string{"--folder", "work"}, want: "Entries for totp:\n" +
			"  NAME    TYPE  FOLDER    TAGS  ID\n" +
			"  github  totp  work/dev  2fa   totp/github\n"},
		"a tag": {args: []string{"--tag", "2fa"}, want: "Entries for totp:\n" +
			"  NAME    TYPE  FOLDER    TAGS  ID\n" +
			"  github  totp  work/dev  2fa   totp/github\n"},
		"no folder": {args: []string{"--folder", ""}, want: "Entries for totp:\n" +
			"  NAME  TYPE  ID\n" +
			"  bank  totp  totp/bank\n"},
		"another case": {args: []string{"--folder", "Work"}, want: "Entries for totp:\n" +
			`  No entries found: there's no folder "Work"; did you mean work? Folders and tags are case-sensitive` + "\n"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestHarness()
			for _, e := range []*vault.Entry{
				{Kind: vault.KindTOTP, Service: "github", Folder: "work/dev", Tags: []string{"2fa"}},
				{Kind: vault.KindTOTP, Service: "bank"},
			} {
				if err := h.store.Save(e, []byte("JBSWY3DPEHPK3PXP")); err != nil {
					t.Fatal(err)
				}
			}
			code := 0
			h.app.Exit = func(c int) { code = c }
			run(h.app, append([]string{"sesh", "--service", "totp", "--list"}, tt.args...))
			if code != 0 || h.stdout.String() != tt.want {
				t.Errorf("exit %d, stdout:\n%s\nwant:\n%s\nstderr: %s", code, h.stdout.String(), tt.want, h.stderr.String())
			}
		})
	}
}
