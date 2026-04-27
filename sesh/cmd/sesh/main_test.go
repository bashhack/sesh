package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	awsMocks "github.com/bashhack/sesh/internal/aws/mocks"
	"github.com/bashhack/sesh/internal/database"
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
			Stdin:         bytes.NewReader(nil),
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

// flockMockKC satisfies the two-method interface that database.KeychainSource
// consumes. It is goroutine-safe and tracks call counts so tests can assert on
// how many times ensureMasterKey crossed into the generate-and-store branch.
//
// Fields are ordered pointer-heavy first so govet's fieldalignment is happy.
type flockMockKC struct {
	getErr error
	setErr error

	// beforeGet fires before GetSecret reads the stored state. The callback
	// receives the current call count (1-indexed) so tests can simulate a
	// concurrent state change between specific calls — e.g. inject a stored
	// key right before ensureMasterKey's post-lock double-check.
	beforeGet func(callNum int32)

	stored []byte
	mu     sync.Mutex

	getCount atomic.Int32
	setCount atomic.Int32
}

func (m *flockMockKC) GetSecret(_, _ string) ([]byte, error) {
	n := m.getCount.Add(1)
	if fn := m.beforeGet; fn != nil {
		fn(n)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getErr != nil {
		return nil, m.getErr
	}
	if m.stored == nil {
		return nil, keychain.ErrNotFound
	}
	return append([]byte{}, m.stored...), nil
}

func (m *flockMockKC) SetSecret(_, _ string, secret []byte) error {
	m.setCount.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.setErr != nil {
		return m.setErr
	}
	m.stored = append([]byte{}, secret...)
	return nil
}

func TestEnsureMasterKey_FastPath(t *testing.T) {
	// Stored value is the hex-encoded form of 32 raw bytes; KeychainSource
	// decodes on read.
	kc := &flockMockKC{stored: []byte(strings.Repeat("ab", 32))}
	ks := database.NewKeychainSource(kc, "testuser")

	if err := ensureMasterKey(ks, t.TempDir()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := kc.setCount.Load(); got != 0 {
		t.Errorf("SetSecret call count = %d, want 0 on fast path", got)
	}
	if got := kc.getCount.Load(); got != 1 {
		t.Errorf("GetSecret call count = %d, want 1 (fast path only)", got)
	}
}

func TestEnsureMasterKey_SlowPath_Generates(t *testing.T) {
	kc := &flockMockKC{}
	ks := database.NewKeychainSource(kc, "testuser")

	if err := ensureMasterKey(ks, t.TempDir()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := kc.setCount.Load(); got != 1 {
		t.Errorf("SetSecret call count = %d, want 1 on slow path", got)
	}
	// Stored form is hex-encoded (2 ASCII chars per raw byte).
	if len(kc.stored) != 64 {
		t.Errorf("stored hex length = %d, want 64 (hex of 32 raw bytes)", len(kc.stored))
	}
}

func TestEnsureMasterKey_SlowPath_DoubleCheck(t *testing.T) {
	// The fast-path GetSecret returns ErrNotFound, but by the time we
	// acquire the flock another process has stored a key. The post-lock
	// re-read must see it and skip generation — otherwise we'd orphan
	// whatever the other process already encrypted.
	kc := &flockMockKC{}
	kc.beforeGet = func(n int32) {
		if n == 2 {
			kc.mu.Lock()
			// Hex-encoded form of a 32-byte key (all 0xCD).
			kc.stored = []byte(strings.Repeat("cd", 32))
			kc.mu.Unlock()
		}
	}
	ks := database.NewKeychainSource(kc, "testuser")

	if err := ensureMasterKey(ks, t.TempDir()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := kc.setCount.Load(); got != 0 {
		t.Errorf("SetSecret call count = %d, want 0 when double-check finds a key", got)
	}
}

func TestEnsureMasterKey_NonNotFoundErrorIsSurfaced(t *testing.T) {
	sentinel := errors.New("keychain locked")
	kc := &flockMockKC{getErr: sentinel}
	ks := database.NewKeychainSource(kc, "testuser")

	err := ensureMasterKey(ks, t.TempDir())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// Must not generate a new key when the read failure is ambiguous —
	// doing so would orphan the existing (undecryptable) data.
	if got := kc.setCount.Load(); got != 0 {
		t.Errorf("SetSecret call count = %d, want 0 on ambiguous get error", got)
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
		"--migrate":             {args: []string{"sesh", "--migrate"}, want: false},
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

func TestEnsureMasterKey_Concurrent(t *testing.T) {
	// Stress-test the flock: N goroutines race through ensureMasterKey
	// against a shared keychain. Exactly one must generate and store.
	kc := &flockMockKC{}
	ks := database.NewKeychainSource(kc, "testuser")
	dataDir := t.TempDir()

	const n = 20
	errs := make(chan error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			<-start
			errs <- ensureMasterKey(ks, dataDir)
		})
	}
	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	}
	if got := kc.setCount.Load(); got != 1 {
		t.Errorf("SetSecret call count = %d across %d concurrent invocations, want exactly 1", got, n)
	}
	// Stored form is hex-encoded (2 ASCII chars per raw byte).
	if len(kc.stored) != 64 {
		t.Errorf("stored hex length = %d, want 64 (hex of 32 raw bytes)", len(kc.stored))
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
