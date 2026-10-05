package keychain

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/testutil"
)

// --- Helper to save/restore all mockable functions ---

type mockState struct {
	getCurrentUser  func() (string, error)
	captureSecure   func(*exec.Cmd) ([]byte, error)
	execSecretInput func(*exec.Cmd, []byte) error
	execCommand     func(string, ...string) *exec.Cmd
}

func saveMocks() mockState {
	return mockState{
		getCurrentUser:  getCurrentUser,
		captureSecure:   captureSecure,
		execSecretInput: execSecretInput,
		execCommand:     execCommand,
	}
}

func (m mockState) restore() {
	getCurrentUser = m.getCurrentUser
	captureSecure = m.captureSecure
	execSecretInput = m.execSecretInput
	execCommand = m.execCommand
}

// --- Tests using in-process mocks (pattern 1) ---

func TestGetCurrentUserDefault(t *testing.T) {
	// Exercise the real getCurrentUser (calls whoami)
	user, err := getCurrentUser()
	if err != nil {
		t.Fatalf("getCurrentUser: %v", err)
	}
	if user == "" {
		t.Fatal("getCurrentUser returned empty string")
	}
}

func TestGetSecretBytesSuccess(t *testing.T) {
	orig := saveMocks()
	defer orig.restore()

	captureSecure = func(cmd *exec.Cmd) ([]byte, error) {
		return []byte("test-secret"), nil
	}

	secretBytes, err := GetSecretBytes("testuser", "test-service")
	if err != nil {
		t.Errorf("Expected no error but got: %v", err)
	}
	if string(secretBytes) != "test-secret" {
		t.Errorf("Expected secret 'test-secret', got '%s'", string(secretBytes))
	}
}

func TestGetSecretWithEmptyUsername(t *testing.T) {
	orig := saveMocks()
	defer orig.restore()

	getCurrentUser = func() (string, error) {
		return "testuser", nil
	}
	captureSecure = func(cmd *exec.Cmd) ([]byte, error) {
		return []byte("test-secret"), nil
	}

	secretBytes, err := GetSecretBytes("", "test-service")
	if err != nil {
		t.Errorf("Expected no error but got: %v", err)
	}
	if string(secretBytes) != "test-secret" {
		t.Errorf("Expected secret 'test-secret', got '%s'", string(secretBytes))
	}
}

func TestGetSecretWithWhoamiError(t *testing.T) {
	orig := saveMocks()
	defer orig.restore()

	getCurrentUser = func() (string, error) {
		return "", fmt.Errorf("whoami failed")
	}

	_, err := GetSecretBytes("", "test-service")
	if err == nil {
		t.Error("Expected error but got nil")
	}
	if !strings.Contains(err.Error(), "could not determine current user") {
		t.Errorf("Expected error with 'could not determine current user', got: %s", err.Error())
	}
}

func TestGetSecretWithSecurityError(t *testing.T) {
	orig := saveMocks()
	defer orig.restore()

	captureSecure = func(cmd *exec.Cmd) ([]byte, error) {
		return nil, fmt.Errorf("security command failed")
	}

	_, err := GetSecretBytes("testuser", "test-service")
	if err == nil {
		t.Error("Expected error but got nil")
	}
	if !strings.Contains(err.Error(), "keychain read failed") {
		t.Errorf("Expected error with 'keychain read failed', got: %s", err.Error())
	}
}

// TestGetSecretBytesNotFound uses the subprocess mock pattern (pattern 2)
// because it tests exit code 44 handling, which requires a real process exit.
// See internal/testutil/exec_mock.go for documentation on both patterns.
func TestGetSecretBytesNotFound(t *testing.T) {
	orig := saveMocks()
	defer orig.restore()

	execCommand = func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{
			"GO_WANT_HELPER_PROCESS=1",
		}
		if command == "security" {
			cmd.Env = append(cmd.Env, "MOCK_ERROR=1", "MOCK_EXIT_CODE=44")
		}
		return cmd
	}
	// Use the real captureSecure so it actually runs the subprocess
	captureSecure = orig.captureSecure

	_, err := GetSecretBytes("testuser", "test-service")
	if err == nil {
		t.Fatal("Expected error but got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Expected ErrNotFound, got: %v", err)
	}
}

func TestSetSecretBytes(t *testing.T) {
	orig := saveMocks()
	defer orig.restore()

	execSecretInput = func(cmd *exec.Cmd, input []byte) error {
		return nil
	}

	err := SetSecretBytes("testuser", "test-service", []byte("test-secret"))
	if err != nil {
		t.Errorf("Expected no error but got: %v", err)
	}

	// Test with error
	execSecretInput = func(cmd *exec.Cmd, input []byte) error {
		return fmt.Errorf("security -i failed")
	}

	err = SetSecretBytes("testuser", "test-service", []byte("test-secret"))
	if err == nil {
		t.Error("Expected error but got nil")
	}
}

func TestDeleteEntry(t *testing.T) {
	orig := saveMocks()
	defer orig.restore()

	// DeleteEntry uses execCommand + cmd.Run() directly — keep subprocess pattern
	execCommand = func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{
			"GO_WANT_HELPER_PROCESS=1",
		}
		return cmd
	}

	err := DeleteEntry("testuser", "test-service")
	if err != nil {
		t.Errorf("Expected no error but got: %v", err)
	}

	execCommand = func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{
			"GO_WANT_HELPER_PROCESS=1",
			"MOCK_ERROR=1",
		}
		return cmd
	}

	err = DeleteEntry("testuser", "test-service")
	if err == nil {
		t.Error("Expected error but got nil")
	}

	// An item that isn't there is ErrNotFound, so callers can treat
	// "already gone" as done.
	execCommand = func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1", "MOCK_ERROR=1", "MOCK_EXIT_CODE=44"}
		return cmd
	}
	if err := DeleteEntry("testuser", "test-service"); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteEntry of a missing item = %v, want ErrNotFound", err)
	}
}

func TestItems_UseTheKeychain(t *testing.T) {
	orig := saveMocks()
	defer orig.restore()
	captureSecure = func(*exec.Cmd) ([]byte, error) { return []byte("the-key"), nil }
	var stored []byte
	execSecretInput = func(_ *exec.Cmd, input []byte) error {
		stored = append([]byte(nil), input...)
		return nil
	}

	got, err := Items{}.GetSecret("me", "sesh-sqlite-encryption-key")
	if err != nil || string(got) != "the-key" {
		t.Errorf("GetSecret = %q, %v; want the item's secret", got, err)
	}
	if err := (Items{}).SetSecret("me", "sesh-sqlite-encryption-key", []byte("new-key")); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}
	if !strings.Contains(string(stored), "add-generic-password -a me -s sesh-sqlite-encryption-key -w new-key") {
		t.Errorf("SetSecret sent %q to security, want an add-generic-password for the item", stored)
	}
}

func TestGetSecretIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping keychain test in short mode")
	}

	orig := saveMocks()
	defer orig.restore()

	// Use real implementations for integration test
	getCurrentUser = orig.getCurrentUser
	captureSecure = orig.captureSecure
	execCommand = orig.execCommand

	randStr, err := testutil.RandomString(8)
	if err != nil {
		t.Fatalf("Failed to generate random string: %v", err)
	}
	nonExistentService := "test-sesh-nonexistent-" + randStr

	_, err = GetSecretBytes("", nonExistentService)
	if err == nil {
		t.Error("Expected error for non-existent keychain item, got nil")
	}
}

func TestSetSecretBytesWithEmptyAccount(t *testing.T) {
	orig := saveMocks()
	defer orig.restore()

	whoamiCalled := false
	securityCalled := false

	getCurrentUser = func() (string, error) {
		whoamiCalled = true
		return "testuser", nil
	}
	execSecretInput = func(cmd *exec.Cmd, input []byte) error {
		securityCalled = true
		return nil
	}

	err := SetSecretBytes("", "test-service", []byte("test-secret"))
	if err != nil {
		t.Errorf("Expected no error but got: %v", err)
	}

	if !whoamiCalled {
		t.Error("Expected getCurrentUser to be called")
	}
	if !securityCalled {
		t.Error("Expected security command to be called")
	}
}

// TestDeleteEntryWithEmptyAccount uses the subprocess mock pattern (pattern 2)
// because DeleteEntry uses execCommand + cmd.Run() with stderr capture.
// See internal/testutil/exec_mock.go for documentation on both patterns.
func TestDeleteEntryWithEmptyAccount(t *testing.T) {
	orig := saveMocks()
	defer orig.restore()

	whoamiCalled := false
	deleteCalled := false

	getCurrentUser = func() (string, error) {
		whoamiCalled = true
		return "testuser", nil
	}

	execCommand = func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{
			"GO_WANT_HELPER_PROCESS=1",
		}

		if command == "security" {
			deleteCalled = true
			if len(args) > 0 && args[0] == "delete-generic-password" {
				for i, arg := range args {
					if arg == "-a" && i+1 < len(args) {
						if args[i+1] != "testuser" {
							t.Errorf("Expected account 'testuser', got %q", args[i+1])
						}
					}
				}
			}
		}

		return cmd
	}

	err := DeleteEntry("", "test-service")
	if err != nil {
		t.Errorf("Expected no error but got: %v", err)
	}

	if !whoamiCalled {
		t.Error("Expected getCurrentUser to be called")
	}
	if !deleteCalled {
		t.Error("Expected security delete command to be called")
	}
}

// TestHelperProcess is the subprocess entry point for pattern 2 tests.
// It is NOT a real test — it runs only when GO_WANT_HELPER_PROCESS=1.
// See internal/testutil/exec_mock.go for documentation.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	args := os.Args
	for i, arg := range args {
		if arg == "--" {
			args = args[i+1:]
			break
		}
	}

	if len(args) < 1 {
		os.Exit(1)
	}

	command := args[0]
	cmdArgs := args[1:]

	switch command {
	case "security":
		if len(cmdArgs) > 0 && cmdArgs[0] == "-i" {
			stdin, err := io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to read stdin: %v\n", err)
				os.Exit(1)
			}
			stdinStr := string(stdin)
			if strings.Contains(stdinStr, "add-generic-password") {
				if os.Getenv("MOCK_ERROR") == "1" {
					os.Exit(1)
				}
				os.Exit(0)
			}
			os.Exit(1)
		} else {
			if os.Getenv("MOCK_ERROR") == "1" {
				exitCode := 1
				if ec := os.Getenv("MOCK_EXIT_CODE"); ec != "" {
					if _, err := fmt.Sscanf(ec, "%d", &exitCode); err != nil {
						fmt.Fprintf(os.Stderr, "failed to parse MOCK_EXIT_CODE: %v\n", err)
					}
				}
				os.Exit(exitCode)
			}
			fmt.Print(os.Getenv("MOCK_OUTPUT"))
			os.Exit(0)
		}
	case "whoami":
		if os.Getenv("MOCK_ERROR") == "1" {
			os.Exit(1)
		}
		fmt.Print(os.Getenv("MOCK_OUTPUT"))
		os.Exit(0)
	default:
		if os.Getenv("MOCK_ERROR") == "1" {
			os.Exit(1)
		}
		fmt.Print(os.Getenv("MOCK_OUTPUT"))
		os.Exit(0)
	}
}
