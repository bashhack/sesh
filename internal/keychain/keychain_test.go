package keychain

import (
	"bytes"
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

func TestGetMFASerialSuccess(t *testing.T) {
	orig := saveMocks()
	defer orig.restore()

	captureSecure = func(cmd *exec.Cmd) ([]byte, error) {
		return []byte("arn:aws:iam::123456789012:mfa/user"), nil
	}

	serialBytes, err := GetMFASerialBytes("testuser", "")
	if err != nil {
		t.Errorf("Expected no error but got: %v", err)
	}
	if string(serialBytes) != "arn:aws:iam::123456789012:mfa/user" {
		t.Errorf("Expected serial 'arn:aws:iam::123456789012:mfa/user', got '%s'", string(serialBytes))
	}
}

func TestGetMFASerialWithEmptyUsername(t *testing.T) {
	orig := saveMocks()
	defer orig.restore()

	getCurrentUser = func() (string, error) {
		return "testuser", nil
	}
	captureSecure = func(cmd *exec.Cmd) ([]byte, error) {
		return []byte("arn:aws:iam::123456789012:mfa/user"), nil
	}

	serialBytes, err := GetMFASerialBytes("", "")
	if err != nil {
		t.Errorf("Expected no error but got: %v", err)
	}
	if string(serialBytes) != "arn:aws:iam::123456789012:mfa/user" {
		t.Errorf("Expected serial 'arn:aws:iam::123456789012:mfa/user', got '%s'", string(serialBytes))
	}
}

func TestGetMFASerialWithWhoamiError(t *testing.T) {
	orig := saveMocks()
	defer orig.restore()

	getCurrentUser = func() (string, error) {
		return "", fmt.Errorf("whoami failed")
	}

	_, err := GetMFASerialBytes("", "")
	if err == nil {
		t.Error("Expected error but got nil")
	}
	if !strings.Contains(err.Error(), "could not determine current user") {
		t.Errorf("Expected error with 'could not determine current user', got: %s", err.Error())
	}
}

func TestGetMFASerialWithSecurityError(t *testing.T) {
	orig := saveMocks()
	defer orig.restore()

	captureSecure = func(cmd *exec.Cmd) ([]byte, error) {
		return nil, fmt.Errorf("security command failed")
	}

	_, err := GetMFASerialBytes("testuser", "")
	if err == nil {
		t.Error("Expected error but got nil")
	}
	if !strings.Contains(err.Error(), "keychain read failed") {
		t.Errorf("Expected error with 'keychain read failed', got: %s", err.Error())
	}
}

func TestSetSecretBytes(t *testing.T) {
	orig := saveMocks()
	defer orig.restore()

	origLoad := loadEntryMetadataImpl
	origSave := saveEntryMetadataImpl
	defer func() {
		loadEntryMetadataImpl = origLoad
		saveEntryMetadataImpl = origSave
	}()
	loadEntryMetadataImpl = func(servicePrefix string) ([]KeychainEntryMeta, error) {
		return []KeychainEntryMeta{}, nil
	}
	saveEntryMetadataImpl = func(meta []KeychainEntryMeta) error {
		return nil
	}

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

func TestListEntries(t *testing.T) {
	originalFunc := loadEntryMetadataImpl
	defer func() { loadEntryMetadataImpl = originalFunc }()

	loadEntryMetadataImpl = func(servicePrefix string) ([]KeychainEntryMeta, error) {
		switch servicePrefix {
		case "sesh-mfa":
			return []KeychainEntryMeta{
				{
					Service:     "sesh-mfa",
					Account:     "testuser",
					Description: "AWS MFA Secret",
					ServiceType: "aws",
				},
			}, nil
		case "sesh-totp":
			return []KeychainEntryMeta{
				{
					Service:     "sesh-totp-github",
					Account:     "testuser",
					Description: "GitHub TOTP",
					ServiceType: "totp",
				},
			}, nil
		}

		return []KeychainEntryMeta{
			{
				Service:     "sesh-mfa",
				Account:     "testuser",
				Description: "AWS MFA Secret",
				ServiceType: "aws",
			},
			{
				Service:     "sesh-totp-github",
				Account:     "testuser",
				Description: "GitHub TOTP",
				ServiceType: "totp",
			},
		}, nil
	}

	entries, err := ListEntries("sesh-mfa")
	if err != nil {
		t.Errorf("Expected no error but got: %v", err)
	}

	if len(entries) != 1 {
		t.Errorf("Expected 1 entry but got %d", len(entries))
	}

	if entries[0].Service != "sesh-mfa" {
		t.Errorf("Expected service 'sesh-mfa' but got '%s'", entries[0].Service)
	}

	if entries[0].Account != "testuser" {
		t.Errorf("Expected account 'testuser' but got '%s'", entries[0].Account)
	}

	if entries[0].Description != "AWS MFA Secret" {
		t.Errorf("Expected description 'AWS MFA Secret' but got '%s'", entries[0].Description)
	}

	entries, err = ListEntries("sesh-totp")
	if err != nil {
		t.Errorf("Expected no error but got: %v", err)
	}

	if len(entries) != 1 {
		t.Errorf("Expected 1 entry but got %d", len(entries))
	}

	if entries[0].Service != "sesh-mfa" && entries[0].Service != "sesh-totp-github" {
		t.Errorf("Expected service 'sesh-mfa' or 'sesh-totp-github' but got '%s'", entries[0].Service)
	}

	t.Run("Error Case", func(t *testing.T) {
		loadEntryMetadataImpl = func(servicePrefix string) ([]KeychainEntryMeta, error) {
			return nil, fmt.Errorf("test error")
		}

		_, err = ListEntries("sesh-mfa")
		if err == nil {
			t.Error("Expected error but got nil")
		}
	})
}

func TestDeleteEntry(t *testing.T) {
	orig := saveMocks()
	defer orig.restore()

	origLoad := loadEntryMetadataImpl
	origSave := saveEntryMetadataImpl
	defer func() {
		loadEntryMetadataImpl = origLoad
		saveEntryMetadataImpl = origSave
	}()
	loadEntryMetadataImpl = func(servicePrefix string) ([]KeychainEntryMeta, error) {
		return []KeychainEntryMeta{}, nil
	}
	saveEntryMetadataImpl = func(meta []KeychainEntryMeta) error {
		return nil
	}

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

func TestGetMFASerialIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping keychain test in short mode")
	}

	orig := saveMocks()
	defer orig.restore()

	// Use real implementations for integration test
	getCurrentUser = orig.getCurrentUser
	captureSecure = orig.captureSecure
	execCommand = orig.execCommand

	_, err := GetMFASerialBytes("", "") // should use `whoami`...
	// ...doesn't really matter here that if it succeeds or fails, just that it doesn't panic!
	_ = err
}

func TestGetSecretString(t *testing.T) {
	orig := saveMocks()
	defer orig.restore()

	tests := map[string]struct {
		account    string
		service    string
		mockOutput string
		wantSecret string
		wantErrMsg string
		mockError  bool
		wantErr    bool
	}{
		"success": {
			account:    "testuser",
			service:    "test-service",
			mockOutput: "test-secret-string",
			wantSecret: "test-secret-string",
		},
		"success with empty account": {
			account:    "",
			service:    "test-service",
			mockOutput: "test-secret-string",
			wantSecret: "test-secret-string",
		},
		"security command error": {
			account:    "testuser",
			service:    "test-service",
			mockError:  true,
			wantErr:    true,
			wantErrMsg: "keychain read failed",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			getCurrentUser = func() (string, error) {
				return "testuser", nil
			}
			if tc.mockError {
				captureSecure = func(cmd *exec.Cmd) ([]byte, error) {
					return nil, fmt.Errorf("security command failed")
				}
			} else {
				captureSecure = func(cmd *exec.Cmd) ([]byte, error) {
					return []byte(tc.mockOutput), nil
				}
			}

			secret, err := GetSecretString(tc.account, tc.service)

			if tc.wantErr && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if tc.wantErrMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tc.wantErrMsg) {
					t.Errorf("Expected error containing %q, got: %s", tc.wantErrMsg, err.Error())
				}
			}
			if !tc.wantErr && secret != tc.wantSecret {
				t.Errorf("Expected secret %q, got %q", tc.wantSecret, secret)
			}
		})
	}
}

func TestSetSecretString(t *testing.T) {
	orig := saveMocks()
	defer orig.restore()

	origLoad := loadEntryMetadataImpl
	origSave := saveEntryMetadataImpl
	defer func() {
		loadEntryMetadataImpl = origLoad
		saveEntryMetadataImpl = origSave
	}()
	loadEntryMetadataImpl = func(servicePrefix string) ([]KeychainEntryMeta, error) {
		return []KeychainEntryMeta{}, nil
	}
	saveEntryMetadataImpl = func(meta []KeychainEntryMeta) error {
		return nil
	}

	tests := map[string]struct {
		account    string
		service    string
		secret     string
		wantErrMsg string
		mockError  bool
		wantErr    bool
	}{
		"success": {
			account: "testuser",
			service: "test-service",
			secret:  "test-secret-string",
		},
		"success with empty account": {
			account: "",
			service: "test-service",
			secret:  "test-secret-string",
		},
		"security command error": {
			account:    "testuser",
			service:    "test-service",
			secret:     "test-secret-string",
			mockError:  true,
			wantErr:    true,
			wantErrMsg: "failed to set secret in keychain",
		},
		"empty secret": {
			account: "testuser",
			service: "test-service",
			secret:  "",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			getCurrentUser = func() (string, error) {
				return "testuser", nil
			}
			if tc.mockError {
				execSecretInput = func(cmd *exec.Cmd, input []byte) error {
					return fmt.Errorf("security -i failed")
				}
			} else {
				execSecretInput = func(cmd *exec.Cmd, input []byte) error {
					return nil
				}
			}

			err := SetSecretString(tc.account, tc.service, tc.secret)

			if tc.wantErr && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if tc.wantErrMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tc.wantErrMsg) {
					t.Errorf("Expected error containing %q, got: %s", tc.wantErrMsg, err.Error())
				}
			}
		})
	}
}

func TestSecretTrimmingForTOTPServices(t *testing.T) {
	orig := saveMocks()
	defer orig.restore()

	tests := map[string]struct {
		service    string
		mockOutput string
		wantSecret string
	}{
		"AWS service with trailing newline": {
			service:    "sesh-aws-default",
			mockOutput: "AWSSECRET123\n",
			wantSecret: "AWSSECRET123",
		},
		"TOTP service with trailing spaces": {
			service:    "sesh-totp-github",
			mockOutput: "TOTPSECRET456   ",
			wantSecret: "TOTPSECRET456",
		},
		"Non-TOTP service also trims whitespace": {
			service:    "other-service",
			mockOutput: "SECRET789\n",
			wantSecret: "SECRET789",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			captureSecure = func(cmd *exec.Cmd) ([]byte, error) {
				// Real ExecAndCaptureSecure does bytes.TrimSpace on output
				return bytes.TrimSpace([]byte(tc.mockOutput)), nil
			}

			secretBytes, err := GetSecretBytes("testuser", tc.service)
			if err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			secret := string(secretBytes)
			if secret != tc.wantSecret {
				t.Errorf("Expected secret %q, got %q", tc.wantSecret, secret)
			}
		})
	}
}

func TestSetSecretBytesWithEmptyAccount(t *testing.T) {
	orig := saveMocks()
	defer orig.restore()

	origLoad := loadEntryMetadataImpl
	origSave := saveEntryMetadataImpl
	defer func() {
		loadEntryMetadataImpl = origLoad
		saveEntryMetadataImpl = origSave
	}()
	loadEntryMetadataImpl = func(servicePrefix string) ([]KeychainEntryMeta, error) {
		return []KeychainEntryMeta{}, nil
	}
	saveEntryMetadataImpl = func(meta []KeychainEntryMeta) error {
		return nil
	}

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

	origLoad := loadEntryMetadataImpl
	origSave := saveEntryMetadataImpl
	defer func() {
		loadEntryMetadataImpl = origLoad
		saveEntryMetadataImpl = origSave
	}()
	loadEntryMetadataImpl = func(servicePrefix string) ([]KeychainEntryMeta, error) {
		return []KeychainEntryMeta{}, nil
	}
	saveEntryMetadataImpl = func(meta []KeychainEntryMeta) error {
		return nil
	}

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
