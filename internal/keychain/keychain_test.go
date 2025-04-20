package keychain

import (
	"fmt"
	"github.com/bashhack/sesh/internal/testutil"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestGetSecretSuccess(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	mockOutput := "test-secret"
	mockError := error(nil)

	execCommand = func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{
			"GO_WANT_HELPER_PROCESS=1",
			fmt.Sprintf("MOCK_OUTPUT=%s", mockOutput),
		}
		if mockError != nil {
			cmd.Env = append(cmd.Env, "MOCK_ERROR=1")
		}
		return cmd
	}

	secret, err := GetSecret("testuser", "test-service")

	if err != nil {
		t.Errorf("Expected no error but got: %v", err)
	}

	if secret != mockOutput {
		t.Errorf("Expected secret '%s', got '%s'", mockOutput, secret)
	}
}

func TestGetSecretWithEmptyUsername(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	whoamiOutput := "testuser"
	securityOutput := "test-secret"

	execCommand = func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{
			"GO_WANT_HELPER_PROCESS=1",
		}

		if command == "whoami" {
			cmd.Env = append(cmd.Env, fmt.Sprintf("MOCK_OUTPUT=%s", whoamiOutput))
		} else if command == "security" {
			cmd.Env = append(cmd.Env, fmt.Sprintf("MOCK_OUTPUT=%s", securityOutput))
		}

		return cmd
	}

	secret, err := GetSecret("", "test-service")

	if err != nil {
		t.Errorf("Expected no error but got: %v", err)
	}

	if secret != securityOutput {
		t.Errorf("Expected secret '%s', got '%s'", securityOutput, secret)
	}
}

func TestGetSecretWithWhoamiError(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	execCommand = func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{
			"GO_WANT_HELPER_PROCESS=1",
		}

		if command == "whoami" {
			cmd.Env = append(cmd.Env, "MOCK_ERROR=1")
		}

		return cmd
	}

	_, err := GetSecret("", "test-service")

	if err == nil {
		t.Error("Expected error but got nil")
	}

	if !strings.Contains(err.Error(), "could not determine current user") {
		t.Errorf("Expected error with 'could not determine current user', got: %s", err.Error())
	}
}

func TestGetSecretWithSecurityError(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	execCommand = func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{
			"GO_WANT_HELPER_PROCESS=1",
		}

		if command == "security" {
			cmd.Env = append(cmd.Env, "MOCK_ERROR=1")
		}

		return cmd
	}

	_, err := GetSecret("testuser", "test-service")

	if err == nil {
		t.Error("Expected error but got nil")
	}

	if !strings.Contains(err.Error(), "no secret found in Keychain") {
		t.Errorf("Expected error with 'no secret found in Keychain', got: %s", err.Error())
	}
}

func TestGetMFASerialSuccess(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	mockOutput := "arn:aws:iam::123456789012:mfa/user"
	mockError := error(nil)

	execCommand = func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{
			"GO_WANT_HELPER_PROCESS=1",
			fmt.Sprintf("MOCK_OUTPUT=%s", mockOutput),
		}
		if mockError != nil {
			cmd.Env = append(cmd.Env, "MOCK_ERROR=1")
		}
		return cmd
	}

	serial, err := GetMFASerial("testuser")

	if err != nil {
		t.Errorf("Expected no error but got: %v", err)
	}

	if serial != mockOutput {
		t.Errorf("Expected serial '%s', got '%s'", mockOutput, serial)
	}
}

func TestGetMFASerialWithEmptyUsername(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	whoamiOutput := "testuser"
	serialOutput := "arn:aws:iam::123456789012:mfa/user"

	execCommand = func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{
			"GO_WANT_HELPER_PROCESS=1",
		}

		if command == "whoami" {
			cmd.Env = append(cmd.Env, fmt.Sprintf("MOCK_OUTPUT=%s", whoamiOutput))
		} else if command == "security" {
			cmd.Env = append(cmd.Env, fmt.Sprintf("MOCK_OUTPUT=%s", serialOutput))
		}

		return cmd
	}

	serial, err := GetMFASerial("")

	if err != nil {
		t.Errorf("Expected no error but got: %v", err)
	}

	if serial != serialOutput {
		t.Errorf("Expected serial '%s', got '%s'", serialOutput, serial)
	}
}

func TestGetMFASerialWithWhoamiError(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	execCommand = func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{
			"GO_WANT_HELPER_PROCESS=1",
		}

		if command == "whoami" {
			cmd.Env = append(cmd.Env, "MOCK_ERROR=1")
		}

		return cmd
	}

	_, err := GetMFASerial("")

	if err == nil {
		t.Error("Expected error but got nil")
	}

	if !strings.Contains(err.Error(), "could not determine current user") {
		t.Errorf("Expected error with 'could not determine current user', got: %s", err.Error())
	}
}

func TestGetMFASerialWithSecurityError(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	execCommand = func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{
			"GO_WANT_HELPER_PROCESS=1",
		}

		if command == "security" {
			cmd.Env = append(cmd.Env, "MOCK_ERROR=1")
		}

		return cmd
	}

	_, err := GetMFASerial("testuser")

	if err == nil {
		t.Error("Expected error but got nil")
	}

	if !strings.Contains(err.Error(), "no MFA serial stored in Keychain") {
		t.Errorf("Expected error with 'no MFA serial stored in Keychain', got: %s", err.Error())
	}
}

func TestGetSecretIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping keychain test in short mode")
	}

	if os.Getenv("CI") == "true" || os.Getenv("SKIP_KEYCHAIN_TESTS") == "true" {
		t.Skip("Skipping keychain test in CI environment")
	}

	nonExistentService := "test-sesh-nonexistent-" + randomString(8)

	_, err := GetSecret("", nonExistentService)
	if err == nil {
		t.Error("Expected error for non-existent keychain item, got nil")
	}
}

func TestGetMFASerialIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping keychain test in short mode")
	}

	if os.Getenv("CI") == "true" || os.Getenv("SKIP_KEYCHAIN_TESTS") == "true" {
		t.Skip("Skipping keychain test in CI environment")
	}

	_, err := GetMFASerial("") // should use `whoami`...
	// ...doesn't really matter here that if it succeeds or fails, just that it doesn't panic!
	_ = err
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[i%len(charset)]
	}
	return string(result)
}

func TestHelperProcess(*testing.T) {
	testutil.TestHelperProcess()
}
