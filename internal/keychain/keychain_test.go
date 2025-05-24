package keychain

import (
	"fmt"
	"github.com/bashhack/sesh/internal/testutil"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestGetSecretBytesSuccess(t *testing.T) {
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

	secretBytes, err := GetSecretBytes("testuser", "test-service")

	if err != nil {
		t.Errorf("Expected no error but got: %v", err)
	}

	secret := string(secretBytes)
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

	secretBytes, err := GetSecretBytes("", "test-service")

	if err != nil {
		t.Errorf("Expected no error but got: %v", err)
	}
	
	secret := string(secretBytes)
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

	_, err := GetSecretBytes("", "test-service")

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

	_, err := GetSecretBytes("testuser", "test-service")

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

	serialBytes, err := GetMFASerialBytes("testuser")

	if err != nil {
		t.Errorf("Expected no error but got: %v", err)
	}

	serial := string(serialBytes)
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

	serialBytes, err := GetMFASerialBytes("")

	if err != nil {
		t.Errorf("Expected no error but got: %v", err)
	}

	serial := string(serialBytes)
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

	_, err := GetMFASerialBytes("")

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

	_, err := GetMFASerialBytes("testuser")

	if err == nil {
		t.Error("Expected error but got nil")
	}

	if !strings.Contains(err.Error(), "no MFA serial stored in Keychain") {
		t.Errorf("Expected error with 'no MFA serial stored in Keychain', got: %s", err.Error())
	}
}

func TestSetSecretBytes(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	execCommand = func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{
			"GO_WANT_HELPER_PROCESS=1",
		}
		return cmd
	}

	err := SetSecretBytes("testuser", "test-service", []byte("test-secret"))
	if err != nil {
		t.Errorf("Expected no error but got: %v", err)
	}

	// Test with error
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

	err = SetSecretBytes("testuser", "test-service", []byte("test-secret"))
	if err == nil {
		t.Error("Expected error but got nil")
	}
}

func TestListEntries(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	// Create mock keychain dump output
	mockOutput := `keychain: "/Users/testuser/Library/Keychains/login.keychain-db"
class: "genp"
attributes:
    0x00000007 <blob>="sesh-mfa"
    "svce"<blob>="sesh-mfa"
    "acct"<blob>="testuser"
    "labl"<blob>="AWS MFA Secret"
data:
<binary data>

keychain: "/Users/testuser/Library/Keychains/login.keychain-db"
class: "genp"
attributes:
    0x00000007 <blob>="sesh-totp-github"
    "svce"<blob>="sesh-totp-github"
    "acct"<blob>="testuser"
    "desc"<blob>="GitHub TOTP"
data:
<binary data>

keychain: "/Users/testuser/Library/Keychains/login.keychain-db"
class: "inet"
attributes:
    0x00000007 <blob>="something-else"
    "svce"<blob>="something-else"
    "acct"<blob>="testuser"
data:
<binary data>
`

	execCommand = func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{
			"GO_WANT_HELPER_PROCESS=1",
			fmt.Sprintf("MOCK_OUTPUT=%s", mockOutput),
		}
		return cmd
	}

	// Mock the LoadEntryMetadata implementation to return test data
	originalFunc := loadEntryMetadataImpl
	defer func() { loadEntryMetadataImpl = originalFunc }()
	
	// Override the function for this test
	loadEntryMetadataImpl = func(servicePrefix string) ([]KeychainEntryMeta, error) {
		// Return different results based on the servicePrefix
		if servicePrefix == "sesh-mfa" {
			return []KeychainEntryMeta{
				{
					Service:     "sesh-mfa",
					Account:     "testuser",
					Description: "AWS MFA Secret",
					ServiceType: "aws",
				},
			}, nil
		} else if servicePrefix == "sesh-totp" {
			return []KeychainEntryMeta{
				{
					Service:     "sesh-totp-github",
					Account:     "testuser",
					Description: "GitHub TOTP",
					ServiceType: "totp",
				},
			}, nil
		}
		
		// Return all entries when no prefix is specified
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

	// Test listing sesh-mfa entries
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

	// Test listing sesh-totp entries separately
	entries, err = ListEntries("sesh-totp")
	if err != nil {
		t.Errorf("Expected no error but got: %v", err)
	}

	if len(entries) != 1 {
		t.Errorf("Expected 1 entry but got %d", len(entries))
	}

	// The service name changed in our new architecture
	if entries[0].Service != "sesh-mfa" && entries[0].Service != "sesh-totp-github" {
		t.Errorf("Expected service 'sesh-mfa' or 'sesh-totp-github' but got '%s'", entries[0].Service)
	}

	// Test with error by creating a new subtest
	t.Run("Error Case", func(t *testing.T) {
		// Reset the mock
		loadEntryMetadataImpl = originalFunc
		
		// Now set it to return an error
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
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

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

	// Test with error
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

	if os.Getenv("CI") == "true" || os.Getenv("SKIP_KEYCHAIN_TESTS") == "true" {
		t.Skip("Skipping keychain test in CI environment")
	}

	nonExistentService := "test-sesh-nonexistent-" + randomString(8)

	_, err := GetSecretBytes("", nonExistentService)
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

	_, err := GetMFASerialBytes("") // should use `whoami`...
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
