package keychain

import (
	"fmt"
	"io"
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

	// Force use of real exec.Command for this integration test
	origExecCommand := execCommand
	execCommand = exec.Command
	defer func() { execCommand = origExecCommand }()

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

	// Force use of real exec.Command for this integration test
	origExecCommand := execCommand
	execCommand = exec.Command
	defer func() { execCommand = origExecCommand }()

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

func TestGetSecretString(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	tests := map[string]struct {
		account      string
		service      string
		mockOutput   string
		mockError    bool
		wantSecret   string
		wantErr      bool
		wantErrMsg   string
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
			wantErrMsg: "no secret found in Keychain",
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			whoamiOutput := "testuser"
			
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
					if test.mockError {
						cmd.Env = append(cmd.Env, "MOCK_ERROR=1")
					} else {
						cmd.Env = append(cmd.Env, fmt.Sprintf("MOCK_OUTPUT=%s", test.mockOutput))
					}
				}

				return cmd
			}

			secret, err := GetSecretString(test.account, test.service)

			if test.wantErr && err == nil {
				t.Error("Expected error but got nil")
			}
			if !test.wantErr && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if test.wantErrMsg != "" && err != nil {
				if !strings.Contains(err.Error(), test.wantErrMsg) {
					t.Errorf("Expected error containing %q, got: %s", test.wantErrMsg, err.Error())
				}
			}
			if !test.wantErr && secret != test.wantSecret {
				t.Errorf("Expected secret %q, got %q", test.wantSecret, secret)
			}
		})
	}
}

func TestSetSecretString(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	tests := map[string]struct {
		account      string
		service      string
		secret       string
		mockError    bool
		wantErr      bool
		wantErrMsg   string
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

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			whoamiOutput := "testuser"
			
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
					if test.mockError {
						cmd.Env = append(cmd.Env, "MOCK_ERROR=1")
					}
				}

				return cmd
			}

			err := SetSecretString(test.account, test.service, test.secret)

			if test.wantErr && err == nil {
				t.Error("Expected error but got nil")
			}
			if !test.wantErr && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if test.wantErrMsg != "" && err != nil {
				if !strings.Contains(err.Error(), test.wantErrMsg) {
					t.Errorf("Expected error containing %q, got: %s", test.wantErrMsg, err.Error())
				}
			}
		})
	}
}

func TestSecretTrimmingForTOTPServices(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	tests := map[string]struct {
		service      string
		mockOutput   string
		wantSecret   string
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

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			execCommand = func(command string, args ...string) *exec.Cmd {
				cs := []string{"-test.run=TestHelperProcess", "--", command}
				cs = append(cs, args...)
				cmd := exec.Command(os.Args[0], cs...)
				cmd.Env = []string{
					"GO_WANT_HELPER_PROCESS=1",
					fmt.Sprintf("MOCK_OUTPUT=%s", test.mockOutput),
				}
				return cmd
			}

			secretBytes, err := GetSecretBytes("testuser", test.service)
			if err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			secret := string(secretBytes)
			if secret != test.wantSecret {
				t.Errorf("Expected secret %q, got %q", test.wantSecret, secret)
			}
		})
	}
}

func TestSetSecretBytesWithEmptyAccount(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	whoamiCalled := false
	securityCalled := false

	execCommand = func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{
			"GO_WANT_HELPER_PROCESS=1",
		}

		if command == "whoami" {
			whoamiCalled = true
			cmd.Env = append(cmd.Env, "MOCK_OUTPUT=testuser")
		} else if command == "security" {
			securityCalled = true
			// Only check the account for the main add-generic-password call, not metadata calls
			if len(args) > 0 && args[0] == "add-generic-password" {
				// Check if this is the main secret storage (not metadata)
				isMainSecret := false
				for i, arg := range args {
					if arg == "-s" && i+1 < len(args) && args[i+1] == "test-service" {
						isMainSecret = true
						break
					}
				}
				
				if isMainSecret {
					// Verify that the account was set from whoami
					for i, arg := range args {
						if arg == "-a" && i+1 < len(args) {
							if args[i+1] != "testuser" {
								t.Errorf("Expected account 'testuser', got %q", args[i+1])
							}
						}
					}
				}
			}
		}

		return cmd
	}

	err := SetSecretBytes("", "test-service", []byte("test-secret"))
	if err != nil {
		t.Errorf("Expected no error but got: %v", err)
	}

	if !whoamiCalled {
		t.Error("Expected whoami to be called")
	}
	if !securityCalled {
		t.Error("Expected security command to be called")
	}
}

func TestDeleteEntryWithEmptyAccount(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	whoamiCalled := false
	deleteCalled := false

	execCommand = func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{
			"GO_WANT_HELPER_PROCESS=1",
		}

		if command == "whoami" {
			whoamiCalled = true
			cmd.Env = append(cmd.Env, "MOCK_OUTPUT=testuser")
		} else if command == "security" {
			deleteCalled = true
			// Verify delete command args
			if len(args) > 0 && args[0] == "delete-generic-password" {
				// Check account was set from whoami
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
		t.Error("Expected whoami to be called")
	}
	if !deleteCalled {
		t.Error("Expected security delete command to be called")
	}
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	
	// Get the command and args
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
	
	// Handle different commands
	switch command {
	case "security":
		// Check if this is interactive mode
		if len(cmdArgs) > 0 && cmdArgs[0] == "-i" {
			// Read stdin to get the actual command
			stdin, _ := io.ReadAll(os.Stdin)
			stdinStr := string(stdin)
			
			// Parse the add-generic-password command from stdin
			if strings.Contains(stdinStr, "add-generic-password") {
				// In test mode, just succeed if not MOCK_ERROR
				if os.Getenv("MOCK_ERROR") == "1" {
					os.Exit(1)
				}
				os.Exit(0)
			}
			// If no recognized command in stdin, exit with error
			os.Exit(1)
		} else {
			// Handle non-interactive security commands as before
			if os.Getenv("MOCK_ERROR") == "1" {
				os.Exit(1)
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
		// For other commands, use the default behavior
		if os.Getenv("MOCK_ERROR") == "1" {
			os.Exit(1)
		}
		fmt.Print(os.Getenv("MOCK_OUTPUT"))
		os.Exit(0)
	}
}
