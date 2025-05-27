package setup

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/keychain/mocks"
)

func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			len(s) > len(substr) &&
				(s[:len(substr)] == substr ||
					s[len(s)-len(substr):] == substr ||
					len(substr) > 0 && len(s) > len(substr) && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestAWSSetupHandler_WithMockReader(t *testing.T) {
	// Test "get current user fails" with proper input
	t.Run("get_current_user_fails_fixed", func(t *testing.T) {
		// Save original functions
		origExecLookPath := execLookPath
		origExecCommand := execCommand
		origGetCurrentUser := getCurrentUser
		origScanQRCode := scanQRCode
		origTimeSleep := timeSleep

		// Restore after test
		defer func() {
			execLookPath = origExecLookPath
			execCommand = origExecCommand
			getCurrentUser = origGetCurrentUser
			scanQRCode = origScanQRCode
			timeSleep = origTimeSleep
		}()

		// Mock time.Sleep to speed up tests
		timeSleep = func(d time.Duration) {}

		// Mock execLookPath
		execLookPath = func(file string) (string, error) {
			if file == "aws" {
				return "/usr/local/bin/aws", nil
			}
			return "", fmt.Errorf("not found")
		}
		// Mock getCurrentUser to fail
		getCurrentUser = func() (string, error) {
			return "", fmt.Errorf("user error")
		}

		// Mock scanQRCode to return just the secret
		scanQRCode = func() (string, error) {
			return "JBSWY3DPEHPK3PXP", nil
		}

		// Mock execCommand for AWS CLI calls
		execCommand = func(command string, args ...string) *exec.Cmd {
			cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess")
			cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")

			if len(args) > 0 && args[0] == "sts" {
				cmd.Env = append(cmd.Env, "STDOUT="+`{"UserId": "AIDAI23HBD", "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/testuser"}`)
			} else if len(args) > 0 && args[0] == "iam" && len(args) > 1 && args[1] == "list-mfa-devices" {
				// Return empty list to trigger the retry flow
				cmd.Env = append(cmd.Env, "STDOUT=")
			}
			return cmd
		}

		// Create mock keychain
		mockKeychain := &mocks.MockProvider{
			SetSecretStringFunc: func(account, service, secret string) error {
				return nil
			},
			StoreEntryMetadataFunc: func(servicePrefix, service, account, description string) error {
				return nil
			},
		}

		// Complete input sequence for QR code flow:
		// 1. Empty profile
		// 2. Choose QR (2)
		// 3. Enter to capture
		// 4. Enter after TOTP codes
		// 5. Choose first MFA device (1)
		// 6. Add extra input for potential retry prompts
		userInput := "\n2\n\n\n1\n3\narn:aws:iam::123456789012:mfa/testuser\n"

		// Use our mock reader
		mockReader := newMockReader(userInput)

		// Create handler
		handler := &AWSSetupHandler{
			keychainProvider: mockKeychain,
			reader:           mockReader.bufReader,
		}

		// Run setup
		err := handler.Setup()

		// Should fail with "failed to get current user"
		if err == nil {
			t.Errorf("Expected error but got nil")
		} else if !contains(err.Error(), "failed to get current user") {
			t.Errorf("Expected error containing 'failed to get current user', got: %v", err)
		}
	})
}
