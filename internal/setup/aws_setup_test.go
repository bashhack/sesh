package setup

import (
	"bufio"
	"fmt"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/keychain/mocks"
)

func TestAWSSetupHandler_Setup(t *testing.T) {
	// Save original functions
	origExecLookPath := execLookPath
	origValidateAndNormalizeSecret := validateAndNormalizeSecret
	origGetCurrentUser := getCurrentUser
	origScanQRCode := scanQRCode
	origReadPassword := readPassword
	defer func() {
		execLookPath = origExecLookPath
		validateAndNormalizeSecret = origValidateAndNormalizeSecret
		getCurrentUser = origGetCurrentUser
		scanQRCode = origScanQRCode
		readPassword = origReadPassword
	}()

	tests := map[string]struct {
		awsNotFound            bool
		profileInput           string
		verifyCredsError       error
		mfaMethodChoice        string
		secretCaptureMethod    string  // "qr" or "manual"
		qrCodeResult           string
		qrCodeError            error
		manualSecret           string
		invalidSecret          bool
		getCurrentUserError    error
		keychainSaveError      error
		expectError            bool
		expectedErrorMsg       string
	}{
		"aws cli not found": {
			awsNotFound:      true,
			expectError:      true,
			expectedErrorMsg: "AWS CLI not found",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Mock execLookPath
			if tc.awsNotFound {
				execLookPath = func(file string) (string, error) {
					return "", fmt.Errorf("not found")
				}
			} else {
				execLookPath = func(file string) (string, error) {
					return "/usr/local/bin/aws", nil
				}
			}

			// Mock validateAndNormalizeSecret
			if tc.invalidSecret {
				validateAndNormalizeSecret = func(secret string) (string, error) {
					return "", fmt.Errorf("invalid secret")
				}
			} else {
				validateAndNormalizeSecret = func(secret string) (string, error) {
					return secret, nil
				}
			}

			// Mock getCurrentUser
			if tc.getCurrentUserError != nil {
				getCurrentUser = func() (string, error) {
					return "", tc.getCurrentUserError
				}
			} else {
				getCurrentUser = func() (string, error) {
					return "testuser", nil
				}
			}

			// Mock scanQRCode
			scanQRCode = func() (string, error) {
				if tc.qrCodeError != nil {
					return "", tc.qrCodeError
				}
				return tc.qrCodeResult, nil
			}

			// Mock readPassword
			readPassword = func(fd int) ([]byte, error) {
				return []byte(tc.manualSecret), nil
			}

			// Create mock keychain
			mockKeychain := &mocks.MockProvider{
				SetSecretStringFunc: func(account, service, secret string) error {
					return tc.keychainSaveError
				},
				StoreEntryMetadataFunc: func(servicePrefix, service, account, description string) error {
					return nil
				},
			}

			// Create handler with mocked reader
			handler := &AWSSetupHandler{
				keychainProvider: mockKeychain,
				reader:           bufio.NewReader(strings.NewReader(tc.profileInput + "\n")),
			}

			// Run setup
			err := handler.Setup()

			// Check error
			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error but got nil")
				} else if tc.expectedErrorMsg != "" && !strings.Contains(err.Error(), tc.expectedErrorMsg) {
					t.Errorf("Expected error containing %q, got %q", tc.expectedErrorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}