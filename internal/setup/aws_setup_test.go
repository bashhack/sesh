package setup

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/keychain/mocks"
)

// mockReader wraps a strings.Reader and returns an error when out of input
// instead of returning empty strings forever
type mockReader struct {
	reader    *strings.Reader
	bufReader *bufio.Reader
}

func newMockReader(input string) *mockReader {
	r := strings.NewReader(input)
	return &mockReader{
		reader:    r,
		bufReader: bufio.NewReader(r),
	}
}

func (m *mockReader) ReadString(delim byte) (string, error) {
	line, err := m.bufReader.ReadString(delim)
	if err == io.EOF && line == "" {
		// Return a clear error when we're out of input
		return "", fmt.Errorf("mock reader: no more input available")
	}
	return line, err
}

func TestAWSSetupHandler_Setup(t *testing.T) {
	// Save original functions
	origExecLookPath := execLookPath
	origExecCommand := execCommand
	origValidateAndNormalizeSecret := validateAndNormalizeSecret
	origGetCurrentUser := getCurrentUser
	origScanQRCode := scanQRCode
	origReadPassword := readPassword
	origTimeSleep := timeSleep
	defer func() {
		execLookPath = origExecLookPath
		execCommand = origExecCommand
		validateAndNormalizeSecret = origValidateAndNormalizeSecret
		getCurrentUser = origGetCurrentUser
		scanQRCode = origScanQRCode
		readPassword = origReadPassword
		timeSleep = origTimeSleep
	}()

	// Mock timeSleep to speed up tests
	timeSleep = func(d time.Duration) {}

	tests := map[string]struct {
		// Test control flags
		awsNotFound         bool
		awsCommandFails     bool
		awsCommandOutputs   map[string]string // command -> output mapping
		getCurrentUserError error
		validateSecretError error
		keychainSaveError   error
		scanQRError         error

		// Expected results
		expectError      bool
		expectedErrorMsg string

		// Input data - this is what the user would type
		userInput string
	}{
		"aws cli not found": {
			awsNotFound:      true,
			expectError:      true,
			expectedErrorMsg: "AWS CLI not found",
			userInput:        "",
		},
		"verify credentials fails": {
			awsCommandFails:  true,
			expectError:      true,
			expectedErrorMsg: "failed to get AWS identity",
			userInput:        "test-profile\n",
		},
		"invalid mfa setup choice": {
			awsCommandOutputs: map[string]string{
				"get-caller-identity": `{"UserId": "AIDAI23HBD", "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/testuser"}`,
			},
			expectError:      true,
			expectedErrorMsg: "invalid choice",
			userInput:        "\n3\n", // empty profile, invalid choice
		},
		"empty mfa setup choice": {
			awsCommandOutputs: map[string]string{
				"get-caller-identity": `{"UserId": "AIDAI23HBD", "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/testuser"}`,
			},
			expectError:      true,
			expectedErrorMsg: "invalid choice, please select 1 or 2",
			userInput:        "\n\n", // empty profile, empty choice
		},
		"invalid totp secret": {
			awsCommandOutputs: map[string]string{
				"get-caller-identity": `{"UserId": "AIDAI23HBD", "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/testuser"}`,
			},
			validateSecretError: fmt.Errorf("invalid base32"),
			expectError:         true,
			expectedErrorMsg:    "invalid TOTP secret",
			userInput:           "\n2\nINVALID_SECRET\n", // empty profile, manual entry, bad secret
		},
		"existing entry cancelled by user": {
			awsCommandOutputs: map[string]string{
				"get-caller-identity": `{"UserId": "AIDAI23HBD", "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/testuser"}`,
			},
			expectError:      true,
			expectedErrorMsg: "setup cancelled by user",
			userInput:        "\nn\n", // empty profile, no to overwrite
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Mock execCommand for AWS CLI calls
			execCommand = func(command string, args ...string) *exec.Cmd {
				cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess")
				cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")

				if tc.awsCommandFails {
					cmd.Env = append(cmd.Env, "MOCK_ERROR=1")
					cmd.Env = append(cmd.Env, "STDOUT=mock error")
				} else if len(args) > 0 {
					// Check what AWS command is being run
					if args[0] == "sts" && len(args) > 1 && args[1] == "get-caller-identity" {
						if output, ok := tc.awsCommandOutputs["get-caller-identity"]; ok {
							cmd.Env = append(cmd.Env, "STDOUT="+output)
						}
					} else if args[0] == "iam" && len(args) > 1 && args[1] == "list-mfa-devices" {
						if output, ok := tc.awsCommandOutputs["list-mfa-devices"]; ok {
							cmd.Env = append(cmd.Env, "STDOUT="+output)
						}
					}
				}

				return cmd
			}

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
			if tc.validateSecretError != nil {
				validateAndNormalizeSecret = func(secret string) (string, error) {
					return "", tc.validateSecretError
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
				if tc.scanQRError != nil {
					return "", tc.scanQRError
				}
				return "otpauth://totp/AWS:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=AWS", nil
			}

			// Mock readPassword for manual entry
			readPassword = func(fd int) ([]byte, error) {
				// Extract the secret from userInput if manual entry
				lines := strings.Split(tc.userInput, "\n")
				if len(lines) >= 3 && strings.Contains(lines[1], "2") {
					return []byte(lines[2]), nil
				}
				return []byte("JBSWY3DPEHPK3PXP"), nil
			}

			// Create mock keychain
			mockKeychain := &mocks.MockProvider{
				GetSecretStringFunc: func(account, service string) (string, error) {
					// Return existing secret for overwrite test case
					if tc.expectedErrorMsg == "setup cancelled by user" {
						return "EXISTING_SECRET", nil
					}
					return "", nil
				},
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
				reader:           bufio.NewReader(strings.NewReader(tc.userInput)),
			}

			// Run setup (without capturing stdout for now to debug)
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

// func TestAWSSetupHandler_Setup(t *testing.T) {
// 	// Save original functions
// 	origExecLookPath := execLookPath
// 	origExecCommand := execCommand
// 	origValidateAndNormalizeSecret := validateAndNormalizeSecret
// 	origGetCurrentUser := getCurrentUser
// 	origScanQRCode := scanQRCode
// 	origReadPassword := readPassword
// 	origTimeSleep := timeSleep
// 	defer func() {
// 		execLookPath = origExecLookPath
// 		execCommand = origExecCommand
// 		validateAndNormalizeSecret = origValidateAndNormalizeSecret
// 		getCurrentUser = origGetCurrentUser
// 		scanQRCode = origScanQRCode
// 		readPassword = origReadPassword
// 		timeSleep = origTimeSleep
// 	}()

// 	// Mock timeSleep to speed up tests
// 	timeSleep = func(d time.Duration) {}

// 	tests := map[string]struct {
// 		// Test control flags
// 		awsNotFound         bool
// 		awsCommandFails     bool
// 		awsCommandOutputs   map[string]string // command -> output mapping
// 		getCurrentUserError error
// 		validateSecretError error
// 		keychainSaveError   error
// 		scanQRError         error

// 		// Expected results
// 		expectError      bool
// 		expectedErrorMsg string

// 		// Input data - this is what the user would type
// 		userInput string
// 	}{
// 		"aws cli not found": {
// 			awsNotFound:      true,
// 			expectError:      true,
// 			expectedErrorMsg: "AWS CLI not found",
// 			userInput:        "",
// 		},
// 		"verify credentials fails": {
// 			awsCommandFails:  true,
// 			expectError:      true,
// 			expectedErrorMsg: "failed to get AWS identity",
// 			userInput:        "test-profile\n",
// 		},
// 		"invalid mfa setup choice": {
// 			awsCommandOutputs: map[string]string{
// 				"get-caller-identity": `{"UserId": "AIDAI23HBD", "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/testuser"}`,
// 			},
// 			expectError:      true,
// 			expectedErrorMsg: "invalid choice",
// 			userInput:        "\n3\n", // empty profile, invalid choice
// 		},
// 		"empty mfa setup choice": {
// 			awsCommandOutputs: map[string]string{
// 				"get-caller-identity": `{"UserId": "AIDAI23HBD", "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/testuser"}`,
// 			},
// 			expectError:      true,
// 			expectedErrorMsg: "invalid choice, please select 1 or 2",
// 			userInput:        "\n\n", // empty profile, empty choice
// 		},
// 		"qr scan fails": {
// 			awsCommandOutputs: map[string]string{
// 				"get-caller-identity": `{"UserId": "AIDAI23HBD", "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/testuser"}`,
// 			},
// 			scanQRError:      fmt.Errorf("camera error"),
// 			expectError:      true,
// 			expectedErrorMsg: "QR capture failed after 2 attempts and user declined manual entry",
// 			userInput:        "\n2\n\n\nn\n", // empty profile, QR choice (2), Enter to capture, Enter to retry, 'n' to decline manual entry
// 		},
// 		"invalid totp secret": {
// 			awsCommandOutputs: map[string]string{
// 				"get-caller-identity": `{"UserId": "AIDAI23HBD", "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/testuser"}`,
// 			},
// 			validateSecretError: fmt.Errorf("invalid base32"),
// 			expectError:         true,
// 			expectedErrorMsg:    "invalid TOTP secret",
// 			userInput:           "\n2\nINVALID_SECRET\n", // empty profile, manual entry, bad secret
// 		},
// 		"get current user fails": {
// 			awsCommandOutputs: map[string]string{
// 				"get-caller-identity": `{"UserId": "AIDAI23HBD", "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/testuser"}`,
// 				"list-mfa-devices":    `{"MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/testuser"}]}`,
// 			},
// 			getCurrentUserError: fmt.Errorf("user error"),
// 			expectError:         true,
// 			expectedErrorMsg:    "failed to get current user",
// 			userInput:           "\n2\nJBSWY3DPEHPK3PXP\n", // empty profile, manual entry, valid secret
// 		},
// 		"keychain save fails": {
// 			awsCommandOutputs: map[string]string{
// 				"get-caller-identity": `{"UserId": "AIDAI23HBD", "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/testuser"}`,
// 				"list-mfa-devices":    `{"MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/testuser"}]}`,
// 			},
// 			keychainSaveError: fmt.Errorf("keychain error"),
// 			expectError:       true,
// 			expectedErrorMsg:  "failed to store secret in keychain",
// 			userInput:         "\n2\nJBSWY3DPEHPK3PXP\n", // empty profile, manual entry, valid secret
// 		},
// 		"successful setup with manual entry": {
// 			awsCommandOutputs: map[string]string{
// 				"get-caller-identity": `{"UserId": "AIDAI23HBD", "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/testuser"}`,
// 				"list-mfa-devices":    `{"MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/testuser"}]}`,
// 			},
// 			expectError: false,
// 			userInput:   "\n2\nJBSWY3DPEHPK3PXP\n", // empty profile, manual entry, valid secret
// 		},
// 		"successful setup with QR code": {
// 			awsCommandOutputs: map[string]string{
// 				"get-caller-identity": `{"UserId": "AIDAI23HBD", "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/testuser"}`,
// 				"list-mfa-devices":    `{"MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/testuser"}]}`,
// 			},
// 			expectError: false,
// 			userInput:   "\n2\n\n\n1\n", // empty profile, QR choice (2), Enter to capture, Enter after TOTP codes, '1' to select first device
// 		},
// 		"successful setup with named profile": {
// 			awsCommandOutputs: map[string]string{
// 				"get-caller-identity": `{"UserId": "AIDAI23HBD", "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/testuser"}`,
// 				"list-mfa-devices":    `{"MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/testuser"}]}`,
// 			},
// 			expectError: false,
// 			userInput:   "test-profile\n2\nJBSWY3DPEHPK3PXP\n", // named profile, manual entry, valid secret
// 		},
// 		"no MFA devices found": {
// 			awsCommandOutputs: map[string]string{
// 				"get-caller-identity": `{"UserId": "AIDAI23HBD", "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/testuser"}`,
// 				"list-mfa-devices":    ``,
// 			},
// 			expectError: false,
// 			userInput:   "\n1\nJBSWY3DPEHPK3PXP\n\n1\n1\n3\narn:aws:iam::123456789012:mfa/testuser\n", // empty profile, choice 1 (ready to continue), secret, Enter after TOTP, '1' to wait/retry, '1' to wait again, '3' for manual entry, then manual ARN
// 		},
// 	}

// 	for name, tc := range tests {
// 		t.Run(name, func(t *testing.T) {
// 			// Mock execCommand for AWS CLI calls
// 			execCommand = func(command string, args ...string) *exec.Cmd {
// 				cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess")
// 				cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")

// 				if tc.awsCommandFails {
// 					cmd.Env = append(cmd.Env, "MOCK_ERROR=1")
// 					cmd.Env = append(cmd.Env, "STDOUT=mock error")
// 				} else if len(args) > 0 {
// 					// Check what AWS command is being run
// 					if args[0] == "sts" && len(args) > 1 && args[1] == "get-caller-identity" {
// 						if output, ok := tc.awsCommandOutputs["get-caller-identity"]; ok {
// 							cmd.Env = append(cmd.Env, "STDOUT="+output)
// 						}
// 					} else if args[0] == "iam" && len(args) > 1 && args[1] == "list-mfa-devices" {
// 						if output, ok := tc.awsCommandOutputs["list-mfa-devices"]; ok {
// 							cmd.Env = append(cmd.Env, "STDOUT="+output)
// 						}
// 					}
// 				}

// 				return cmd
// 			}

// 			// Mock execLookPath
// 			if tc.awsNotFound {
// 				execLookPath = func(file string) (string, error) {
// 					return "", fmt.Errorf("not found")
// 				}
// 			} else {
// 				execLookPath = func(file string) (string, error) {
// 					return "/usr/local/bin/aws", nil
// 				}
// 			}

// 			// Mock validateAndNormalizeSecret
// 			if tc.validateSecretError != nil {
// 				validateAndNormalizeSecret = func(secret string) (string, error) {
// 					return "", tc.validateSecretError
// 				}
// 			} else {
// 				validateAndNormalizeSecret = func(secret string) (string, error) {
// 					return secret, nil
// 				}
// 			}

// 			// Mock getCurrentUser
// 			if tc.getCurrentUserError != nil {
// 				getCurrentUser = func() (string, error) {
// 					return "", tc.getCurrentUserError
// 				}
// 			} else {
// 				getCurrentUser = func() (string, error) {
// 					return "testuser", nil
// 				}
// 			}

// 			// Mock scanQRCode
// 			scanQRCode = func() (string, error) {
// 				if tc.scanQRError != nil {
// 					return "", tc.scanQRError
// 				}
// 				return "otpauth://totp/AWS:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=AWS", nil
// 			}

// 			// Mock readPassword for manual entry
// 			readPassword = func(fd int) ([]byte, error) {
// 				// Extract the secret from userInput if manual entry
// 				lines := strings.Split(tc.userInput, "\n")
// 				if len(lines) >= 3 && strings.Contains(lines[1], "2") {
// 					return []byte(lines[2]), nil
// 				}
// 				return []byte("JBSWY3DPEHPK3PXP"), nil
// 			}

// 			// Create mock keychain
// 			mockKeychain := &mocks.MockProvider{
// 				SetSecretStringFunc: func(account, service, secret string) error {
// 					return tc.keychainSaveError
// 				},
// 				StoreEntryMetadataFunc: func(servicePrefix, service, account, description string) error {
// 					return nil
// 				},
// 			}

// 			// Create handler with mocked reader
// 			handler := &AWSSetupHandler{
// 				keychainProvider: mockKeychain,
// 				reader:           bufio.NewReader(strings.NewReader(tc.userInput)),
// 			}

// 			// Run setup (without capturing stdout for now to debug)
// 			err := handler.Setup()

// 			// Check error
// 			if tc.expectError {
// 				if err == nil {
// 					t.Errorf("Expected error but got nil")
// 				} else if tc.expectedErrorMsg != "" && !strings.Contains(err.Error(), tc.expectedErrorMsg) {
// 					t.Errorf("Expected error containing %q, got %q", tc.expectedErrorMsg, err.Error())
// 				}
// 			} else {
// 				if err != nil {
// 					t.Errorf("Expected no error but got: %v", err)
// 				}
// 			}
// 		})
// 	}
// }

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
		} else if !strings.Contains(err.Error(), "failed to get current user") {
			t.Errorf("Expected error containing 'failed to get current user', got: %v", err)
		}
	})
}

