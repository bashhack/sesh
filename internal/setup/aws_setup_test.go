package setup

import (
	"bufio"
	"fmt"
	"io"
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
	origRunCommand := runCommand
	origValidateAndNormalizeSecret := validateAndNormalizeSecret
	origGetCurrentUser := getCurrentUser
	origScanQRCode := scanQRCode
	origReadPassword := readPassword
	origTimeSleep := timeSleep
	defer func() {
		execLookPath = origExecLookPath
		runCommand = origRunCommand
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
		getCurrentUserError error
		validateSecretError error
		keychainSaveError   error
		scanQRError         error
		awsCommandOutputs   map[string]string // command -> output mapping

		// Expected results
		expectedErrorMsg string

		// Input data - this is what the user would type
		userInput       string
		awsNotFound     bool
		awsCommandFails bool
		expectError     bool
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
			// Mock runCommand for AWS CLI calls
			runCommand = func(name string, args ...string) ([]byte, error) {
				if tc.awsCommandFails {
					return nil, fmt.Errorf("mock aws error")
				}
				if len(args) > 0 {
					if args[0] == "sts" && len(args) > 1 && args[1] == "get-caller-identity" {
						if output, ok := tc.awsCommandOutputs["get-caller-identity"]; ok {
							return []byte(output), nil
						}
					} else if args[0] == "iam" && len(args) > 1 && args[1] == "list-mfa-devices" {
						if output, ok := tc.awsCommandOutputs["list-mfa-devices"]; ok {
							return []byte(output), nil
						}
					}
				}
				return []byte(""), nil
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

func TestAWSSetupHandler_WithMockReader(t *testing.T) {
	// Test "get current user fails" with proper input
	t.Run("get_current_user_fails_fixed", func(t *testing.T) {
		// Save original functions
		origExecLookPath := execLookPath
		origRunCommand := runCommand
		origGetCurrentUser := getCurrentUser
		origScanQRCode := scanQRCode
		origTimeSleep := timeSleep

		// Restore after test
		defer func() {
			execLookPath = origExecLookPath
			runCommand = origRunCommand
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

		// Mock runCommand for AWS CLI calls
		runCommand = func(name string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "sts" {
				return []byte(`{"UserId": "AIDAI23HBD", "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/testuser"}`), nil
			} else if len(args) > 0 && args[0] == "iam" && len(args) > 1 && args[1] == "list-mfa-devices" {
				return []byte(""), nil
			}
			return []byte(""), nil
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
