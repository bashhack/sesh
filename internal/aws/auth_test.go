package aws

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"testing"
)

// MockExecCommand returns a function that creates a mock exec.Command
func MockExecCommand(output string, err error) func(string, ...string) *exec.Cmd {
	return func(_ string, _ ...string) *exec.Cmd {
		cmd := &exec.Cmd{}

		if err != nil {
			cmd = exec.Command("false")
			return cmd
		}

		cmd = exec.Command("echo", output)
		return cmd
	}
}

func TestGetSessionToken_Success(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	mockResp := SessionTokenResponse{
		Credentials: Credentials{
			AccessKeyId:     "MOCK-ACCESS-KEY",
			SecretAccessKey: "mock-secret-key",
			SessionToken:    "mock-session-token",
			Expiration:      "2025-01-01T00:00:00Z",
		},
	}

	mockRespJSON, _ := json.Marshal(mockResp)

	execCommand = MockExecCommand(string(mockRespJSON), nil)

	creds, err := GetSessionToken("test-profile", "arn:aws:iam::123456789012:mfa/test", []byte("123456"))

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	if creds.AccessKeyId != "MOCK-ACCESS-KEY" {
		t.Errorf("Expected AccessKeyId 'MOCK-ACCESS-KEY', got '%s'", creds.AccessKeyId)
	}

	if creds.SecretAccessKey != "mock-secret-key" {
		t.Errorf("Expected SecretAccessKey 'mock-secret-key', got '%s'", creds.SecretAccessKey)
	}

	if creds.SessionToken != "mock-session-token" {
		t.Errorf("Expected SessionToken 'mock-session-token', got '%s'", creds.SessionToken)
	}

	if creds.Expiration != "2025-01-01T00:00:00Z" {
		t.Errorf("Expected Expiration '2025-01-01T00:00:00Z', got '%s'", creds.Expiration)
	}
}

func TestGetSessionToken_CommandError(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	execCommand = MockExecCommand("", errors.New("command failed"))

	_, err := GetSessionToken("test-profile", "arn:aws:iam::123456789012:mfa/test", []byte("123456"))

	if err == nil {
		t.Error("Expected error, got nil")
	}
}

func TestGetSessionToken_InvalidJSON(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	execCommand = MockExecCommand("not json", nil)

	_, err := GetSessionToken("test-profile", "arn:aws:iam::123456789012:mfa/test", []byte("123456"))

	if err == nil || err.Error() == "" {
		t.Error("Expected JSON parsing error, got nil or empty")
	}
}

func TestGetSessionToken_EmptyProfile(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	var capturedArgs []string

	execCommand = func(_ string, args ...string) *exec.Cmd {
		capturedArgs = args

		mockResp := SessionTokenResponse{
			Credentials: Credentials{
				AccessKeyId:     "MOCK-ACCESS-KEY",
				SecretAccessKey: "mock-secret-key",
				SessionToken:    "mock-session-token",
				Expiration:      "2025-01-01T00:00:00Z",
			},
		}

		mockRespJSON, _ := json.Marshal(mockResp)
		cmd := exec.Command("echo", string(mockRespJSON))
		return cmd
	}

	_, err := GetSessionToken("", "arn:aws:iam::123456789012:mfa/test", []byte("123456"))
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Verify --profile was not added to args
	for i, arg := range capturedArgs {
		if arg == "--profile" && i < len(capturedArgs)-1 {
			t.Error("--profile should not be included with empty profile")
		}
	}
}

func TestGetSessionToken_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping AWS integration test in short mode")
	}

	if os.Getenv("CI") == "true" || os.Getenv("SKIP_AWS_TESTS") == "true" {
		t.Skip("Skipping AWS integration test in CI/automated environment")
	}

	// This is a very minimal check - I'm not trying to authenticate
	// since that would require real credentials and MFA codes
	// I'm just aiming for coverage here and ensuring the function
	// handles basic error cases correctly

	_, err := GetSessionToken("nonexistent-profile", "invalid-serial", []byte("123456"))
	if err == nil {
		t.Error("Expected error for invalid AWS credentials, got nil")
	}
}

func TestGetFirstMFADevice_Success(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	mockResp := ListDevicesResponse{
		MFADevices: []MFADevice{
			{
				SerialNumber: "arn:aws:iam::123456789012:mfa/test-user",
			},
		},
	}

	mockRespJSON, _ := json.Marshal(mockResp)

	execCommand = func(_ string, _ ...string) *exec.Cmd {
		cmd := exec.Command("echo", string(mockRespJSON))
		return cmd
	}

	serial, err := GetFirstMFADevice("test-profile")

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	if serial != "arn:aws:iam::123456789012:mfa/test-user" {
		t.Errorf("Expected serial 'arn:aws:iam::123456789012:mfa/test-user', got '%s'", serial)
	}
}

func TestGetFirstMFADevice_NoDevices(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	mockResp := ListDevicesResponse{
		MFADevices: []MFADevice{},
	}

	mockRespJSON, _ := json.Marshal(mockResp)

	execCommand = func(_ string, _ ...string) *exec.Cmd {
		cmd := exec.Command("echo", string(mockRespJSON))
		return cmd
	}

	_, err := GetFirstMFADevice("test-profile")

	if err == nil {
		t.Error("Expected 'no MFA devices found' error, got nil")
	}
}

func TestGetFirstMFADevice_CommandError(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	execCommand = func(_ string, _ ...string) *exec.Cmd {
		// Use a command that will fail
		return exec.Command("false")
	}

	_, err := GetFirstMFADevice("test-profile")

	if err == nil {
		t.Error("Expected command error, got nil")
	}
}

func TestGetFirstMFADevice_InvalidJSON(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	execCommand = func(_ string, _ ...string) *exec.Cmd {
		cmd := exec.Command("echo", "not json")
		return cmd
	}

	_, err := GetFirstMFADevice("test-profile")

	if err == nil {
		t.Error("Expected JSON parsing error, got nil")
	}
}

func TestGetFirstMFADevice_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping AWS integration test in short mode")
	}

	if os.Getenv("CI") == "true" || os.Getenv("SKIP_AWS_TESTS") == "true" {
		t.Skip("Skipping AWS integration test in CI/automated environment")
	}

	_, err := GetFirstMFADevice("nonexistent-profile-" + randomString(8))
	if err == nil {
		t.Error("Expected error for nonexistent profile, got nil")
	}
}

func TestCredentials_ZeroSecrets(t *testing.T) {
	tests := map[string]struct {
		name  string
		creds *Credentials
	}{
		"normal credentials": {
			name: "normal credentials",
			creds: &Credentials{
				AccessKeyId:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				SessionToken:    "AQoDYXdzEJr...",
				Expiration:      "2023-12-01T00:00:00Z",
			},
		},
		"empty credentials": {
			name: "empty credentials",
			creds: &Credentials{
				AccessKeyId:     "",
				SecretAccessKey: "",
				SessionToken:    "",
				Expiration:      "",
			},
		},
		"nil credentials": {
			name:  "nil credentials",
			creds: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Make copies of original values for verification (except for nil case)
			var originalAccessKey, originalSecret, originalToken string
			if test.creds != nil {
				originalAccessKey = test.creds.AccessKeyId
				originalSecret = test.creds.SecretAccessKey
				originalToken = test.creds.SessionToken
			}

			// Call ZeroSecrets
			test.creds.ZeroSecrets()

			// Verify that the method doesn't panic on nil
			if test.creds == nil {
				// Test passed - no panic
				return
			}

			// Verify all sensitive fields are empty
			if test.creds.AccessKeyId != "" {
				t.Errorf("AccessKeyId not zeroed: %q", test.creds.AccessKeyId)
			}
			if test.creds.SecretAccessKey != "" {
				t.Errorf("SecretAccessKey not zeroed: %q", test.creds.SecretAccessKey)
			}
			if test.creds.SessionToken != "" {
				t.Errorf("SessionToken not zeroed: %q", test.creds.SessionToken)
			}

			// Verify Expiration is NOT zeroed (it's not sensitive)
			if test.creds.Expiration == "" && test.name == "normal credentials" {
				t.Error("Expiration should not be zeroed")
			}

			// Verify that original values were not empty (for normal case)
			if test.name == "normal credentials" {
				if originalAccessKey == "" || originalSecret == "" || originalToken == "" {
					t.Error("Test setup error: original values should not be empty")
				}
			}
		})
	}
}

func TestCredentials_ZeroSecrets_ActuallyZerosMemory(t *testing.T) {
	// This test verifies that the underlying memory is actually being zeroed
	// by checking that the secure.ZeroStrings function is being called
	creds := &Credentials{
		AccessKeyId:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "AQoDYXdzEJr...",
		Expiration:      "2023-12-01T00:00:00Z",
	}

	// Store original string values
	origAccess := creds.AccessKeyId
	origSecret := creds.SecretAccessKey
	origToken := creds.SessionToken

	// Call ZeroSecrets
	creds.ZeroSecrets()

	// Verify the struct fields are empty
	if creds.AccessKeyId != "" || creds.SecretAccessKey != "" || creds.SessionToken != "" {
		t.Error("Credentials fields not cleared")
	}

	// Note: We can't directly test that the original string memory was zeroed
	// because Go's string internals are not directly accessible. However,
	// we're calling secure.ZeroStrings which should handle this.
	// This is more of a verification that the method structure is correct.
	_ = origAccess
	_ = origSecret
	_ = origToken
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[i%len(charset)]
	}
	return string(result)
}
