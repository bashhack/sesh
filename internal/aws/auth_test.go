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

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[i%len(charset)]
	}
	return string(result)
}
