package aws

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/testutil"
)

// MockExecCommand returns a function that creates a mock exec.Command
func MockExecCommand(output string, err error) func(string, ...string) *exec.Cmd {
	return func(_ string, _ ...string) *exec.Cmd {
		if err != nil {
			return exec.Command("false")
		}

		return exec.Command("echo", output)
	}
}

func TestGetSessionToken_Success(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	mockResp := SessionTokenResponse{
		Credentials: Credentials{
			AccessKeyID:     "MOCK-ACCESS-KEY",
			SecretAccessKey: "mock-secret-key",
			SessionToken:    "mock-session-token",
			Expiration:      "2025-01-01T00:00:00Z",
		},
	}

	mockRespJSON, err := json.Marshal(mockResp)
	if err != nil {
		t.Fatalf("Failed to marshal mock response: %v", err)
	}

	execCommand = MockExecCommand(string(mockRespJSON), nil)

	creds, err := GetSessionToken("test-profile", "arn:aws:iam::123456789012:mfa/test", []byte("123456"))

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	if creds.AccessKeyID != "MOCK-ACCESS-KEY" {
		t.Errorf("Expected AccessKeyID 'MOCK-ACCESS-KEY', got '%s'", creds.AccessKeyID)
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

// The AWS CLI's message reaches the caller, which retries on it; the code doesn't.
func TestGetSessionToken_CommandErrorMessage(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	const awsSays = InvalidMFAMessage
	execCommand = func(_ string, _ ...string) *exec.Cmd {
		return exec.Command("sh", "-c", "echo 'An error occurred (AccessDenied): "+awsSays+". ' >&2; exit 254")
	}

	_, err := GetSessionToken("test-profile", "arn:aws:iam::123456789012:mfa/test", []byte("654321"))
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	if !strings.Contains(err.Error(), awsSays) {
		t.Errorf("error %q doesn't hold the AWS CLI's message %q", err, awsSays)
	}
	if strings.Contains(err.Error(), "654321") {
		t.Errorf("error %q holds the MFA code", err)
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
				AccessKeyID:     "MOCK-ACCESS-KEY",
				SecretAccessKey: "mock-secret-key",
				SessionToken:    "mock-session-token",
				Expiration:      "2025-01-01T00:00:00Z",
			},
		}

		mockRespJSON, err := json.Marshal(mockResp)
		if err != nil {
			t.Fatalf("test setup: failed to marshal mock response: %v", err)
		}
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

	mockRespJSON, err := json.Marshal(mockResp)
	if err != nil {
		t.Fatalf("Failed to marshal mock response: %v", err)
	}

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

	mockRespJSON, err := json.Marshal(mockResp)
	if err != nil {
		t.Fatalf("Failed to marshal mock response: %v", err)
	}

	execCommand = func(_ string, _ ...string) *exec.Cmd {
		cmd := exec.Command("echo", string(mockRespJSON))
		return cmd
	}

	_, err = GetFirstMFADevice("test-profile")

	if wantSub := "no authenticator app"; err == nil || !strings.Contains(err.Error(), wantSub) {
		t.Errorf("GetFirstMFADevice() = %v, want an error containing %q", err, wantSub)
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

	randStr, err := testutil.RandomString(8)
	if err != nil {
		t.Fatalf("Failed to generate random string: %v", err)
	}
	_, err = GetFirstMFADevice("nonexistent-profile-" + randStr)
	if err == nil {
		t.Error("Expected error for nonexistent profile, got nil")
	}
}

func TestCredentials_Clear(t *testing.T) {
	tests := map[string]struct {
		creds          *Credentials
		expectNonEmpty bool // Expiration should remain non-empty
	}{
		"normal credentials": {
			creds: &Credentials{
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				SessionToken:    "AQoDYXdzEJr...",
				Expiration:      "2023-12-01T00:00:00Z",
			},
			expectNonEmpty: true,
		},
		"empty credentials": {
			creds: &Credentials{},
		},
		"nil credentials": {
			creds: nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			tc.creds.Clear()

			if tc.creds == nil {
				return
			}

			if tc.creds.AccessKeyID != "" {
				t.Errorf("AccessKeyID not zeroed: %q", tc.creds.AccessKeyID)
			}
			if tc.creds.SecretAccessKey != "" {
				t.Errorf("SecretAccessKey not zeroed: %q", tc.creds.SecretAccessKey)
			}
			if tc.creds.SessionToken != "" {
				t.Errorf("SessionToken not zeroed: %q", tc.creds.SessionToken)
			}

			if tc.expectNonEmpty && tc.creds.Expiration == "" {
				t.Error("Expiration should not be zeroed")
			}
		})
	}
}
