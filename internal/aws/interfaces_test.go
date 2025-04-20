package aws

import (
	"encoding/json"
	"os/exec"
	"testing"
)

func TestNewDefaultProvider(t *testing.T) {
	provider := NewDefaultProvider()

	_, ok := provider.(*DefaultProvider)
	if !ok {
		t.Errorf("Expected *DefaultProvider, got %T", provider)
	}
}

func TestDefaultProviderImplementsProvider(t *testing.T) {
	// Compile-time check that DefaultProvider implements Provider
	var _ Provider = (*DefaultProvider)(nil)
}

func TestDefaultProviderGetSessionToken(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	execCommand = func(command string, args ...string) *exec.Cmd {
		mockResp := SessionTokenResponse{
			Credentials: Credentials{
				AccessKeyId:     "test-key",
				SecretAccessKey: "test-secret",
				SessionToken:    "test-token",
				Expiration:      "2023-01-01T00:00:00Z",
			},
		}

		mockRespJSON, _ := json.Marshal(mockResp)
		return exec.Command("echo", string(mockRespJSON))
	}

	provider := NewDefaultProvider()
	creds, err := provider.GetSessionToken("test-profile", "test-serial", "123456")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if creds.AccessKeyId != "test-key" {
		t.Errorf("Expected AccessKeyId 'test-key', got '%s'", creds.AccessKeyId)
	}
}

func TestDefaultProviderGetFirstMFADevice(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	execCommand = func(command string, args ...string) *exec.Cmd {
		mockResp := ListDevicesResponse{
			MFADevices: []MFADevice{
				{
					SerialNumber: "test-serial",
				},
			},
		}

		mockRespJSON, _ := json.Marshal(mockResp)
		return exec.Command("echo", string(mockRespJSON))
	}

	provider := NewDefaultProvider()
	serial, err := provider.GetFirstMFADevice("test-profile")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if serial != "test-serial" {
		t.Errorf("Expected serial 'test-serial', got '%s'", serial)
	}
}
