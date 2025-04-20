package keychain

import (
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

func TestDefaultProviderGetSecret(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	execCommand = func(command string, args ...string) *exec.Cmd {
		if command == "whoami" {
			return exec.Command("echo", "testuser")
		}
		if command == "security" && len(args) >= 4 && args[0] == "find-generic-password" {
			return exec.Command("echo", "test-secret")
		}
		return exec.Command("echo", "")
	}

	provider := NewDefaultProvider()
	secret, err := provider.GetSecret("testuser", "test-service")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if secret != "test-secret" {
		t.Errorf("Expected secret 'test-secret', got '%s'", secret)
	}
}

func TestDefaultProviderGetMFASerial(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	execCommand = func(command string, args ...string) *exec.Cmd {
		if command == "whoami" {
			return exec.Command("echo", "testuser")
		}
		if command == "security" && len(args) >= 4 && args[0] == "find-generic-password" {
			return exec.Command("echo", "test-serial")
		}
		return exec.Command("echo", "")
	}

	provider := NewDefaultProvider()
	serial, err := provider.GetMFASerial("testuser")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if serial != "test-serial" {
		t.Errorf("Expected serial 'test-serial', got '%s'", serial)
	}
}
