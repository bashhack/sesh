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
			// Use printf to avoid newline and ensure clean output
			return exec.Command("printf", "testuser")
		}
		if command == "security" && len(args) >= 4 && args[0] == "find-generic-password" {
			// Use printf to avoid newline and ensure clean output
			return exec.Command("printf", "test-secret")
		}
		return exec.Command("printf", "")
	}

	provider := NewDefaultProvider()
	secretBytes, err := provider.GetSecret("testuser", "test-service")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	
	// Convert bytes to string for assertion
	secretStr := string(secretBytes)
	expectedStr := "test-secret"
	if secretStr != expectedStr {
		t.Errorf("Expected secret '%s', got '%s'", expectedStr, secretStr)
	}
}

func TestDefaultProviderGetMFASerial(t *testing.T) {
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()

	execCommand = func(command string, args ...string) *exec.Cmd {
		if command == "whoami" {
			// Use printf to avoid newline and ensure clean output
			return exec.Command("printf", "testuser")
		}
		if command == "security" && len(args) >= 4 && args[0] == "find-generic-password" {
			// Use printf to avoid newline and ensure clean output
			return exec.Command("printf", "test-serial")
		}
		return exec.Command("printf", "")
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
