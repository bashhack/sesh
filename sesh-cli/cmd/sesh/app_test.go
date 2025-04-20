package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/aws"
)

type KeychainError struct {
	Message string
}

func (e *KeychainError) Error() string {
	return e.Message
}

type SessionTokenError struct {
	Message string
}

func (e *SessionTokenError) Error() string {
	return e.Message
}

func TestNewDefaultApp(t *testing.T) {
	app := NewDefaultApp()

	if app.AWS == nil {
		t.Error("AWS provider is nil")
	}
	if app.Keychain == nil {
		t.Error("Keychain provider is nil")
	}
	if app.TOTP == nil {
		t.Error("TOTP provider is nil")
	}
	if app.SetupWizard == nil {
		t.Error("SetupWizard is nil")
	}
	if app.ExecLookPath == nil {
		t.Error("ExecLookPath is nil")
	}
	if app.Exit == nil {
		t.Error("Exit is nil")
	}
	if app.Stdout == nil {
		t.Error("Stdout is nil")
	}
	if app.Stderr == nil {
		t.Error("Stderr is nil")
	}
}

func TestAppMFAError(t *testing.T) {
	var stderr bytes.Buffer

	app := NewDefaultApp()
	app.Stderr = &stderr

	testErr := &aws.MFADeviceNotFoundError{Message: "test error"}
	app.PrintMFAError(testErr)

	output := stderr.String()

	expectedStrings := []string{
		"test error",
		"Provide your MFA ARN explicitly",
		"--serial",
		"SESH_MFA_SERIAL",
		"aws configure",
	}

	for _, expected := range expectedStrings {
		if !bytes.Contains(stderr.Bytes(), []byte(expected)) {
			t.Errorf("Expected error output to contain '%s', got: %s", expected, output)
		}
	}
}

func TestAppKeychainError(t *testing.T) {
	var stderr bytes.Buffer

	app := NewDefaultApp()
	app.Stderr = &stderr

	testErr := &KeychainError{Message: "test error"}
	app.PrintKeychainError(testErr, "testuser", "test-keychain")

	output := stderr.String()

	expectedStrings := []string{
		"test error",
		"Run the setup wizard",
		"sesh --setup",
		"--keychain-user",
		"--keychain-name",
		"testuser",
		"test-keychain",
	}

	for _, expected := range expectedStrings {
		if !bytes.Contains(stderr.Bytes(), []byte(expected)) {
			t.Errorf("Expected error output to contain '%s', got: %s", expected, output)
		}
	}
}

func TestAppSessionTokenError(t *testing.T) {
	var stderr bytes.Buffer

	app := NewDefaultApp()
	app.Stderr = &stderr

	testErr := &SessionTokenError{Message: "test error"}
	app.PrintSessionTokenError(testErr)

	output := stderr.String()

	expectedStrings := []string{
		"test error",
		"Verify your AWS credentials",
		"aws configure",
		"Verify your MFA serial ARN",
		"--serial",
		"Check AWS CLI installation",
	}

	for _, expected := range expectedStrings {
		if !bytes.Contains(stderr.Bytes(), []byte(expected)) {
			t.Errorf("Expected error output to contain '%s', got: %s", expected, output)
		}
	}
}

func TestFormatExpiryTime(t *testing.T) {
	app := NewDefaultApp()

	invalidDate := "invalid"
	result := app.FormatExpiryTime(invalidDate)
	if result != invalidDate {
		t.Errorf("Expected invalid date to be returned as-is, got: %s", result)
	}

	futureTime := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
	result = app.FormatExpiryTime(futureTime)

	if !bytes.Contains([]byte(result), []byte("valid for")) {
		t.Errorf("Expected result to contain 'valid for', got: %s", result)
	}

	if !bytes.Contains([]byte(result), []byte("h")) {
		t.Errorf("Expected result to contain hour marker 'h', got: %s", result)
	}

	if !bytes.Contains([]byte(result), []byte("m")) {
		t.Errorf("Expected result to contain minute marker 'm', got: %s", result)
	}
}
