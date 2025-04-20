package testutil

import (
	"os"
	"testing"
)

// TestMockExecCommand tests creation of mock commands
// We can't actually execute the commands in a test because
// they involve running the test binary itself as a helper process
func TestMockExecCommand(t *testing.T) {
	// We can only verify that the MockExecCommand returns a valid command
	// that has the correct environment variables set
	mockCmd := MockExecCommand("test output", nil)
	cmd := mockCmd("echo", "test")

	// Verify the environment has the expected values
	foundHelper := false
	foundOutput := false

	for _, env := range cmd.Env {
		if env == "GO_WANT_HELPER_PROCESS=1" {
			foundHelper = true
		}
		if env == "MOCK_OUTPUT=test output" {
			foundOutput = true
		}
	}

	if !foundHelper {
		t.Error("GO_WANT_HELPER_PROCESS env var not found")
	}
	if !foundOutput {
		t.Error("MOCK_OUTPUT env var not found")
	}

	// Test with error flag
	mockCmd = MockExecCommand("", os.ErrNotExist)
	cmd = mockCmd("ls", "nonexistentdir")

	foundError := false
	for _, env := range cmd.Env {
		if env == "MOCK_ERROR=1" {
			foundError = true
			break
		}
	}

	if !foundError {
		t.Error("MOCK_ERROR env var not found")
	}
}

// TestMockCommandContext tests the mockCmd implementation
func TestMockCommandContext(t *testing.T) {
	// Test success case
	mockCmd := MockCommandContext("test output", nil)
	cmd := mockCmd("echo", "test")

	// Verify output method
	output, err := cmd.Output()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if string(output) != "test output" {
		t.Errorf("Expected 'test output', got '%s'", string(output))
	}

	// Verify Run method
	err = cmd.Run()
	if err != nil {
		t.Errorf("Expected no error from Run(), got %v", err)
	}

	// Verify CombinedOutput method
	output, err = cmd.CombinedOutput()
	if err != nil {
		t.Errorf("Expected no error from CombinedOutput(), got %v", err)
	}
	if string(output) != "test output" {
		t.Errorf("Expected 'test output', got '%s'", string(output))
	}

	// Test error case
	mockCmd = MockCommandContext("", os.ErrNotExist)
	cmd = mockCmd("ls", "nonexistentdir")

	output, err = cmd.Output()
	if err == nil {
		t.Error("Expected error from Output(), got nil")
	}
	if len(output) > 0 {
		t.Errorf("Expected empty output, got '%s'", string(output))
	}

	err = cmd.Run()
	if err == nil {
		t.Error("Expected error from Run(), got nil")
	}

	output, err = cmd.CombinedOutput()
	if err == nil {
		t.Error("Expected error from CombinedOutput(), got nil")
	}
	if len(output) > 0 {
		t.Errorf("Expected empty output, got '%s'", string(output))
	}
}

// TestCaptureOutput tests the stdout and stderr capture functions
func TestCaptureOutput(t *testing.T) {
	// Test stdout capture
	stdout := CaptureStdout(func() {
		os.Stdout.WriteString("test stdout")
	})
	if stdout != "test stdout" {
		t.Errorf("Expected 'test stdout', got '%s'", stdout)
	}

	// Test stderr capture
	stderr := CaptureStderr(func() {
		os.Stderr.WriteString("test stderr")
	})
	if stderr != "test stderr" {
		t.Errorf("Expected 'test stderr', got '%s'", stderr)
	}
}
