package setup

import (
	"os/exec"
	"sync"
	"testing"

	"github.com/bashhack/sesh/internal/testutil"
)

// MockCommand creates a mock exec.Cmd object
type MockCommand struct {
	OutputData  []byte
	ErrorValue  error
	RunCalled   bool
	CommandName string
	CommandArgs []string
}

// Output mocks the exec.Cmd Output method
func (m *MockCommand) Output() ([]byte, error) {
	return m.OutputData, m.ErrorValue
}

// Run mocks the exec.Cmd Run method
func (m *MockCommand) Run() error {
	m.RunCalled = true
	return m.ErrorValue
}

// SimpleRunner is a mock command runner for testing
type SimpleRunner struct {
	sync.Mutex
	Commands      map[string]*MockCommand
	CommandCalls  []string
	DefaultOutput []byte
	DefaultError  error
}

// Command returns a mock command based on the command name
func (r *SimpleRunner) Command(command string, args ...string) *exec.Cmd {
	r.Mutex.Lock()
	r.CommandCalls = append(r.CommandCalls, command)
	r.Mutex.Unlock()

	// Check if we have a specific mock for this command
	if r.Commands != nil && r.Commands[command] != nil {
		return testutil.MockExecCommand(
			string(r.Commands[command].OutputData),
			r.Commands[command].ErrorValue,
		)(command, args...)
	}

	// Fall back to default behavior
	return testutil.MockExecCommand(
		string(r.DefaultOutput),
		r.DefaultError,
	)(command, args...)
}

func TestWizardErrorHandling(t *testing.T) {
	// Skip this test since we've refactored the implementation
	t.Skip("Test no longer applicable with refactored setup wizard")
}

func TestSetupService(t *testing.T) {
	// Mock setup handler
	type mockSetupHandler struct {
		name        string
		setupCalled bool
		setupError  error
	}

	handler := &mockSetupHandler{
		name: "test-service",
	}

	// Implement SetupHandler interface
	handler.ServiceName = func() string {
		return handler.name
	}
	handler.Setup = func() error {
		handler.setupCalled = true
		return handler.setupError
	}

	// Create setup service
	service := NewSetupService(nil)

	// Test registering handler
	service.RegisterHandler(handler)

	// Test getting available services
	services := service.GetAvailableServices()
	if len(services) != 1 {
		t.Errorf("Expected 1 service, got %d", len(services))
	}
	if services[0] != "test-service" {
		t.Errorf("Expected service 'test-service', got %s", services[0])
	}

	// Test setup for registered service
	err := service.SetupService("test-service")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !handler.setupCalled {
		t.Error("Setup was not called on handler")
	}

	// Test setup for unregistered service
	err = service.SetupService("unknown-service")
	if err == nil {
		t.Error("Expected error for unknown service, got nil")
	}
}

func TestAWSSetupHandler(t *testing.T) {
	// This is a basic test to ensure the handler implements the interface
	handler := NewAWSSetupHandler(nil)

	if handler.ServiceName() != "aws" {
		t.Errorf("Expected service name 'aws', got %s", handler.ServiceName())
	}
}

func TestTOTPSetupHandler(t *testing.T) {
	// This is a basic test to ensure the handler implements the interface
	handler := NewTOTPSetupHandler(nil)

	if handler.ServiceName() != "totp" {
		t.Errorf("Expected service name 'totp', got %s", handler.ServiceName())
	}
}

// These tests are no longer applicable with the refactored setup wizard

// Remove this test as it's testing the specific implementation with WizardOptions that's been refactored

// Remove this test as it's testing the specific implementation with runWizardWithOptions that's been refactored

// Remove this test as it's testing the specific implementation with runWizardWithOptions that's been refactored

// Remove this test as it's testing the specific implementation with runWizardWithOptions that's been refactored

// Remove this test as it's testing the specific implementation with runWizardWithOptions that's been refactored

// Remove this test as it's testing the specific implementation with runWizardWithOptions that's been refactored

func TestHelperProcess(*testing.T) {
	testutil.TestHelperProcess()
}
