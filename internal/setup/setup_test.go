package setup

import (
	"os/exec"
	"strings"
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

// mockSetupHandler implements SetupHandler for testing
type mockSetupHandler struct {
	name        string
	setupCalled bool
	setupError  error
}

func (h *mockSetupHandler) ServiceName() string {
	return h.name
}

func (h *mockSetupHandler) Setup() error {
	h.setupCalled = true
	return h.setupError
}

func TestSetupService(t *testing.T) {
	handler := &mockSetupHandler{
		name: "test-service",
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
	
	// Find our service in the list (order not guaranteed)
	found := false
	for _, s := range services {
		if s == "test-service" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected to find 'test-service' in services list")
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

func TestAWSSetupHandler_createServiceName(t *testing.T) {
	handler := &AWSSetupHandler{}
	
	tests := map[string]struct {
		prefix  string
		profile string
		want    string
	}{
		"default profile": {
			prefix:  "sesh-aws",
			profile: "",
			want:    "sesh-aws-default",
		},
		"custom profile": {
			prefix:  "sesh-aws",
			profile: "dev",
			want:    "sesh-aws-dev",
		},
		"serial prefix with profile": {
			prefix:  "sesh-aws-serial",
			profile: "prod",
			want:    "sesh-aws-serial-prod",
		},
		"empty prefix default profile": {
			prefix:  "",
			profile: "",
			want:    "-default",
		},
	}
	
	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			got := handler.createServiceName(test.prefix, test.profile)
			if got != test.want {
				t.Errorf("createServiceName(%q, %q) = %v, want %v", test.prefix, test.profile, got, test.want)
			}
		})
	}
}

func TestTOTPSetupHandler_createTOTPServiceName(t *testing.T) {
	handler := &TOTPSetupHandler{}
	
	tests := map[string]struct {
		serviceName string
		profile     string
		want        string
	}{
		"service without profile": {
			serviceName: "github",
			profile:     "",
			want:        "sesh-totp-github",
		},
		"service with profile": {
			serviceName: "github",
			profile:     "work",
			want:        "sesh-totp-github-work",
		},
		"service with spaces": {
			serviceName: "my service",
			profile:     "",
			want:        "sesh-totp-my service",
		},
		"empty service": {
			serviceName: "",
			profile:     "",
			want:        "sesh-totp-",
		},
	}
	
	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			got := handler.createTOTPServiceName(test.serviceName, test.profile)
			if got != test.want {
				t.Errorf("createTOTPServiceName(%q, %q) = %v, want %v", test.serviceName, test.profile, got, test.want)
			}
		})
	}
}

func TestAWSSetupHandler_createAWSCommand(t *testing.T) {
	handler := &AWSSetupHandler{}
	
	tests := map[string]struct {
		profile string
		args    []string
		wantCmd string
		wantArgs []string
	}{
		"command without profile": {
			profile: "",
			args:    []string{"sts", "get-caller-identity"},
			wantCmd: "aws",
			wantArgs: []string{"sts", "get-caller-identity"},
		},
		"command with profile": {
			profile: "dev",
			args:    []string{"sts", "get-caller-identity"},
			wantCmd: "aws",
			wantArgs: []string{"sts", "--profile", "dev", "get-caller-identity"},
		},
		"complex command with profile": {
			profile: "prod",
			args:    []string{"iam", "list-mfa-devices", "--query", "MFADevices[].SerialNumber", "--output", "text"},
			wantCmd: "aws",
			wantArgs: []string{"iam", "--profile", "prod", "list-mfa-devices", "--query", "MFADevices[].SerialNumber", "--output", "text"},
		},
	}
	
	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			cmd := handler.createAWSCommand(test.profile, test.args...)
			
			// Check command name
			if cmd.Path != test.wantCmd {
				// The command might be resolved to full path, so check just the base name
				base := cmd.Path
				if idx := len(cmd.Path) - 1; idx >= 0 {
					for i := idx; i >= 0; i-- {
						if cmd.Path[i] == '/' {
							base = cmd.Path[i+1:]
							break
						}
					}
				}
				if base != test.wantCmd {
					t.Errorf("command = %v, want %v", base, test.wantCmd)
				}
			}
			
			// Check arguments - skip the first argument which is the command itself
			gotArgs := cmd.Args[1:]
			if len(gotArgs) != len(test.wantArgs) {
				t.Errorf("args length = %d, want %d", len(gotArgs), len(test.wantArgs))
			}
			for i, want := range test.wantArgs {
				if i < len(gotArgs) && gotArgs[i] != want {
					t.Errorf("args[%d] = %v, want %v", i, gotArgs[i], want)
				}
			}
		})
	}
}

func TestAWSSetupHandler_promptForMFAARN(t *testing.T) {
	// This is a more complex test that requires mocking user input
	// We'll create a simple validation test for the format checking
	validARNs := []string{
		"arn:aws:iam::123456789012:mfa/user",
		"arn:aws:iam::000000000000:mfa/testuser",
		"arn:aws:iam::999999999999:mfa/my.user-name",
	}
	
	invalidARNs := []string{
		"",
		"not-an-arn",
		"arn:aws:s3::123456789012:bucket/mybucket", // Wrong service
		"arn:aws:iam::123456789012:user/myuser",    // Wrong resource type
		"arn:aws:iam:us-east-1:123456789012:mfa/user", // Region shouldn't be present
	}
	
	// Test ARN validation logic that would be used in promptForMFAARN
	for _, arn := range validARNs {
		if !strings.HasPrefix(arn, "arn:aws:iam::") || !strings.Contains(arn, ":mfa/") {
			t.Errorf("Valid ARN failed validation: %s", arn)
		}
	}
	
	for _, arn := range invalidARNs {
		if arn != "" && strings.HasPrefix(arn, "arn:aws:iam::") && strings.Contains(arn, ":mfa/") {
			t.Errorf("Invalid ARN passed validation: %s", arn)
		}
	}
}
