package setup

import (
	"bufio"
	"bytes"
	"io"
	"os"
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

// Tests for TOTP Setup Handler prompt methods

func TestTOTPSetupHandler_promptForServiceName(t *testing.T) {
	tests := map[string]struct {
		input      string
		wantResult string
		wantErr    bool
		wantErrMsg string
	}{
		"valid service name": {
			input:      "github\n",
			wantResult: "github",
			wantErr:    false,
		},
		"service name with spaces": {
			input:      "My Service\n",
			wantResult: "My Service",
			wantErr:    false,
		},
		"empty service name": {
			input:      "\n",
			wantResult: "",
			wantErr:    true,
			wantErrMsg: "service name cannot be empty",
		},
		"service name with only spaces": {
			input:      "   \n",
			wantResult: "",
			wantErr:    true,
			wantErrMsg: "service name cannot be empty",
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			// Create handler with mock reader
			handler := &TOTPSetupHandler{
				reader: strings.NewReader(test.input),
			}

			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			result, err := handler.promptForServiceName()

			w.Close()
			os.Stdout = oldStdout

			// Read captured output
			var buf bytes.Buffer
			io.Copy(&buf, r)
			output := buf.String()

			// Check prompt was displayed
			if !strings.Contains(output, "Enter name for this TOTP service:") {
				t.Error("Expected prompt not displayed")
			}

			// Check result
			if result != test.wantResult {
				t.Errorf("promptForServiceName() result = %v, want %v", result, test.wantResult)
			}

			// Check error
			if test.wantErr && err == nil {
				t.Error("promptForServiceName() expected error but got nil")
			}
			if !test.wantErr && err != nil {
				t.Errorf("promptForServiceName() unexpected error: %v", err)
			}
			if test.wantErrMsg != "" && err != nil {
				if err.Error() != test.wantErrMsg {
					t.Errorf("error message = %v, want %v", err.Error(), test.wantErrMsg)
				}
			}
		})
	}
}

func TestTOTPSetupHandler_promptForProfile(t *testing.T) {
	tests := map[string]struct {
		input      string
		wantResult string
	}{
		"profile provided": {
			input:      "work\n",
			wantResult: "work",
		},
		"empty profile": {
			input:      "\n",
			wantResult: "",
		},
		"profile with spaces": {
			input:      "my profile\n",
			wantResult: "my profile",
		},
		"only spaces": {
			input:      "   \n",
			wantResult: "",
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			// Create handler with mock reader
			handler := &TOTPSetupHandler{
				reader: strings.NewReader(test.input),
			}

			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			result, err := handler.promptForProfile()

			w.Close()
			os.Stdout = oldStdout

			// Read captured output
			var buf bytes.Buffer
			io.Copy(&buf, r)
			output := buf.String()

			// Check prompt was displayed
			if !strings.Contains(output, "Enter profile name (optional, for multiple accounts with the same service):") {
				t.Error("Expected prompt not displayed")
			}

			// Check result
			if result != test.wantResult {
				t.Errorf("promptForProfile() result = %v, want %v", result, test.wantResult)
			}

			// Should never error
			if err != nil {
				t.Errorf("promptForProfile() unexpected error: %v", err)
			}
		})
	}
}

func TestTOTPSetupHandler_promptForCaptureMethod(t *testing.T) {
	tests := map[string]struct {
		input      string
		wantResult string
		wantErr    bool
		wantErrMsg string
	}{
		"choice 1": {
			input:      "1\n",
			wantResult: "1",
			wantErr:    false,
		},
		"choice 2": {
			input:      "2\n",
			wantResult: "2",
			wantErr:    false,
		},
		"invalid choice 3": {
			input:      "3\n",
			wantResult: "",
			wantErr:    true,
			wantErrMsg: "invalid choice, please select 1 or 2",
		},
		"invalid choice text": {
			input:      "manual\n",
			wantResult: "",
			wantErr:    true,
			wantErrMsg: "invalid choice, please select 1 or 2",
		},
		"empty choice": {
			input:      "\n",
			wantResult: "",
			wantErr:    true,
			wantErrMsg: "invalid choice, please select 1 or 2",
		},
		"choice with spaces": {
			input:      " 1 \n",
			wantResult: "1",
			wantErr:    false,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			// Create handler with mock reader
			handler := &TOTPSetupHandler{
				reader: strings.NewReader(test.input),
			}

			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			result, err := handler.promptForCaptureMethod()

			w.Close()
			os.Stdout = oldStdout

			// Read captured output
			var buf bytes.Buffer
			io.Copy(&buf, r)
			output := buf.String()

			// Check prompts were displayed
			expectedPrompts := []string{
				"How would you like to capture the TOTP secret?",
				"1: Enter the secret key manually",
				"2: Capture QR code from screen",
				"Enter your choice (1-2):",
			}
			for _, expected := range expectedPrompts {
				if !strings.Contains(output, expected) {
					t.Errorf("Expected prompt not displayed: %q", expected)
				}
			}

			// Check result
			if result != test.wantResult {
				t.Errorf("promptForCaptureMethod() result = %v, want %v", result, test.wantResult)
			}

			// Check error
			if test.wantErr && err == nil {
				t.Error("promptForCaptureMethod() expected error but got nil")
			}
			if !test.wantErr && err != nil {
				t.Errorf("promptForCaptureMethod() unexpected error: %v", err)
			}
			if test.wantErrMsg != "" && err != nil {
				if err.Error() != test.wantErrMsg {
					t.Errorf("error message = %v, want %v", err.Error(), test.wantErrMsg)
				}
			}
		})
	}
}

func TestTOTPSetupHandler_captureTOTPSecret(t *testing.T) {
	tests := map[string]struct {
		choice     string
		wantErr    bool
		wantErrMsg string
	}{
		"invalid choice 3": {
			choice:     "3",
			wantErr:    true,
			wantErrMsg: "invalid choice, please select 1 or 2",
		},
		"invalid choice empty": {
			choice:     "",
			wantErr:    true,
			wantErrMsg: "invalid choice, please select 1 or 2",
		},
		"invalid choice text": {
			choice:     "manual",
			wantErr:    true,
			wantErrMsg: "invalid choice, please select 1 or 2",
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			handler := &TOTPSetupHandler{}

			_, err := handler.captureTOTPSecret(test.choice)

			// Check error
			if test.wantErr && err == nil {
				t.Error("captureTOTPSecret() expected error but got nil")
			}
			if !test.wantErr && err != nil {
				t.Errorf("captureTOTPSecret() unexpected error: %v", err)
			}
			if test.wantErrMsg != "" && err != nil {
				if err.Error() != test.wantErrMsg {
					t.Errorf("error message = %v, want %v", err.Error(), test.wantErrMsg)
				}
			}
		})
	}
}

func TestTOTPSetupHandler_showTOTPSetupCompletionMessage(t *testing.T) {
	tests := map[string]struct {
		serviceName string
		profile     string
		wantOutput  []string
	}{
		"service without profile": {
			serviceName: "github",
			profile:     "",
			wantOutput: []string{
				"✅ Setup complete! You can now use 'sesh --service totp --service-name github' to generate TOTP codes.",
				"Use 'sesh --service totp --service-name github --clip' to copy the code to clipboard.",
			},
		},
		"service with profile": {
			serviceName: "github",
			profile:     "work",
			wantOutput: []string{
				"✅ Setup complete! You can now use 'sesh --service totp --service-name github --profile work' to generate TOTP codes.",
				"Use 'sesh --service totp --service-name github --clip' to copy the code to clipboard.",
			},
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			handler := &TOTPSetupHandler{}

			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			handler.showTOTPSetupCompletionMessage(test.serviceName, test.profile)

			w.Close()
			os.Stdout = oldStdout

			// Read captured output
			var buf bytes.Buffer
			io.Copy(&buf, r)
			output := buf.String()

			// Check expected output
			for _, expected := range test.wantOutput {
				if !strings.Contains(output, expected) {
					t.Errorf("Expected output not found: %q", expected)
				}
			}
		})
	}
}

func TestAWSSetupHandler(t *testing.T) {
	// This is a basic test to ensure the handler implements the interface
	handler := NewAWSSetupHandler(nil)

	if handler.ServiceName() != "aws" {
		t.Errorf("Expected service name 'aws', got %s", handler.ServiceName())
	}
}

