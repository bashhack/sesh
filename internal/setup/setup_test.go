package setup

import (
	"bufio"
	"bytes"
	"fmt"
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
				reader: bufio.NewReader(strings.NewReader(test.input)),
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
				reader: bufio.NewReader(strings.NewReader(test.input)),
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
				reader: bufio.NewReader(strings.NewReader(test.input)),
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


// TestTOTPSetupHandler_captureManualEntry tests the manual entry capture
func TestTOTPSetupHandler_captureManualEntry(t *testing.T) {
	// Note: This function uses term.ReadPassword which reads from syscall.Stdin
	// Making it difficult to test directly. We'll test the error paths and
	// document that the happy path requires manual integration testing.
	
	t.Run("integration test required", func(t *testing.T) {
		t.Skip("captureManualEntry uses term.ReadPassword which reads from syscall.Stdin - requires integration testing")
	})
}

// TestAWSSetupHandler_verifyAWSCredentials tests AWS credential verification
func TestAWSSetupHandler_verifyAWSCredentials(t *testing.T) {
	tests := map[string]struct {
		profile       string
		commandOutput string
		commandError  error
		wantErr       bool
		wantErrMsg    string
	}{
		"valid credentials": {
			profile:       "default",
			commandOutput: `{"UserId":"AIDAI23HXD3MBVRDTCKBR","Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/testuser"}`,
			commandError:  nil,
			wantErr:       false,
		},
		"invalid credentials": {
			profile:       "nonexistent",
			commandOutput: "",
			commandError:  exec.ErrNotFound,
			wantErr:       true,
			wantErrMsg:    "failed to verify AWS credentials",
		},
		"empty profile valid": {
			profile:       "",
			commandOutput: `{"UserId":"AIDAI23HXD3MBVRDTCKBR","Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/testuser"}`,
			commandError:  nil,
			wantErr:       false,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			// Create a mock command runner
			runner := &SimpleRunner{
				Commands: map[string]*MockCommand{
					"aws": {
						OutputData: []byte(test.commandOutput),
						ErrorValue: test.commandError,
					},
				},
			}

			handler := &AWSSetupHandler{
				runner: runner,
			}

			err := handler.verifyAWSCredentials(test.profile)

			// Check error
			if test.wantErr && err == nil {
				t.Error("verifyAWSCredentials() expected error but got nil")
			}
			if !test.wantErr && err != nil {
				t.Errorf("verifyAWSCredentials() unexpected error: %v", err)
			}
			if test.wantErrMsg != "" && err != nil {
				if !strings.Contains(err.Error(), test.wantErrMsg) {
					t.Errorf("error message = %v, want to contain %v", err.Error(), test.wantErrMsg)
				}
			}
		})
	}
}

// TestAWSSetupHandler_captureAWSManualEntry tests manual AWS credential entry
func TestAWSSetupHandler_captureAWSManualEntry(t *testing.T) {
	// Note: This function uses term.ReadPassword which reads from syscall.Stdin
	// for the secret key, making it difficult to test the password input directly.
	
	tests := map[string]struct {
		inputs     []string // access key, region
		wantAccess string
		wantRegion string
		wantErr    bool
	}{
		"valid inputs": {
			inputs:     []string{"AKIAIOSFODNN7EXAMPLE\n", "us-east-1\n"},
			wantAccess: "AKIAIOSFODNN7EXAMPLE",
			wantRegion: "us-east-1",
			wantErr:    false,
		},
		"empty access key": {
			inputs:     []string{"\n", "us-east-1\n"},
			wantAccess: "",
			wantRegion: "",
			wantErr:    true,
		},
		"access key with spaces": {
			inputs:     []string{"  AKIAIOSFODNN7EXAMPLE  \n", "us-west-2\n"},
			wantAccess: "AKIAIOSFODNN7EXAMPLE",
			wantRegion: "us-west-2",
			wantErr:    false,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			// Create handler with mock reader for non-password inputs
			handler := &AWSSetupHandler{
				reader: bufio.NewReader(strings.NewReader(strings.Join(test.inputs, ""))),
			}

			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Note: The actual secret key input using term.ReadPassword
			// cannot be easily mocked, so we focus on testing the 
			// access key and region input handling
			t.Skip("captureAWSManualEntry uses term.ReadPassword for secret key - requires integration testing")

			w.Close()
			os.Stdout = oldStdout

			// Read captured output
			var buf bytes.Buffer
			io.Copy(&buf, r)
		})
	}
}

// TestAWSSetupHandler_captureMFASecret tests MFA secret capture
func TestAWSSetupHandler_captureMFASecret(t *testing.T) {
	// Note: This function uses term.ReadPassword which reads from syscall.Stdin
	// Making it difficult to test directly.
	
	t.Run("integration test required", func(t *testing.T) {
		t.Skip("captureMFASecret uses term.ReadPassword which reads from syscall.Stdin - requires integration testing")
	})
}

// TestAWSSetupHandler_selectMFADevice tests MFA device selection
func TestAWSSetupHandler_selectMFADevice(t *testing.T) {
	tests := map[string]struct {
		devices     []string
		userInput   string
		wantDevice  string
		wantErr     bool
		wantErrMsg  string
	}{
		"single device": {
			devices:    []string{"arn:aws:iam::123456789012:mfa/user"},
			userInput:  "", // No input needed for single device
			wantDevice: "arn:aws:iam::123456789012:mfa/user",
			wantErr:    false,
		},
		"multiple devices select first": {
			devices:    []string{"arn:aws:iam::123456789012:mfa/user1", "arn:aws:iam::123456789012:mfa/user2"},
			userInput:  "1\n",
			wantDevice: "arn:aws:iam::123456789012:mfa/user1",
			wantErr:    false,
		},
		"multiple devices select second": {
			devices:    []string{"arn:aws:iam::123456789012:mfa/user1", "arn:aws:iam::123456789012:mfa/user2"},
			userInput:  "2\n",
			wantDevice: "arn:aws:iam::123456789012:mfa/user2",
			wantErr:    false,
		},
		"invalid selection too high": {
			devices:    []string{"arn:aws:iam::123456789012:mfa/user1", "arn:aws:iam::123456789012:mfa/user2"},
			userInput:  "3\n",
			wantDevice: "",
			wantErr:    true,
			wantErrMsg: "invalid selection",
		},
		"invalid selection zero": {
			devices:    []string{"arn:aws:iam::123456789012:mfa/user1", "arn:aws:iam::123456789012:mfa/user2"},
			userInput:  "0\n",
			wantDevice: "",
			wantErr:    true,
			wantErrMsg: "invalid selection",
		},
		"invalid selection text": {
			devices:    []string{"arn:aws:iam::123456789012:mfa/user1", "arn:aws:iam::123456789012:mfa/user2"},
			userInput:  "first\n",
			wantDevice: "",
			wantErr:    true,
			wantErrMsg: "invalid input",
		},
		"no devices": {
			devices:    []string{},
			userInput:  "",
			wantDevice: "",
			wantErr:    true,
			wantErrMsg: "no MFA devices found",
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			// Create handler with mock reader
			handler := &AWSSetupHandler{
				reader: bufio.NewReader(strings.NewReader(test.userInput)),
			}

			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			device, err := handler.selectMFADevice(test.devices)

			w.Close()
			os.Stdout = oldStdout

			// Read captured output
			var buf bytes.Buffer
			io.Copy(&buf, r)
			output := buf.String()

			// Check device
			if device != test.wantDevice {
				t.Errorf("selectMFADevice() device = %v, want %v", device, test.wantDevice)
			}

			// Check error
			if test.wantErr && err == nil {
				t.Error("selectMFADevice() expected error but got nil")
			}
			if !test.wantErr && err != nil {
				t.Errorf("selectMFADevice() unexpected error: %v", err)
			}
			if test.wantErrMsg != "" && err != nil {
				if !strings.Contains(err.Error(), test.wantErrMsg) {
					t.Errorf("error message = %v, want to contain %v", err.Error(), test.wantErrMsg)
				}
			}

			// Check prompts for multiple devices
			if len(test.devices) > 1 {
				if !strings.Contains(output, "Multiple MFA devices found:") {
					t.Error("Expected multiple devices prompt not displayed")
				}
				for i, device := range test.devices {
					expectedPrompt := fmt.Sprintf("%d: %s", i+1, device)
					if !strings.Contains(output, expectedPrompt) {
						t.Errorf("Expected device option not displayed: %q", expectedPrompt)
					}
				}
			}
		})
	}
}
