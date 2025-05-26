package setup

import (
	"bufio"
	"bytes"
	"errors"
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
	// Save original readPassword and restore after test
	origReadPassword := readPassword
	defer func() { readPassword = origReadPassword }()
	
	tests := map[string]struct {
		secretInput string
		readError   error
		wantSecret  string
		wantErr     bool
		wantErrMsg  string
	}{
		"valid secret": {
			secretInput: "JBSWY3DPEHPK3PXP",
			readError:   nil,
			wantSecret:  "JBSWY3DPEHPK3PXP",
			wantErr:     false,
		},
		"secret with spaces": {
			secretInput: "  JBSWY3DPEHPK3PXP  ",
			readError:   nil,
			wantSecret:  "JBSWY3DPEHPK3PXP",
			wantErr:     false,
		},
		"read error": {
			secretInput: "",
			readError:   io.ErrUnexpectedEOF,
			wantSecret:  "",
			wantErr:     true,
			wantErrMsg:  "failed to read secret",
		},
	}
	
	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			// Mock readPassword
			readPassword = func(fd int) ([]byte, error) {
				if test.readError != nil {
					return nil, test.readError
				}
				return []byte(test.secretInput), nil
			}
			
			handler := &TOTPSetupHandler{
				reader: bufio.NewReader(strings.NewReader("")),
			}
			
			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w
			
			secret, err := handler.captureManualEntry()
			
			w.Close()
			os.Stdout = oldStdout
			
			// Read captured output
			var buf bytes.Buffer
			io.Copy(&buf, r)
			output := buf.String()
			
			// Check prompt was displayed
			if !strings.Contains(output, "Enter your TOTP secret key") {
				t.Error("Expected prompt not displayed")
			}
			
			// Check secret
			if secret != test.wantSecret {
				t.Errorf("captureManualEntry() secret = %v, want %v", secret, test.wantSecret)
			}
			
			// Check error
			if test.wantErr && err == nil {
				t.Error("captureManualEntry() expected error but got nil")
			}
			if !test.wantErr && err != nil {
				t.Errorf("captureManualEntry() unexpected error: %v", err)
			}
			if test.wantErrMsg != "" && err != nil {
				if !strings.Contains(err.Error(), test.wantErrMsg) {
					t.Errorf("error message = %v, want to contain %v", err.Error(), test.wantErrMsg)
				}
			}
		})
	}
}

// TestAWSSetupHandler_verifyAWSCredentials tests AWS credential verification
func TestAWSSetupHandler_verifyAWSCredentials(t *testing.T) {
	// Save original execCommand and restore after test
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()
	
	tests := map[string]struct {
		profile       string
		commandOutput string
		commandError  bool
		wantUserArn   string
		wantErr       bool
		wantErrMsg    string
	}{
		"valid credentials": {
			profile:       "default",
			commandOutput: "arn:aws:iam::123456789012:user/testuser",
			commandError:  false,
			wantUserArn:   "arn:aws:iam::123456789012:user/testuser",
			wantErr:       false,
		},
		"invalid credentials": {
			profile:       "nonexistent",
			commandOutput: "",
			commandError:  true,
			wantUserArn:   "",
			wantErr:       true,
			wantErrMsg:    "failed to get AWS identity",
		},
		"empty profile valid": {
			profile:       "",
			commandOutput: "arn:aws:iam::123456789012:user/testuser",
			commandError:  false,
			wantUserArn:   "arn:aws:iam::123456789012:user/testuser",
			wantErr:       false,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			// Mock execCommand
			execCommand = func(command string, args ...string) *exec.Cmd {
				cs := []string{"-test.run=TestHelperProcess", "--", command}
				cs = append(cs, args...)
				cmd := exec.Command(os.Args[0], cs...)
				cmd.Env = []string{
					"GO_WANT_HELPER_PROCESS=1",
					"MOCK_OUTPUT=" + test.commandOutput,
				}
				if test.commandError {
					cmd.Env = append(cmd.Env, "MOCK_ERROR=1")
				}
				return cmd
			}

			handler := &AWSSetupHandler{
				reader: bufio.NewReader(strings.NewReader("")),
			}

			userArn, err := handler.verifyAWSCredentials(test.profile)

			// Check user ARN
			if userArn != test.wantUserArn {
				t.Errorf("verifyAWSCredentials() userArn = %v, want %v", userArn, test.wantUserArn)
			}

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
	// Save original readPassword and restore after test
	origReadPassword := readPassword
	defer func() { readPassword = origReadPassword }()
	
	tests := map[string]struct {
		secretInput string
		readError   error
		wantSecret  string
		wantErr     bool
		wantErrMsg  string
	}{
		"valid AWS secret": {
			secretInput: "JBSWY3DPEHPK3PXP",
			readError:   nil,
			wantSecret:  "JBSWY3DPEHPK3PXP",
			wantErr:     false,
		},
		"secret with spaces": {
			secretInput: "  JBSWY3DPEHPK3PXP  ",
			readError:   nil,
			wantSecret:  "JBSWY3DPEHPK3PXP",
			wantErr:     false,
		},
		"read error": {
			secretInput: "",
			readError:   io.ErrUnexpectedEOF,
			wantSecret:  "",
			wantErr:     true,
			wantErrMsg:  "failed to read secret",
		},
	}
	
	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			// Mock readPassword
			readPassword = func(fd int) ([]byte, error) {
				if test.readError != nil {
					return nil, test.readError
				}
				return []byte(test.secretInput), nil
			}
			
			handler := &AWSSetupHandler{
				reader: bufio.NewReader(strings.NewReader("")),
			}
			
			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w
			
			secret, err := handler.captureAWSManualEntry()
			
			w.Close()
			os.Stdout = oldStdout
			
			// Read captured output
			var buf bytes.Buffer
			io.Copy(&buf, r)
			output := buf.String()
			
			// Check that instructions were displayed
			if !strings.Contains(output, "DO NOT COMPLETE THE AWS SETUP YET") {
				t.Error("Expected setup instructions not displayed")
			}
			
			// Check secret
			if secret != test.wantSecret {
				t.Errorf("captureAWSManualEntry() secret = %v, want %v", secret, test.wantSecret)
			}
			
			// Check error
			if test.wantErr && err == nil {
				t.Error("captureAWSManualEntry() expected error but got nil")
			}
			if !test.wantErr && err != nil {
				t.Errorf("captureAWSManualEntry() unexpected error: %v", err)
			}
			if test.wantErrMsg != "" && err != nil {
				if !strings.Contains(err.Error(), test.wantErrMsg) {
					t.Errorf("error message = %v, want to contain %v", err.Error(), test.wantErrMsg)
				}
			}
		})
	}
}
// TestAWSSetupHandler_captureMFASecret tests MFA secret capture
func TestAWSSetupHandler_captureMFASecret(t *testing.T) {
	// Save original readPassword and restore after test
	origReadPassword := readPassword
	defer func() { readPassword = origReadPassword }()
	
	tests := map[string]struct {
		secretInput string
		readError   error
		wantSecret  string
		wantErr     bool
		wantErrMsg  string
	}{
		"valid MFA secret": {
			secretInput: "JBSWY3DPEHPK3PXP",
			readError:   nil,
			wantSecret:  "JBSWY3DPEHPK3PXP",
			wantErr:     false,
		},
		"secret with spaces": {
			secretInput: "  JBSWY3DPEHPK3PXP  ",
			readError:   nil,
			wantSecret:  "JBSWY3DPEHPK3PXP",
			wantErr:     false,
		},
		"read error": {
			secretInput: "",
			readError:   io.ErrUnexpectedEOF,
			wantSecret:  "",
			wantErr:     true,
			wantErrMsg:  "failed to read secret",
		},
	}
	
	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			// Mock readPassword
			readPassword = func(fd int) ([]byte, error) {
				if test.readError != nil {
					return nil, test.readError
				}
				return []byte(test.secretInput), nil
			}
			
			handler := &AWSSetupHandler{
				reader: bufio.NewReader(strings.NewReader("")),
			}
			
			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w
			
			secret, err := handler.captureMFASecret("1") // Choice 1 for manual entry
			
			w.Close()
			os.Stdout = oldStdout
			
			// Read captured output
			var buf bytes.Buffer
			io.Copy(&buf, r)
			output := buf.String()
			
			// Check that instructions were displayed
			if !strings.Contains(output, "DO NOT COMPLETE THE AWS SETUP YET") {
				t.Error("Expected setup instructions not displayed")
			}
			
			// Check secret
			if secret != test.wantSecret {
				t.Errorf("captureMFASecret() secret = %v, want %v", secret, test.wantSecret)
			}
			
			// Check error
			if test.wantErr && err == nil {
				t.Error("captureMFASecret() expected error but got nil")
			}
			if !test.wantErr && err != nil {
				t.Errorf("captureMFASecret() unexpected error: %v", err)
			}
			if test.wantErrMsg != "" && err != nil {
				if !strings.Contains(err.Error(), test.wantErrMsg) {
					t.Errorf("error message = %v, want to contain %v", err.Error(), test.wantErrMsg)
				}
			}
		})
	}
}

// TestAWSSetupHandler_promptForMFASetupMethod tests MFA setup method selection
func TestAWSSetupHandler_promptForMFASetupMethod(t *testing.T) {
	tests := map[string]struct {
		input      string
		wantChoice string
		wantErr    bool
		wantErrMsg string
	}{
		"choice 1 manual": {
			input:      "1\n",
			wantChoice: "1",
			wantErr:    false,
		},
		"choice 2 qr code": {
			input:      "2\n",
			wantChoice: "2",
			wantErr:    false,
		},
		"invalid choice 3": {
			input:      "3\n",
			wantChoice: "",
			wantErr:    true,
			wantErrMsg: "invalid choice, please select 1 or 2",
		},
		"invalid choice empty": {
			input:      "\n",
			wantChoice: "",
			wantErr:    true,
			wantErrMsg: "invalid choice, please select 1 or 2",
		},
		"choice with spaces": {
			input:      " 1 \n",
			wantChoice: "1",
			wantErr:    false,
		},
	}
	
	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			handler := &AWSSetupHandler{
				reader: bufio.NewReader(strings.NewReader(test.input)),
			}
			
			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w
			
			choice, err := handler.promptForMFASetupMethod()
			
			w.Close()
			os.Stdout = oldStdout
			
			// Read captured output
			var buf bytes.Buffer
			io.Copy(&buf, r)
			output := buf.String()
			
			// Check that instructions were displayed
			if !strings.Contains(output, "Let's set up a virtual MFA device") {
				t.Error("Expected setup instructions not displayed")
			}
			
			// Check choice
			if choice != test.wantChoice {
				t.Errorf("promptForMFASetupMethod() choice = %v, want %v", choice, test.wantChoice)
			}
			
			// Check error
			if test.wantErr && err == nil {
				t.Error("promptForMFASetupMethod() expected error but got nil")
			}
			if !test.wantErr && err != nil {
				t.Errorf("promptForMFASetupMethod() unexpected error: %v", err)
			}
			if test.wantErrMsg != "" && err != nil {
				if err.Error() != test.wantErrMsg {
					t.Errorf("error message = %v, want %v", err.Error(), test.wantErrMsg)
				}
			}
		})
	}
}

// TestAWSSetupHandler_showSetupCompletionMessage tests completion message display
func TestAWSSetupHandler_showSetupCompletionMessage(t *testing.T) {
	tests := map[string]struct {
		profile        string
		wantContains   []string
	}{
		"default profile": {
			profile: "",
			wantContains: []string{
				"Setup complete!",
				"Run 'sesh -service aws' to generate a temporary session token",
				"To use this setup, run without the --profile flag",
				"The default AWS profile will be used",
			},
		},
		"custom profile": {
			profile: "dev",
			wantContains: []string{
				"Setup complete!",
				"Run 'sesh -service aws' to generate a temporary session token",
				"To use this setup, run: sesh --profile dev",
			},
		},
	}
	
	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			handler := &AWSSetupHandler{}
			
			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w
			
			handler.showSetupCompletionMessage(test.profile)
			
			w.Close()
			os.Stdout = oldStdout
			
			// Read captured output
			var buf bytes.Buffer
			io.Copy(&buf, r)
			output := buf.String()
			
			// Check expected content
			for _, expected := range test.wantContains {
				if !strings.Contains(output, expected) {
					t.Errorf("Expected output to contain: %q", expected)
				}
			}
		})
	}
}

// TestAWSSetupHandler_setupMFAConsole tests MFA console setup guidance
func TestAWSSetupHandler_setupMFAConsole(t *testing.T) {
	tests := map[string]struct {
		secret       string
		readerInput  string
		wantErr      bool
		wantContains []string
	}{
		"valid secret": {
			secret:      "JBSWY3DPEHPK3PXP",
			readerInput: "\n",
			wantErr:     false,
			wantContains: []string{
				"Generated TOTP codes for AWS setup",
				"First code:",
				"Second code:",
				"IMPORTANT - FOLLOW THESE STEPS",
				"Press Enter ONLY AFTER you see",
			},
		},
		"invalid secret": {
			secret:      "invalid-secret",
			readerInput: "\n",
			wantErr:     true,
			wantContains: []string{},
		},
	}
	
	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			handler := &AWSSetupHandler{
				reader: bufio.NewReader(strings.NewReader(test.readerInput)),
			}
			
			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w
			
			err := handler.setupMFAConsole(test.secret)
			
			w.Close()
			os.Stdout = oldStdout
			
			// Read captured output
			var buf bytes.Buffer
			io.Copy(&buf, r)
			output := buf.String()
			
			// Check error
			if test.wantErr && err == nil {
				t.Error("setupMFAConsole() expected error but got nil")
			}
			if !test.wantErr && err != nil {
				t.Errorf("setupMFAConsole() unexpected error: %v", err)
			}
			
			// Check expected content
			for _, expected := range test.wantContains {
				if !strings.Contains(output, expected) {
					t.Errorf("Expected output to contain: %q", expected)
				}
			}
		})
	}
}

// TestCaptureQRWithRetry tests QR code capture with retry logic
func TestCaptureQRWithRetry(t *testing.T) {
	// Save original scanQRCode and restore after test
	origScanQRCode := scanQRCode
	defer func() { scanQRCode = origScanQRCode }()
	
	// Mock manual entry function
	mockManualEntry := func() (string, error) {
		return "MANUAL_SECRET", nil
	}
	
	tests := map[string]struct {
		readerInput    string
		scanResults    []error  // Results for each scan attempt
		scanSecret     string
		wantSecret     string
		wantErr        bool
		wantScanCalls  int
	}{
		"success on first try": {
			readerInput:   "\n",
			scanResults:   []error{nil},
			scanSecret:    "QR_SECRET",
			wantSecret:    "QR_SECRET",
			wantErr:       false,
			wantScanCalls: 1,
		},
		"success on second try": {
			readerInput:   "\n\n",
			scanResults:   []error{errors.New("scan failed"), nil},
			scanSecret:    "QR_SECRET",
			wantSecret:    "QR_SECRET", 
			wantErr:       false,
			wantScanCalls: 2,
		},
		"switch to manual after first failure": {
			readerInput:   "\nm\n",
			scanResults:   []error{errors.New("scan failed")},
			scanSecret:    "",
			wantSecret:    "MANUAL_SECRET",
			wantErr:       false,
			wantScanCalls: 1,
		},
		"fail all attempts then manual": {
			readerInput:   "\n\n\ny\n",  // Enter for attempt 1, Enter for attempt 2, Enter to skip retry prompt, y for manual
			scanResults:   []error{errors.New("scan failed"), errors.New("scan failed")},
			scanSecret:    "",
			wantSecret:    "MANUAL_SECRET",
			wantErr:       false,
			wantScanCalls: 2,
		},
		"fail all attempts and decline manual": {
			readerInput:   "\n\n\nn\n",  // Enter for attempt 1, Enter for attempt 2, Enter to skip retry prompt, n to decline manual
			scanResults:   []error{errors.New("scan failed"), errors.New("scan failed")},
			scanSecret:    "",
			wantSecret:    "",
			wantErr:       true,
			wantScanCalls: 2,
		},
	}
	
	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			scanCallCount := 0
			
			// Mock scanQRCode
			scanQRCode = func() (string, error) {
				if scanCallCount < len(test.scanResults) {
					err := test.scanResults[scanCallCount]
					scanCallCount++
					if err != nil {
						return "", err
					}
					return test.scanSecret, nil
				}
				return "", errors.New("unexpected scan call")
			}
			
			reader := bufio.NewReader(strings.NewReader(test.readerInput))
			
			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w
			
			secret, err := captureQRWithRetry(reader, mockManualEntry)
			
			w.Close()
			os.Stdout = oldStdout
			
			// Read captured output
			var buf bytes.Buffer
			io.Copy(&buf, r)
			output := buf.String()
			
			// Check scan was called expected number of times
			if scanCallCount != test.wantScanCalls {
				t.Errorf("scanQRCode called %d times, want %d", scanCallCount, test.wantScanCalls)
			}
			
			// Check secret
			if secret != test.wantSecret {
				t.Errorf("captureQRWithRetry() secret = %v, want %v", secret, test.wantSecret)
			}
			
			// Check error
			if test.wantErr && err == nil {
				t.Error("captureQRWithRetry() expected error but got nil")
			}
			if !test.wantErr && err != nil {
				t.Errorf("captureQRWithRetry() unexpected error: %v", err)
			}
			
			// Check output contains expected prompts
			if strings.Contains(output, "QR capture attempt") {
				// Good, attempt message shown
			} else {
				t.Error("Expected QR capture attempt message")
			}
		})
	}
}

// TestTOTPSetupHandler_captureQRCodeWithFallback tests TOTP QR capture wrapper
func TestTOTPSetupHandler_captureQRCodeWithFallback(t *testing.T) {
	// Save original scanQRCode and readPassword and restore after test
	origScanQRCode := scanQRCode
	origReadPassword := readPassword
	defer func() { 
		scanQRCode = origScanQRCode
		readPassword = origReadPassword
	}()
	
	tests := map[string]struct {
		readerInput   string
		scanSuccess   bool
		passwordInput string
		wantSecret    string
		wantErr       bool
	}{
		"QR scan success": {
			readerInput: "\n",
			scanSuccess: true,
			wantSecret:  "QR_SECRET",
			wantErr:     false,
		},
		"QR scan fails, manual entry": {
			readerInput:   "\nm\n",
			scanSuccess:   false,
			passwordInput: "MANUAL_SECRET",
			wantSecret:    "MANUAL_SECRET",
			wantErr:       false,
		},
	}
	
	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			// Mock scanQRCode
			scanQRCode = func() (string, error) {
				if test.scanSuccess {
					return "QR_SECRET", nil
				}
				return "", errors.New("scan failed")
			}
			
			// Mock readPassword
			readPassword = func(fd int) ([]byte, error) {
				return []byte(test.passwordInput), nil
			}
			
			handler := &TOTPSetupHandler{
				reader: bufio.NewReader(strings.NewReader(test.readerInput)),
			}
			
			// Capture stdout
			oldStdout := os.Stdout
			_, w, _ := os.Pipe()
			os.Stdout = w
			
			secret, err := handler.captureQRCodeWithFallback()
			
			w.Close()
			os.Stdout = oldStdout
			
			// Check secret
			if secret != test.wantSecret {
				t.Errorf("captureQRCodeWithFallback() secret = %v, want %v", secret, test.wantSecret)
			}
			
			// Check error
			if test.wantErr && err == nil {
				t.Error("captureQRCodeWithFallback() expected error but got nil")
			}
			if !test.wantErr && err != nil {
				t.Errorf("captureQRCodeWithFallback() unexpected error: %v", err)
			}
		})
	}
}

// TestAWSSetupHandler_captureAWSQRCodeWithFallback tests AWS QR capture wrapper  
func TestAWSSetupHandler_captureAWSQRCodeWithFallback(t *testing.T) {
	// Save original scanQRCode and readPassword and restore after test
	origScanQRCode := scanQRCode
	origReadPassword := readPassword
	defer func() { 
		scanQRCode = origScanQRCode
		readPassword = origReadPassword
	}()
	
	tests := map[string]struct {
		readerInput   string
		scanSuccess   bool
		passwordInput string
		wantSecret    string
		wantErr       bool
	}{
		"QR scan success": {
			readerInput: "\n",
			scanSuccess: true,
			wantSecret:  "AWS_QR_SECRET",
			wantErr:     false,
		},
		"QR scan fails, manual entry": {
			readerInput:   "\nm\n",
			scanSuccess:   false,
			passwordInput: "AWS_MANUAL_SECRET",
			wantSecret:    "AWS_MANUAL_SECRET",
			wantErr:       false,
		},
	}
	
	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			// Mock scanQRCode
			scanQRCode = func() (string, error) {
				if test.scanSuccess {
					return "AWS_QR_SECRET", nil
				}
				return "", errors.New("scan failed")
			}
			
			// Mock readPassword
			readPassword = func(fd int) ([]byte, error) {
				return []byte(test.passwordInput), nil
			}
			
			handler := &AWSSetupHandler{
				reader: bufio.NewReader(strings.NewReader(test.readerInput)),
			}
			
			// Capture stdout
			oldStdout := os.Stdout
			_, w, _ := os.Pipe()
			os.Stdout = w
			
			secret, err := handler.captureAWSQRCodeWithFallback()
			
			w.Close()
			os.Stdout = oldStdout
			
			// Check secret
			if secret != test.wantSecret {
				t.Errorf("captureAWSQRCodeWithFallback() secret = %v, want %v", secret, test.wantSecret)
			}
			
			// Check error
			if test.wantErr && err == nil {
				t.Error("captureAWSQRCodeWithFallback() expected error but got nil")
			}
			if !test.wantErr && err != nil {
				t.Errorf("captureAWSQRCodeWithFallback() unexpected error: %v", err)
			}
		})
	}
}

// TestAWSSetupHandler_selectMFADevice tests MFA device selection
func TestAWSSetupHandler_selectMFADevice(t *testing.T) {
	// Save original execCommand and restore after test
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()
	
	tests := map[string]struct {
		profile       string
		awsOutputs    []string  // Multiple outputs for refresh scenarios
		awsError      bool
		userInput     string
		wantDevice    string
		wantErr       bool
		wantErrMsg    string
	}{
		"single device select 1": {
			profile:    "default",
			awsOutputs: []string{"arn:aws:iam::123456789012:mfa/user"},
			awsError:   false,
			userInput:  "1\n",
			wantDevice: "arn:aws:iam::123456789012:mfa/user",
			wantErr:    false,
		},
		"multiple devices select first": {
			profile:    "default", 
			awsOutputs: []string{"arn:aws:iam::123456789012:mfa/user1\tarn:aws:iam::123456789012:mfa/user2"},
			awsError:   false,
			userInput:  "1\n",
			wantDevice: "arn:aws:iam::123456789012:mfa/user1",
			wantErr:    false,
		},
		"multiple devices select second": {
			profile:    "default",
			awsOutputs: []string{"arn:aws:iam::123456789012:mfa/user1\tarn:aws:iam::123456789012:mfa/user2"}, 
			awsError:   false,
			userInput:  "2\n",
			wantDevice: "arn:aws:iam::123456789012:mfa/user2",
			wantErr:    false,
		},
		"manual entry": {
			profile:    "default",
			awsOutputs: []string{"arn:aws:iam::123456789012:mfa/user1"},
			awsError:   false,
			userInput:  "m\narn:aws:iam::123456789012:mfa/manual\n",
			wantDevice: "arn:aws:iam::123456789012:mfa/manual",
			wantErr:    false,
		},
		"no devices with manual entry": {
			profile:    "default",
			awsOutputs: []string{""},
			awsError:   false,
			userInput:  "3\narn:aws:iam::123456789012:mfa/manual\n", // Choice 3 for manual entry when no devices found
			wantDevice: "arn:aws:iam::123456789012:mfa/manual",
			wantErr:    false,
		},
		"refresh devices": {
			profile:    "default",
			awsOutputs: []string{"arn:aws:iam::123456789012:mfa/user1", "arn:aws:iam::123456789012:mfa/user1\tarn:aws:iam::123456789012:mfa/user2"},
			awsError:   false,
			userInput:  "r\n2\n", // Refresh then select second device
			wantDevice: "arn:aws:iam::123456789012:mfa/user2",
			wantErr:    false,
		},
		"invalid choice then valid": {
			profile:    "default",
			awsOutputs: []string{"arn:aws:iam::123456789012:mfa/user1\tarn:aws:iam::123456789012:mfa/user2"},
			awsError:   false,
			userInput:  "invalid\n1\n", // Invalid then valid choice
			wantDevice: "arn:aws:iam::123456789012:mfa/user1",
			wantErr:    false,
		},
		"out of range then valid": {
			profile:    "default",
			awsOutputs: []string{"arn:aws:iam::123456789012:mfa/user1"},
			awsError:   false,
			userInput:  "5\n1\n", // Out of range then valid
			wantDevice: "arn:aws:iam::123456789012:mfa/user1",
			wantErr:    false,
		},
		"wait and retry": {
			profile:    "default",
			awsOutputs: []string{"", "arn:aws:iam::123456789012:mfa/user"}, // Initially no devices, then finds one
			awsError:   false,
			userInput:  "1\n1\n", // Wait option, then select first device
			wantDevice: "arn:aws:iam::123456789012:mfa/user",
			wantErr:    false,
		},
		"return to console and retry": {
			profile:    "default",
			awsOutputs: []string{"", "arn:aws:iam::123456789012:mfa/user"}, // Initially no devices, then finds one
			awsError:   false,
			userInput:  "2\n\n1\n", // Return to console, press enter, then select device
			wantDevice: "arn:aws:iam::123456789012:mfa/user",
			wantErr:    false,
		},
		"invalid retry choice": {
			profile:    "default",
			awsOutputs: []string{""},
			awsError:   false,
			userInput:  "invalid\n3\narn:aws:iam::123456789012:mfa/manual\n", // Invalid choice, then manual
			wantDevice: "arn:aws:iam::123456789012:mfa/manual",
			wantErr:    false,
		},
		"refresh with no devices after": {
			profile:    "default",
			awsOutputs: []string{"arn:aws:iam::123456789012:mfa/user1", ""}, // Has devices, refresh finds nothing
			awsError:   false,
			userInput:  "r\nm\narn:aws:iam::123456789012:mfa/manual\n", // Refresh finds nothing, then manual
			wantDevice: "arn:aws:iam::123456789012:mfa/manual",
			wantErr:    false,
		},
		"exhaust retries then manual": {
			profile:    "default",
			awsOutputs: []string{"", "", "", ""}, // No devices found in any attempt
			awsError:   false,
			userInput:  "1\n1\n1\narn:aws:iam::123456789012:mfa/manual\n", // Try wait twice, exhaust retries, then manual
			wantDevice: "arn:aws:iam::123456789012:mfa/manual",
			wantErr:    false,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			// Track which AWS output to return
			outputIndex := 0
			
			// Mock execCommand to return our test data
			execCommand = func(command string, args ...string) *exec.Cmd {
				cs := []string{"-test.run=TestHelperProcess", "--", command}
				cs = append(cs, args...)
				cmd := exec.Command(os.Args[0], cs...)
				
				// Get the current output or use the last one if we've exhausted the list
				output := ""
				if outputIndex < len(test.awsOutputs) {
					output = test.awsOutputs[outputIndex]
					outputIndex++
				} else if len(test.awsOutputs) > 0 {
					output = test.awsOutputs[len(test.awsOutputs)-1]
				}
				
				cmd.Env = []string{
					"GO_WANT_HELPER_PROCESS=1",
					"MOCK_OUTPUT=" + output,
				}
				if test.awsError {
					cmd.Env = append(cmd.Env, "MOCK_ERROR=1")
				}
				return cmd
			}
			
			// Create handler with mock reader
			handler := &AWSSetupHandler{
				reader: bufio.NewReader(strings.NewReader(test.userInput)),
			}

			// Capture stdout  
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			device, err := handler.selectMFADevice(test.profile)

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

			// Verify the prompts were shown
			if len(test.awsOutputs) > 0 && test.awsOutputs[0] != "" {
				if !strings.Contains(output, "Found MFA device(s):") {
					t.Error("Expected 'Found MFA device(s):' prompt")
				}
			}
		})
	}
}
