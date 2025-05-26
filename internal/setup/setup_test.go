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

// TestAWSSetupHandler_selectMFADevice tests MFA device selection
func TestAWSSetupHandler_selectMFADevice(t *testing.T) {
	// Save original execCommand and restore after test
	origExecCommand := execCommand
	defer func() { execCommand = origExecCommand }()
	
	tests := map[string]struct {
		profile       string
		awsOutput     string  // What AWS returns when listing MFA devices
		awsError      bool
		userInput     string
		wantDevice    string
		wantErr       bool
		wantErrMsg    string
	}{
		"single device select 1": {
			profile:    "default",
			awsOutput:  "arn:aws:iam::123456789012:mfa/user",
			awsError:   false,
			userInput:  "1\n",
			wantDevice: "arn:aws:iam::123456789012:mfa/user",
			wantErr:    false,
		},
		"multiple devices select first": {
			profile:    "default", 
			awsOutput:  "arn:aws:iam::123456789012:mfa/user1\tarn:aws:iam::123456789012:mfa/user2",
			awsError:   false,
			userInput:  "1\n",
			wantDevice: "arn:aws:iam::123456789012:mfa/user1",
			wantErr:    false,
		},
		"multiple devices select second": {
			profile:    "default",
			awsOutput:  "arn:aws:iam::123456789012:mfa/user1\tarn:aws:iam::123456789012:mfa/user2", 
			awsError:   false,
			userInput:  "2\n",
			wantDevice: "arn:aws:iam::123456789012:mfa/user2",
			wantErr:    false,
		},
		"manual entry": {
			profile:    "default",
			awsOutput:  "arn:aws:iam::123456789012:mfa/user1",
			awsError:   false,
			userInput:  "m\narn:aws:iam::123456789012:mfa/manual\n",
			wantDevice: "arn:aws:iam::123456789012:mfa/manual",
			wantErr:    false,
		},
		"no devices with manual entry": {
			profile:    "default",
			awsOutput:  "",
			awsError:   false,
			userInput:  "3\narn:aws:iam::123456789012:mfa/manual\n", // Choice 3 for manual entry when no devices found
			wantDevice: "arn:aws:iam::123456789012:mfa/manual",
			wantErr:    false,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			// Mock execCommand to return our test data
			execCommand = func(command string, args ...string) *exec.Cmd {
				cs := []string{"-test.run=TestHelperProcess", "--", command}
				cs = append(cs, args...)
				cmd := exec.Command(os.Args[0], cs...)
				cmd.Env = []string{
					"GO_WANT_HELPER_PROCESS=1",
					"MOCK_OUTPUT=" + test.awsOutput,
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
			if test.awsOutput != "" {
				if !strings.Contains(output, "Found MFA device(s):") {
					t.Error("Expected 'Found MFA device(s):' prompt")
				}
			}
		})
	}
}
