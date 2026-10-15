package setup

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/qrcode"
	"github.com/bashhack/sesh/internal/testutil"
)

func TestRunCommandDefault(t *testing.T) {
	// Exercise the real runCommand (calls an actual command)
	out, err := runCommand("echo", "hello")
	if err != nil {
		t.Fatalf("runCommand: %v", err)
	}
	if !strings.Contains(string(out), "hello") {
		t.Fatalf("expected 'hello' in output, got %q", string(out))
	}
}

// MockCommand creates a mock exec.Cmd object
type MockCommand struct {
	ErrorValue  error
	CommandName string
	OutputData  []byte
	CommandArgs []string
	RunCalled   bool
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
	DefaultError  error
	Commands      map[string]*MockCommand
	CommandCalls  []string
	DefaultOutput []byte
	mu            sync.Mutex
}

// Command returns a mock command based on the command name
func (r *SimpleRunner) Command(command string, args ...string) *exec.Cmd {
	r.mu.Lock()
	r.CommandCalls = append(r.CommandCalls, command)
	r.mu.Unlock()

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

// Tests for TOTP Setup Handler prompt methods

func TestAWSSetupHandler(t *testing.T) {
	// This is a basic test to ensure the handler implements the interface
	handler := NewAWSSetupHandler(nil)

	if handler.ServiceName() != "aws" {
		t.Errorf("Expected service name 'aws', got %s", handler.ServiceName())
	}
}

func TestHelperProcess(*testing.T) {
	testutil.TestHelperProcess()
}

func TestAWSSetupHandler_runAWSCommand(t *testing.T) {
	handler := &AWSSetupHandler{}

	tests := map[string]struct {
		profile  string
		args     []string
		wantName string
		wantArgs []string
	}{
		"command without profile": {
			profile:  "",
			args:     []string{"sts", "get-caller-identity"},
			wantName: "aws",
			wantArgs: []string{"sts", "get-caller-identity"},
		},
		"command with profile": {
			profile:  "dev",
			args:     []string{"sts", "get-caller-identity"},
			wantName: "aws",
			wantArgs: []string{"sts", "--profile", "dev", "get-caller-identity"},
		},
		"complex command with profile": {
			profile:  "prod",
			args:     []string{"iam", "list-mfa-devices", "--query", "MFADevices[].SerialNumber", "--output", "text"},
			wantName: "aws",
			wantArgs: []string{"iam", "--profile", "prod", "list-mfa-devices", "--query", "MFADevices[].SerialNumber", "--output", "text"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var gotName string
			var gotArgs []string

			origRunCommand := runCommand
			defer func() { runCommand = origRunCommand }()
			runCommand = func(name string, args ...string) ([]byte, error) {
				gotName = name
				gotArgs = args
				return []byte("mock-output"), nil
			}

			if _, err := handler.runAWSCommand(tc.profile, tc.args...); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if gotName != tc.wantName {
				t.Errorf("command = %v, want %v", gotName, tc.wantName)
			}
			if len(gotArgs) != len(tc.wantArgs) {
				t.Errorf("args length = %d, want %d\ngot:  %v\nwant: %v", len(gotArgs), len(tc.wantArgs), gotArgs, tc.wantArgs)
			}
			for i, want := range tc.wantArgs {
				if i < len(gotArgs) && gotArgs[i] != want {
					t.Errorf("args[%d] = %v, want %v", i, gotArgs[i], want)
				}
			}
		})
	}
}

func TestAWSSetupHandler_promptForMFAARN(t *testing.T) {
	tests := map[string]struct {
		userInput string
		wantARN   string
		wantErr   bool
	}{
		"valid ARN on first try": {
			userInput: "arn:aws:iam::123456789012:mfa/user\n",
			wantARN:   "arn:aws:iam::123456789012:mfa/user",
			wantErr:   false,
		},
		"empty input then valid": {
			userInput: "\narn:aws:iam::123456789012:mfa/user\n",
			wantARN:   "arn:aws:iam::123456789012:mfa/user",
			wantErr:   false,
		},
		"invalid format then valid": {
			userInput: "not-an-arn\narn:aws:iam::123456789012:mfa/user\n",
			wantARN:   "arn:aws:iam::123456789012:mfa/user",
			wantErr:   false,
		},
		"wrong service then valid": {
			userInput: "arn:aws:s3::123456789012:bucket/mybucket\narn:aws:iam::123456789012:mfa/user\n",
			wantARN:   "arn:aws:iam::123456789012:mfa/user",
			wantErr:   false,
		},
		"wrong resource type then valid": {
			userInput: "arn:aws:iam::123456789012:user/myuser\narn:aws:iam::123456789012:mfa/user\n",
			wantARN:   "arn:aws:iam::123456789012:mfa/user",
			wantErr:   false,
		},
		"multiple invalid then valid": {
			userInput: "\nnot-an-arn\narn:aws:s3::123456789012:bucket/mybucket\narn:aws:iam::123456789012:mfa/user\n",
			wantARN:   "arn:aws:iam::123456789012:mfa/user",
			wantErr:   false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Create handler with mock reader
			handler := &AWSSetupHandler{
				reader: bufio.NewReader(strings.NewReader(tc.userInput)),
			}

			var arn string
			var err error
			output := testutil.CaptureStdout(func() {
				arn, err = handler.promptForMFAARN()
			})

			// Check ARN
			if arn != tc.wantARN {
				t.Errorf("promptForMFAARN() arn = %v, want %v", arn, tc.wantARN)
			}

			// Check error
			if tc.wantErr && err == nil {
				t.Error("promptForMFAARN() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("promptForMFAARN() unexpected error: %v", err)
			}

			// Verify that appropriate error messages were shown
			if strings.HasPrefix(tc.userInput, "\n") {
				// Empty input was provided as first line
				if !strings.Contains(output, "MFA ARN cannot be empty") {
					t.Error("Expected empty ARN error message")
				}
			}
			if strings.Contains(tc.userInput, "not-an-arn") || strings.Contains(tc.userInput, ":s3:") || strings.Contains(tc.userInput, ":user/") {
				// Invalid format was provided
				if !strings.Contains(output, "Invalid ARN format") {
					t.Error("Expected invalid ARN format error message")
				}
			}
		})
	}
}

// TestAWSSetupHandler_verifyAWSCredentials tests AWS credential verification
func TestAWSSetupHandler_verifyAWSCredentials(t *testing.T) {
	// Save original runCommand and restore after test
	origRunCommand := runCommand
	defer func() { runCommand = origRunCommand }()

	tests := map[string]struct {
		profile       string
		commandOutput string
		wantUserArn   string
		wantErrMsg    string
		commandError  bool
		wantErr       bool
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

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Mock runCommand
			runCommand = func(name string, args ...string) ([]byte, error) {
				if tc.commandError {
					return nil, fmt.Errorf("mock aws error")
				}
				return []byte(tc.commandOutput), nil
			}

			handler := &AWSSetupHandler{
				reader: bufio.NewReader(strings.NewReader("")),
			}

			userArn, err := handler.verifyAWSCredentials(tc.profile)

			// Check user ARN
			if userArn != tc.wantUserArn {
				t.Errorf("verifyAWSCredentials() userArn = %v, want %v", userArn, tc.wantUserArn)
			}

			// Check error
			if tc.wantErr && err == nil {
				t.Error("verifyAWSCredentials() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("verifyAWSCredentials() unexpected error: %v", err)
			}
			if tc.wantErrMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tc.wantErrMsg) {
					t.Errorf("error message = %v, want to contain %v", err.Error(), tc.wantErrMsg)
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
		readError   error
		secretInput string
		wantSecret  string
		wantErrMsg  string
		wantErr     bool
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

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Mock readPassword
			readPassword = func(fd int) ([]byte, error) {
				if tc.readError != nil {
					return nil, tc.readError
				}
				return []byte(tc.secretInput), nil
			}

			handler := &AWSSetupHandler{
				reader: bufio.NewReader(strings.NewReader("")),
			}

			var secret string
			var err error
			output := testutil.CaptureStdout(func() {
				secret, err = handler.captureAWSManualEntry()
			})

			// Check that instructions were displayed
			if !strings.Contains(output, "DO NOT COMPLETE THE AWS SETUP YET") {
				t.Error("Expected setup instructions not displayed")
			}

			// Check secret
			if secret != tc.wantSecret {
				t.Errorf("captureAWSManualEntry() secret = %v, want %v", secret, tc.wantSecret)
			}

			// Check error
			if tc.wantErr && err == nil {
				t.Error("captureAWSManualEntry() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("captureAWSManualEntry() unexpected error: %v", err)
			}
			if tc.wantErrMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tc.wantErrMsg) {
					t.Errorf("error message = %v, want to contain %v", err.Error(), tc.wantErrMsg)
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
		readError   error
		secretInput string
		wantSecret  string
		wantErrMsg  string
		wantErr     bool
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

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Mock readPassword
			readPassword = func(fd int) ([]byte, error) {
				if tc.readError != nil {
					return nil, tc.readError
				}
				return []byte(tc.secretInput), nil
			}

			handler := &AWSSetupHandler{
				reader: bufio.NewReader(strings.NewReader("")),
			}

			var secret string
			var err error
			output := testutil.CaptureStdout(func() {
				secret, err = handler.captureMFASecret("1") // Choice 1 for manual entry
			})

			// Check that instructions were displayed
			if !strings.Contains(output, "DO NOT COMPLETE THE AWS SETUP YET") {
				t.Error("Expected setup instructions not displayed")
			}

			// Check secret
			if secret != tc.wantSecret {
				t.Errorf("captureMFASecret() secret = %v, want %v", secret, tc.wantSecret)
			}

			// Check error
			if tc.wantErr && err == nil {
				t.Error("captureMFASecret() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("captureMFASecret() unexpected error: %v", err)
			}
			if tc.wantErrMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tc.wantErrMsg) {
					t.Errorf("error message = %v, want to contain %v", err.Error(), tc.wantErrMsg)
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
		wantErrMsg string
		wantErr    bool
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

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			handler := &AWSSetupHandler{
				reader: bufio.NewReader(strings.NewReader(tc.input)),
			}

			var choice string
			var err error
			output := testutil.CaptureStdout(func() {
				choice, err = handler.promptForMFASetupMethod()
			})

			// Check that instructions were displayed
			if !strings.Contains(output, "Let's set up a virtual MFA device") {
				t.Error("Expected setup instructions not displayed")
			}

			// Check choice
			if choice != tc.wantChoice {
				t.Errorf("promptForMFASetupMethod() choice = %v, want %v", choice, tc.wantChoice)
			}

			// Check error
			if tc.wantErr && err == nil {
				t.Error("promptForMFASetupMethod() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("promptForMFASetupMethod() unexpected error: %v", err)
			}
			if tc.wantErrMsg != "" && err != nil {
				if err.Error() != tc.wantErrMsg {
					t.Errorf("error message = %v, want %v", err.Error(), tc.wantErrMsg)
				}
			}
		})
	}
}

// TestAWSSetupHandler_showSetupCompletionMessage tests completion message display
func TestAWSSetupHandler_showSetupCompletionMessage(t *testing.T) {
	tests := map[string]struct {
		profile      string
		wantContains []string
	}{
		"default profile": {
			profile: "",
			wantContains: []string{
				"Setup complete!",
				"Run 'sesh aws' to generate a temporary session token",
				"To use this setup, run without the --profile flag",
				"The default AWS profile will be used",
			},
		},
		"custom profile": {
			profile: "dev",
			wantContains: []string{
				"Setup complete!",
				"Run 'sesh aws' to generate a temporary session token",
				"To use this setup, run: sesh aws --profile dev",
			},
		},
		"profile that needs quoting": {
			profile: "my prod",
			wantContains: []string{
				"To use this setup, run: sesh aws --profile 'my prod'",
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			handler := &AWSSetupHandler{}

			output := testutil.CaptureStdout(func() {
				handler.showSetupCompletionMessage(tc.profile)
			})

			// Check expected content
			for _, expected := range tc.wantContains {
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
		wantContains []string
		wantErr      bool
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
			secret:       "invalid-secret",
			readerInput:  "\n",
			wantErr:      true,
			wantContains: []string{},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			handler := &AWSSetupHandler{
				reader: bufio.NewReader(strings.NewReader(tc.readerInput)),
			}

			var err error
			output := testutil.CaptureStdout(func() {
				err = handler.setupMFAConsole(tc.secret)
			})

			// Check error
			if tc.wantErr && err == nil {
				t.Error("setupMFAConsole() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("setupMFAConsole() unexpected error: %v", err)
			}

			// Check expected content
			for _, expected := range tc.wantContains {
				if !strings.Contains(output, expected) {
					t.Errorf("Expected output to contain: %q", expected)
				}
			}
		})
	}
}

// TestCaptureQRWithRetry tests QR code capture with retry logic
func TestCaptureQRWithRetry(t *testing.T) {
	// Save originals and restore after test
	origScanQRCodeFull := scanQRCodeFull
	defer func() {
		scanQRCodeFull = origScanQRCodeFull
	}()

	// Mock manual entry function
	mockManualEntry := func() (string, error) {
		return "MANUAL_SECRET", nil
	}

	tests := map[string]struct {
		readerInput   string
		scanSecret    string
		wantSecret    string
		scanResults   []error // Results for each scan attempt
		wantScanCalls int
		wantErr       bool
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
			readerInput:   "\n\n\n",
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
			readerInput:   "\n\n\ny\n", // Enter for attempt 1, Enter for attempt 2, Enter to skip retry prompt, y for manual
			scanResults:   []error{errors.New("scan failed"), errors.New("scan failed")},
			scanSecret:    "",
			wantSecret:    "MANUAL_SECRET",
			wantErr:       false,
			wantScanCalls: 2,
		},
		"fail all attempts and decline manual": {
			readerInput:   "\n\n\nn\n", // Enter for attempt 1, Enter for attempt 2, Enter to skip retry prompt, n to decline manual
			scanResults:   []error{errors.New("scan failed"), errors.New("scan failed")},
			scanSecret:    "",
			wantSecret:    "",
			wantErr:       true,
			wantScanCalls: 2,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			scanCallCount := 0

			// Mock scanQRCodeFull (used by captureQRWithRetryFull)
			scanQRCodeFull = func() (qrcode.TOTPInfo, error) {
				if scanCallCount < len(tc.scanResults) {
					err := tc.scanResults[scanCallCount]
					scanCallCount++
					if err != nil {
						return qrcode.TOTPInfo{}, err
					}
					return qrcode.TOTPInfo{Secret: tc.scanSecret}, nil
				}
				return qrcode.TOTPInfo{}, errors.New("unexpected scan call")
			}

			reader := bufio.NewReader(strings.NewReader(tc.readerInput))

			var secret string
			var err error
			output := testutil.CaptureStdout(func() {
				secret, err = captureQRWithRetry(reader, mockManualEntry)
			})

			// Check scan was called expected number of times
			if scanCallCount != tc.wantScanCalls {
				t.Errorf("scanQRCodeFull called %d times, want %d", scanCallCount, tc.wantScanCalls)
			}

			// Check secret
			if secret != tc.wantSecret {
				t.Errorf("captureQRWithRetry() secret = %v, want %v", secret, tc.wantSecret)
			}

			// Check error
			if tc.wantErr && err == nil {
				t.Error("captureQRWithRetry() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
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

// TestAWSSetupHandler_captureAWSQRCodeWithFallback tests AWS QR capture wrapper
func TestAWSSetupHandler_captureAWSQRCodeWithFallback(t *testing.T) {
	// Save originals and restore after test
	origScanQRCodeFull := scanQRCodeFull
	origReadPassword := readPassword
	defer func() {
		scanQRCodeFull = origScanQRCodeFull
		readPassword = origReadPassword
	}()

	tests := map[string]struct {
		readerInput   string
		passwordInput string
		wantSecret    string
		scanSuccess   bool
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

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Mock scanQRCodeFull
			scanQRCodeFull = func() (qrcode.TOTPInfo, error) {
				if tc.scanSuccess {
					return qrcode.TOTPInfo{Secret: "AWS_QR_SECRET"}, nil
				}
				return qrcode.TOTPInfo{}, errors.New("scan failed")
			}

			// Mock readPassword
			readPassword = func(fd int) ([]byte, error) {
				return []byte(tc.passwordInput), nil
			}

			handler := &AWSSetupHandler{
				reader: bufio.NewReader(strings.NewReader(tc.readerInput)),
			}

			var secret string
			var err error
			testutil.CaptureStdout(func() {
				secret, err = handler.captureAWSQRCodeWithFallback()
			})

			// Check secret
			if secret != tc.wantSecret {
				t.Errorf("captureAWSQRCodeWithFallback() secret = %v, want %v", secret, tc.wantSecret)
			}

			// Check error
			if tc.wantErr && err == nil {
				t.Error("captureAWSQRCodeWithFallback() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("captureAWSQRCodeWithFallback() unexpected error: %v", err)
			}
		})
	}
}

// TestAWSSetupHandler_selectMFADevice tests MFA device selection
func TestAWSSetupHandler_selectMFADevice(t *testing.T) {
	// Save original runCommand and restore after test
	origRunCommand := runCommand
	defer func() { runCommand = origRunCommand }()

	// Save original timeSleep and restore after test
	origTimeSleep := timeSleep
	defer func() { timeSleep = origTimeSleep }()

	// Mock timeSleep to not actually sleep in tests
	timeSleep = func(d time.Duration) {
		// Don't actually sleep in tests
	}

	tests := map[string]struct {
		profile    string
		userInput  string
		wantDevice string
		wantErrMsg string
		awsOutputs []string // Multiple outputs for refresh scenarios
		awsError   bool
		wantErr    bool
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
			userInput:  "r\n3\narn:aws:iam::123456789012:mfa/manual\n", // Refresh finds nothing, then shows retry prompt, choose manual
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

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Track which AWS output to return
			outputIndex := 0

			// Mock runCommand to return our test data
			runCommand = func(name string, args ...string) ([]byte, error) {
				output := ""
				if outputIndex < len(tc.awsOutputs) {
					output = tc.awsOutputs[outputIndex]
					outputIndex++
				} else if len(tc.awsOutputs) > 0 {
					output = tc.awsOutputs[len(tc.awsOutputs)-1]
				}
				if tc.awsError {
					return nil, fmt.Errorf("mock aws error")
				}
				return []byte(output), nil
			}

			// Create handler with mock reader
			handler := &AWSSetupHandler{
				reader: bufio.NewReader(strings.NewReader(tc.userInput)),
			}

			var device string
			var err error
			output := testutil.CaptureStdout(func() {
				device, err = handler.selectMFADevice(tc.profile)
			})

			// Check device
			if device != tc.wantDevice {
				t.Errorf("selectMFADevice() device = %v, want %v", device, tc.wantDevice)
			}

			// Check error
			if tc.wantErr && err == nil {
				t.Error("selectMFADevice() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("selectMFADevice() unexpected error: %v", err)
			}
			if tc.wantErrMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tc.wantErrMsg) {
					t.Errorf("error message = %v, want to contain %v", err.Error(), tc.wantErrMsg)
				}
			}

			// Verify the prompts were shown
			if len(tc.awsOutputs) > 0 && tc.awsOutputs[0] != "" {
				if !strings.Contains(output, "Found MFA device(s):") {
					t.Error("Expected 'Found MFA device(s):' prompt")
				}
			}
		})
	}
}
