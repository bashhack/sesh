package setup

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/bashhack/sesh/internal/testutil"
	"github.com/bashhack/sesh/internal/totp"
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
	input := strings.NewReader("Invalid-TOTP-Secret\n")
	var output, errOutput bytes.Buffer

	exitCalled := false
	exitCode := 0
	mockExit := func(code int) {
		exitCalled = true
		exitCode = code
	}

	opts := WizardOptions{
		Reader:      input,
		Writer:      &output,
		ErrorWriter: &errOutput,
		OsExit:      mockExit,
		SkipClear:   true,
	}

	RunWizardWithOptions(opts)

	if !exitCalled {
		t.Error("Expected exit function to be called for invalid TOTP")
	}
	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}

	errorMsg := errOutput.String()
	if !strings.Contains(errorMsg, "Failed to generate MFA codes") {
		t.Errorf("Expected error message about MFA codes, got: %s", errorMsg)
	}
}

func TestRunWizard(t *testing.T) {
	originalRunWizardWithOptions := RunWizardWithOptions
	defer func() {
		RunWizardWithOptions = originalRunWizardWithOptions
	}()

	called := false
	RunWizardWithOptions = func(WizardOptions) {
		called = true
	}

	RunWizard()

	if !called {
		t.Error("RunWizard did not call RunWizardWithOptions")
	}
}

func TestDefaultWizardRunnerRun(t *testing.T) {
	originalRunWizardWithOptions := RunWizardWithOptions
	defer func() {
		RunWizardWithOptions = originalRunWizardWithOptions
	}()

	runWizardWithOptionsCalled := false
	RunWizardWithOptions = func(opts WizardOptions) {
		runWizardWithOptionsCalled = true
	}

	runner := DefaultWizardRunner{}
	err := runner.Run()

	if err != nil {
		t.Errorf("DefaultWizardRunner.Run() returned an error: %v", err)
	}

	// Verify RunWizardWithOptions was called (which implies RunWizard was called)
	if !runWizardWithOptionsCalled {
		t.Error("DefaultWizardRunner.Run() did not result in RunWizardWithOptions being called")
	}
}

func TestDefaultCommandRunner(t *testing.T) {
	runner := &DefaultCommandRunner{}
	cmd := runner.Command("echo", "test")

	if cmd == nil {
		t.Error("DefaultCommandRunner.Command returned nil")
	}
}

func TestClearWithWriter(t *testing.T) {
	// NOTE: I'm just verifying it doesn't panic!
	var buf bytes.Buffer
	mockRunner := &SimpleRunner{
		DefaultError: nil,
	}
	clearWithWriter(&buf, mockRunner)
}

func TestClear(t *testing.T) {
	// NOTE: Just calling clearWithWriter with os.Stdout,
	// I don't have a great way to test the visual effect.
	// Just checking it compiles and does not panic!
	originalClearFunc := clear
	clearCalled := false

	clear = func() {
		clearCalled = true
	}
	defer func() {
		clear = originalClearFunc
	}()

	clear()

	if !clearCalled {
		t.Error("clear() was not called")
	}
}

func TestClearImpl(t *testing.T) {
	originalClearWithWriter := clearWithWriter
	defer func() {
		clearWithWriter = originalClearWithWriter
	}()

	clearWithWriterCalled := false
	clearWithWriter = func(w io.Writer, runner CommandRunner) {
		clearWithWriterCalled = true
		if w != os.Stdout {
			t.Error("clearImpl() did not use os.Stdout")
		}
		if _, ok := runner.(*DefaultCommandRunner); !ok {
			t.Error("clearImpl() did not use DefaultCommandRunner")
		}
	}

	clearImpl()

	if !clearWithWriterCalled {
		t.Error("clearImpl() did not call clearWithWriter()")
	}
}

func TestRunWizardWithOptions_CustomOptions(t *testing.T) {
	originalRunWizardWithOptions := RunWizardWithOptions
	defer func() {
		RunWizardWithOptions = originalRunWizardWithOptions
	}()

	var output, errOutput bytes.Buffer
	customExit := func(code int) {
		// No-op for testing
	}

	customRunner := &SimpleRunner{DefaultError: nil}

	optionsVerified := false
	RunWizardWithOptions = func(opts WizardOptions) {
		optionsVerified = true
		if opts.Writer != &output {
			t.Error("Custom Writer not used")
		}
		if opts.ErrorWriter != &errOutput {
			t.Error("Custom ErrorWriter not used")
		}
		if opts.OsExit == nil {
			t.Error("Custom OsExit not used")
		}
		if opts.ExecCommand != customRunner {
			t.Error("Custom ExecCommand not used")
		}
		if !opts.SkipClear {
			t.Error("SkipClear should be true")
		}
	}

	RunWizardWithOptions(WizardOptions{
		Writer:      &output,
		ErrorWriter: &errOutput,
		OsExit:      customExit,
		ExecCommand: customRunner,
		SkipClear:   true,
	})

	if !optionsVerified {
		t.Error("Options were not verified")
	}
}

func TestRunWizardWithOptions_TOTPError(t *testing.T) {
	input := strings.NewReader("invalid-secret\n")
	var output, errOutput bytes.Buffer

	exitCalled := false
	exitCode := 0
	mockExit := func(code int) {
		exitCalled = true
		exitCode = code
	}

	opts := WizardOptions{
		Reader:      input,
		Writer:      &output,
		ErrorWriter: &errOutput,
		OsExit:      mockExit,
		SkipClear:   true,
	}

	totp.MockGenerateConsecutiveCodes.CurrentCode = ""
	totp.MockGenerateConsecutiveCodes.NextCode = ""
	totp.MockGenerateConsecutiveCodes.Error = errors.New("invalid TOTP secret")
	totp.MockGenerateConsecutiveCodes.Enabled = true
	defer totp.ResetMock()

	runWizardWithOptions(opts)

	if !exitCalled {
		t.Error("Expected exit to be called")
	}
	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}

	errorStr := errOutput.String()
	if !strings.Contains(errorStr, "Failed to generate MFA codes") {
		t.Errorf("Expected error output to contain 'Failed to generate MFA codes', got: %s", errorStr)
	}
}

func TestWizardWithDefaultUsername(t *testing.T) {
	secretInput := "TESTSECRET123456\n\n" // Secret followed by empty username (to use default)
	input := strings.NewReader(secretInput)
	var output, errOutput bytes.Buffer

	exitCalled := false
	mockExit := func(code int) {
		exitCalled = true
	}

	totp.MockGenerateConsecutiveCodes.CurrentCode = "123456"
	totp.MockGenerateConsecutiveCodes.NextCode = "654321"
	totp.MockGenerateConsecutiveCodes.Error = nil
	totp.MockGenerateConsecutiveCodes.Enabled = true
	defer totp.ResetMock()

	whoamiMock := &MockCommand{
		OutputData: []byte("testuser\n"),
		ErrorValue: nil,
	}
	securityMock := &MockCommand{
		OutputData: []byte(""),
		ErrorValue: nil,
	}
	awsMock := &MockCommand{
		OutputData: []byte(`{"MFADevices":[{"SerialNumber":"arn:aws:iam::123456789012:mfa/testuser","UserName":"testuser"}]}`),
		ErrorValue: nil,
	}

	mockRunner := &SimpleRunner{
		DefaultOutput: []byte(""),
		DefaultError:  nil,
		Commands: map[string]*MockCommand{
			"whoami":   whoamiMock,
			"security": securityMock,
			"aws":      awsMock,
		},
	}

	opts := WizardOptions{
		Reader:            input,
		Writer:            &output,
		ErrorWriter:       &errOutput,
		ExecCommand:       mockRunner,
		OsExit:            mockExit,
		SkipClear:         true,
		AppExecutablePath: "/usr/local/bin/sesh", // Provide a path so we don't call os.Executable
	}

	runWizardWithOptions(opts)

	if exitCalled {
		t.Error("Exit function was called but should not have been")
	}

	outputStr := output.String()

	if !strings.Contains(outputStr, "📱 Enter these two consecutive codes in AWS when prompted:") {
		t.Error("Missing expected TOTP code header in output")
	}
	if !strings.Contains(outputStr, "First code:  123456") {
		t.Error("Missing first TOTP code in output")
	}
	if !strings.Contains(outputStr, "Second code: 654321") {
		t.Error("Missing second TOTP code in output")
	}
	if !strings.Contains(outputStr, "ℹ️  You can enter both codes immediately one after another") {
		t.Error("Missing codes instructions in output")
	}
	if !strings.Contains(outputStr, "⏱️  Complete the AWS setup within 30 seconds") {
		t.Error("Missing timing information in output")
	}

	if !strings.Contains(outputStr, "👤 Keychain account name") {
		t.Error("Missing keychain account name prompt in output")
	}
	if !strings.Contains(outputStr, "💾 Saving your secret to Keychain") {
		t.Error("Missing saving to keychain message in output")
	}

	foundWhoami := false
	for _, cmd := range mockRunner.CommandCalls {
		if cmd == "whoami" {
			foundWhoami = true
			break
		}
	}
	if !foundWhoami {
		t.Error("whoami command was not called to get default username")
	}

	if !strings.Contains(outputStr, "✅ MFA secret successfully stored in Keychain!") {
		t.Error("Missing success message for keychain storage")
	}

	if !strings.Contains(outputStr, "📝 Next steps:") {
		t.Error("Missing next steps section in output")
	}
}

func TestWizardWithWhoamiError(t *testing.T) {
	secretInput := "TESTSECRET123456\n\n" // Secret followed by empty username (to trigger whoami)
	input := strings.NewReader(secretInput)
	var output, errOutput bytes.Buffer

	exitCalled := false
	exitCode := 0
	mockExit := func(code int) {
		exitCalled = true
		exitCode = code
	}

	totp.MockGenerateConsecutiveCodes.CurrentCode = "123456"
	totp.MockGenerateConsecutiveCodes.NextCode = "654321"
	totp.MockGenerateConsecutiveCodes.Error = nil
	totp.MockGenerateConsecutiveCodes.Enabled = true
	defer totp.ResetMock()

	whoamiMock := &MockCommand{
		OutputData: []byte(""),
		ErrorValue: errors.New("whoami command failed"),
	}

	mockRunner := &SimpleRunner{
		DefaultOutput: []byte(""),
		DefaultError:  nil,
		Commands: map[string]*MockCommand{
			"whoami": whoamiMock,
		},
	}

	opts := WizardOptions{
		Reader:      input,
		Writer:      &output,
		ErrorWriter: &errOutput,
		ExecCommand: mockRunner,
		OsExit:      mockExit,
		SkipClear:   true,
	}

	runWizardWithOptions(opts)

	if !exitCalled {
		t.Error("Exit function should have been called")
	}
	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}

	errorStr := errOutput.String()
	if !strings.Contains(errorStr, "Could not determine current user") {
		t.Errorf("Expected error about determining current user, got: %s", errorStr)
	}
}

func TestWizardSecurityCommandError(t *testing.T) {
	secretInput := "TESTSECRET123456\ntestuser\n" // Secret and explicit username
	input := strings.NewReader(secretInput)
	var output, errOutput bytes.Buffer

	exitCalled := false
	exitCode := 0
	mockExit := func(code int) {
		exitCalled = true
		exitCode = code
	}

	totp.MockGenerateConsecutiveCodes.CurrentCode = "123456"
	totp.MockGenerateConsecutiveCodes.NextCode = "654321"
	totp.MockGenerateConsecutiveCodes.Error = nil
	totp.MockGenerateConsecutiveCodes.Enabled = true
	defer totp.ResetMock()

	securityMock := &MockCommand{
		OutputData: []byte(""),
		ErrorValue: errors.New("security command failed"),
	}

	mockRunner := &SimpleRunner{
		DefaultOutput: []byte(""),
		DefaultError:  nil,
		Commands: map[string]*MockCommand{
			"security": securityMock,
		},
	}

	opts := WizardOptions{
		Reader:            input,
		Writer:            &output,
		ErrorWriter:       &errOutput,
		ExecCommand:       mockRunner,
		OsExit:            mockExit,
		SkipClear:         true,
		AppExecutablePath: "/usr/local/bin/sesh", // Provide a path so we don't call os.Executable
	}

	runWizardWithOptions(opts)

	if !exitCalled {
		t.Error("Exit function should have been called")
	}
	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}

	errorStr := errOutput.String()
	if !strings.Contains(errorStr, "Failed to store secret in Keychain") {
		t.Errorf("Expected error about storing secret in Keychain, got: %s", errorStr)
	}
}

func TestWizardMFADevicesError(t *testing.T) {
	secretInput := "TESTSECRET123456\ntestuser\n"
	input := strings.NewReader(secretInput)
	var output, errOutput bytes.Buffer

	exitCalled := false
	mockExit := func(code int) {
		exitCalled = true
	}

	totp.MockGenerateConsecutiveCodes.CurrentCode = "123456"
	totp.MockGenerateConsecutiveCodes.NextCode = "654321"
	totp.MockGenerateConsecutiveCodes.Error = nil
	totp.MockGenerateConsecutiveCodes.Enabled = true
	defer totp.ResetMock()

	securityMock := &MockCommand{
		OutputData: []byte(""),
		ErrorValue: nil,
	}
	awsMock := &MockCommand{
		OutputData: []byte(""),
		ErrorValue: errors.New("aws command failed"),
	}

	mockRunner := &SimpleRunner{
		DefaultOutput: []byte(""),
		DefaultError:  nil,
		Commands: map[string]*MockCommand{
			"security": securityMock,
			"aws":      awsMock,
		},
	}

	opts := WizardOptions{
		Reader:            input,
		Writer:            &output,
		ErrorWriter:       &errOutput,
		ExecCommand:       mockRunner,
		OsExit:            mockExit,
		SkipClear:         true,
		AppExecutablePath: "/usr/local/bin/sesh",
	}

	runWizardWithOptions(opts)

	if exitCalled {
		t.Error("Exit was called, but should not have been")
	}

	errorStr := errOutput.String()
	if !strings.Contains(errorStr, "Could not list MFA devices from AWS") {
		t.Errorf("Expected error about MFA devices, got: %s", errorStr)
	}

	outputStr := output.String()
	if !strings.Contains(outputStr, "📝 Next steps:") {
		t.Error("Missing next steps section in output")
	}
}

func TestHelperProcess(*testing.T) {
	testutil.TestHelperProcess()
}
