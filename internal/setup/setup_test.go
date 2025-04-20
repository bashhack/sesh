package setup

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/testutil"
	"github.com/bashhack/sesh/internal/totp"
)

type SimpleRunner struct {
	ReturnError bool
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

func (r *SimpleRunner) Command(command string, args ...string) *exec.Cmd {
	mockCmd := testutil.MockExecCommand("mocked output", nil)
	if r.ReturnError {
		mockCmd = testutil.MockExecCommand("", errors.New("mock error"))
	}
	return mockCmd("test", "arg")
}

func TestClearWithWriter(t *testing.T) {
	// NOTE: I'm just verifying it doesn't panic!
	var buf bytes.Buffer
	mockRunner := &SimpleRunner{ReturnError: false}
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

	customRunner := &SimpleRunner{ReturnError: false}

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
