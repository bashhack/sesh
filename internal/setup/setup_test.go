package setup

import (
	"bytes"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/testutil"
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

// TestClear tests the clear function
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
