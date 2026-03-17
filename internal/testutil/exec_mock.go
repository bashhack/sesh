package testutil

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
)

// MockExecCommand builds a mock exec.Command function that returns
// predetermined output and optionally errors
func MockExecCommand(output string, err error) func(string, ...string) *exec.Cmd {
	return func(command string, args ...string) *exec.Cmd {
		// Create a test helper process that will be executed instead of the real command
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)

		// Set environment variables to control the helper process behavior
		cmd.Env = []string{
			"GO_WANT_HELPER_PROCESS=1",
			"MOCK_OUTPUT=" + output,
		}

		if err != nil {
			cmd.Env = append(cmd.Env, "MOCK_ERROR=1")
		}

		return cmd
	}
}

// MockCommandContext creates a test command that can be used in context-aware situations
func MockCommandContext(output string, err error) func(string, ...string) CommandRunner {
	return func(command string, args ...string) CommandRunner {
		return &mockCmd{
			output: output,
			err:    err,
		}
	}
}

// CommandRunner is an interface that encapsulates the methods we need from exec.Cmd
type CommandRunner interface {
	Output() ([]byte, error)
	Run() error
	CombinedOutput() ([]byte, error)
}

// mockCmd is a mock implementation of the CommandRunner interface
type mockCmd struct {
	output string
	err    error
}

// Output returns the predetermined output
func (m *mockCmd) Output() ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return []byte(m.output), nil
}

// Run simulates running a command
func (m *mockCmd) Run() error {
	return m.err
}

// CombinedOutput returns the predetermined output
func (m *mockCmd) CombinedOutput() ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return []byte(m.output), nil
}

// TestHelperProcess is not a real test, it's used by the mock exec.Command
// It should never be executed unless GO_WANT_HELPER_PROCESS is set.
// All tests using MockExecCommand must include a TestHelperProcess function.
//
// Example of how to implement in your test file:
//
//	func TestHelperProcess(t *testing.T) {
//		if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
//			return
//		}
//		if os.Getenv("MOCK_ERROR") == "1" {
//			os.Exit(1)
//		}
//		fmt.Print(os.Getenv("MOCK_OUTPUT"))
//		os.Exit(0)
//	}
func TestHelperProcess() {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	fmt.Print(os.Getenv("MOCK_OUTPUT"))
	if os.Getenv("MOCK_ERROR") == "1" {
		os.Exit(1)
	}
	os.Exit(0)
}

// stdoutMu serializes access to os.Stdout across concurrent tests.
var stdoutMu sync.Mutex

// CaptureStdout captures stdout during a function execution.
//
// Safe for use with t.Parallel() — concurrent callers are serialized via a mutex.
// If fn panics, os.Stdout is restored before the panic propagates.
func CaptureStdout(fn func()) string {
	stdoutMu.Lock()
	defer stdoutMu.Unlock()

	r, w, err := os.Pipe()
	if err != nil {
		panic("CaptureStdout: os.Pipe failed: " + err.Error())
	}

	originalStdout := os.Stdout
	os.Stdout = w
	defer func() {
		os.Stdout = originalStdout
	}()

	fn()

	if err := w.Close(); err != nil {
		panic("CaptureStdout: w.Close failed: " + err.Error())
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		panic("CaptureStdout: io.Copy failed: " + err.Error())
	}
	if err := r.Close(); err != nil {
		panic("CaptureStdout: r.Close failed: " + err.Error())
	}

	return buf.String()
}

// CaptureStderr captures stderr during a function execution.
//
// Safe for use with t.Parallel() — concurrent callers are serialized via a mutex.
// If fn panics, os.Stderr is restored before the panic propagates.
func CaptureStderr(fn func()) string {
	stderrMu.Lock()
	defer stderrMu.Unlock()

	r, w, err := os.Pipe()
	if err != nil {
		panic("CaptureStderr: os.Pipe failed: " + err.Error())
	}

	originalStderr := os.Stderr
	os.Stderr = w
	defer func() {
		os.Stderr = originalStderr
	}()

	fn()

	if err := w.Close(); err != nil {
		panic("CaptureStderr: w.Close failed: " + err.Error())
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		panic("CaptureStderr: io.Copy failed: " + err.Error())
	}
	if err := r.Close(); err != nil {
		panic("CaptureStderr: r.Close failed: " + err.Error())
	}

	return buf.String()
}
