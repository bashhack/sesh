package testutil

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
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

// CaptureStdout captures stdout during a function execution
func CaptureStdout(fn func()) string {
	r, w, _ := os.Pipe()

	originalStdout := os.Stdout

	os.Stdout = w

	fn()

	// Close the write end of the pipe to get all output
	// and ignoring error as I can't do anything with it in this context
	_ = w.Close()

	os.Stdout = originalStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	return buf.String()
}

// CaptureStderr captures stderr during a function execution
func CaptureStderr(fn func()) string {
	r, w, _ := os.Pipe()

	originalStderr := os.Stderr

	os.Stderr = w

	fn()

	// Close the write end of the pipe to get all output
	// and ignoring any error as I can't do anything with it in this context
	_ = w.Close()

	os.Stderr = originalStderr

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	return buf.String()
}
