// Package testutil provides test helpers including command mocking, stdout/stderr capture, and random string generation.
package testutil

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
)

// NOTE TO SELF: I have two patterns for mocking external commands.
//
// Pattern 1 (in-process mock) — I should use this most of the time.
// It's way faster, especially under -race (subprocess pattern costs ~1s per call).
// I define a var like `var runCommand = func(name string, args ...string) ([]byte, error)`
// in prod code, then swap it in tests. See internal/setup/setup.go for how I did this.
//
// Pattern 2 (subprocess mock, below) — I only need this when I care about real
// process behavior: exit codes, signals, stderr, etc. It spawns the test binary
// as a child process via TestHelperProcess. See internal/keychain/keychain_test.go.

// MockExecCommand builds a mock exec.Command function that returns
// predetermined output and optionally errors (pattern 2: subprocess mock)
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
	err    error
	output string
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
	wClosed := false
	rClosed := false
	defer func() {
		if !wClosed {
			if err := w.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "CaptureStdout: deferred w.Close failed: %v\n", err)
			}
		}
		if !rClosed {
			if err := r.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "CaptureStdout: deferred r.Close failed: %v\n", err)
			}
		}
	}()

	originalStdout := os.Stdout
	os.Stdout = w
	defer func() {
		os.Stdout = originalStdout
	}()

	fn()

	if err := w.Close(); err != nil {
		panic("CaptureStdout: w.Close failed: " + err.Error())
	}
	wClosed = true

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		panic("CaptureStdout: io.Copy failed: " + err.Error())
	}
	if err := r.Close(); err != nil {
		panic("CaptureStdout: r.Close failed: " + err.Error())
	}
	rClosed = true

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
	wClosed := false
	rClosed := false
	defer func() {
		if !wClosed {
			if closeErr := w.Close(); closeErr != nil {
				fmt.Fprintf(os.Stderr, "CaptureStderr: deferred w.Close failed: %v\n", closeErr)
			}
		}
		if !rClosed {
			if closeErr := r.Close(); closeErr != nil {
				fmt.Fprintf(os.Stderr, "CaptureStderr: deferred r.Close failed: %v\n", closeErr)
			}
		}
	}()

	originalStderr := os.Stderr
	os.Stderr = w
	defer func() {
		os.Stderr = originalStderr
	}()

	fn()

	if err := w.Close(); err != nil {
		panic("CaptureStderr: w.Close failed: " + err.Error())
	}
	wClosed = true

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		panic("CaptureStderr: io.Copy failed: " + err.Error())
	}
	if err := r.Close(); err != nil {
		panic("CaptureStderr: r.Close failed: " + err.Error())
	}
	rClosed = true

	return buf.String()
}
