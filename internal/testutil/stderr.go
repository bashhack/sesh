package testutil

import (
	"bytes"
	"io"
	"os"
	"sync"
	"testing"
)

// stderrMu serializes access to os.Stderr across concurrent tests.
var stderrMu sync.Mutex

// RedirectStderr redirects os.Stderr to a pipe for the duration of a test.
// Call the returned function to restore os.Stderr and retrieve captured output.
// The restore function must be called exactly once (typically via defer).
//
// Safe for use with t.Parallel() — concurrent callers are serialized via a mutex.
func RedirectStderr(t *testing.T) func() string {
	t.Helper()

	stderrMu.Lock()

	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		stderrMu.Unlock()
		t.Fatalf("os.Pipe() failed: %v", err)
	}
	os.Stderr = w

	return func() string {
		if err := w.Close(); err != nil {
			t.Errorf("RedirectStderr: w.Close failed: %v", err)
		}
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, r); err != nil {
			t.Errorf("RedirectStderr: io.Copy failed: %v", err)
		}
		if err := r.Close(); err != nil {
			t.Errorf("RedirectStderr: r.Close failed: %v", err)
		}
		os.Stderr = oldStderr
		stderrMu.Unlock()
		return buf.String()
	}
}

// DiscardStderr redirects os.Stderr to a pipe and discards output.
// The returned function restores os.Stderr. Typical usage:
//
//	defer testutil.DiscardStderr(t)()
func DiscardStderr(t *testing.T) func() {
	t.Helper()

	restore := RedirectStderr(t)
	return func() {
		restore()
	}
}
