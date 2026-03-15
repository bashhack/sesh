package testutil

import (
	"bytes"
	"io"
	"os"
	"testing"
)

// RedirectStderr redirects os.Stderr to a pipe for the duration of a test.
// Call the returned function to restore os.Stderr and retrieve captured output.
// The restore function must be called exactly once (typically via defer).
func RedirectStderr(t *testing.T) func() string {
	t.Helper()

	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() failed: %v", err)
	}
	os.Stderr = w

	return func() string {
		w.Close()
		var buf bytes.Buffer
		io.Copy(&buf, r)
		r.Close()
		os.Stderr = oldStderr
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
