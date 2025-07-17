// Package secure provides security-related utilities for sesh.
//
// IMPORTANT SECURITY NOTE:
// Go's memory model and garbage collection make secure memory management
// challenging. The functions in this package do their best to reduce the
// exposure window of sensitive data, but they cannot guarantee complete
// removal from memory due to factors like:
//
// 1. Go's garbage collector can move and copy data
// 2. Go strings are immutable and their contents can be duplicated
// 3. Compiler optimizations might affect security guarantees
// 4. Memory might be paged to disk outside of Go's control
//
// For maximum security, prefer:
// - Keeping sensitive data in []byte form rather than strings
// - Minimizing the scope and lifetime of sensitive data
// - Zeroing sensitive data immediately after use
package secure

import (
	"bytes"
	"os/exec"
	"runtime"
)

// SecureZeroBytes zeros out a byte slice in a way that won't be
// optimized away by the compiler. This helps ensure sensitive data
// is cleared from memory when no longer needed.
func SecureZeroBytes(data []byte) {
	// Return early if data is empty
	if len(data) == 0 {
		return
	}

	// Explicitly zero each byte
	for i := range data {
		data[i] = 0
	}

	// Use runtime.KeepAlive to prevent the compiler from
	// optimizing away the zeroing operation
	runtime.KeepAlive(data)
}

// SecureZeroString attempts to reduce the exposure window of a string
// by creating a byte slice copy and zeroing it. Due to Go's immutable
// strings and garbage-collected memory model, the original string data
// may remain in memory and cannot be securely erased.
//
// WARNING: Only use this if you cannot avoid working with string.
// Prefer keeping secrets in []byte form from the beginning for actual zeroing.
// This function can introduce additional exposure by creating a second copy
// of the sensitive data in memory.
func SecureZeroString(s string) {
	if s == "" {
		return
	}

	// Convert to bytes for zeroing
	// Note: This creates a new copy in memory, which is not ideal for security
	b := []byte(s)
	SecureZeroBytes(b)
}

// ZeroStrings zeroes multiple strings at once
func ZeroStrings(strings ...string) {
	for _, s := range strings {
		SecureZeroString(s)
	}
}

// ZeroBytes zeroes multiple byte slices at once
func ZeroBytes(byteSlices ...[]byte) {
	for _, b := range byteSlices {
		SecureZeroBytes(b)
	}
}

// ExecAndCaptureSecure executes a command and securely captures its stdout
// as a byte slice. If an error occurs, any captured output is securely zeroed.
// This function is particularly useful for capturing sensitive data from commands.
func ExecAndCaptureSecure(cmd *exec.Cmd) ([]byte, error) {
	// Use direct command execution with a secure buffer instead of pipes
	// This addresses an issue where using stdout pipes would return incorrect data
	// for binary content from certain commands (e.g., macOS 'security')
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Zero both buffers before returning error
		SecureZeroBytes(stdout.Bytes())
		SecureZeroBytes(stderr.Bytes())
		return nil, err
	}

	result := bytes.TrimSpace(stdout.Bytes())

	// Create a copy we can safely return
	secureResult := make([]byte, len(result))
	copy(secureResult, result)

	// Zero both buffers to minimize exposure window
	SecureZeroBytes(stdout.Bytes())
	SecureZeroBytes(stderr.Bytes())

	return secureResult, nil
}

// ExecWithSecretInput executes a command with a sensitive byte slice provided via stdin
// This is more secure than passing secrets as command-line arguments, which might
// be visible in process listings (ps) or command history
func ExecWithSecretInput(cmd *exec.Cmd, secret []byte) error {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	if _, err := stdin.Write(secret); err != nil {
		_ = cmd.Process.Kill() // Kill process on write error
		_ = cmd.Wait()         // Clean up resources
		return err
	}

	// Close stdin to signal EOF
	_ = stdin.Close()

	return cmd.Wait()
}
