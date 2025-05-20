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

import "runtime"

// SecureZeroBytes zeros out a byte slice in a way that won't be
// optimized away by the compiler. This helps ensure sensitive data
// is cleared from memory when no longer needed.
func SecureZeroBytes(data []byte) {
	// Return early if data is nil or empty
	if data == nil || len(data) == 0 {
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