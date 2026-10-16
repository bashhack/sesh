// Package secure provides security-related utilities for sesh.
//
// IMPORTANT SECURITY NOTE:
// Go's memory model and garbage collection make secure memory management
// challenging. The functions in this package do their best to reduce the
// exposure window of sensitive data, but they cannot guarantee complete
// removal from memory due to factors like:
//
// 1. Go's garbage collector can move and copy data
// 2. Go strings are immutable: their contents can't be overwritten at all
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
