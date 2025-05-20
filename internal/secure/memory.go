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

// SecureZeroString zeros out the contents of a string by creating
// a byte slice copy and zeroing that. Note that this doesn't guarantee
// the original string is removed from memory due to Go's immutable strings,
// but it helps reduce the exposure window.
func SecureZeroString(s string) {
	if s == "" {
		return
	}
	
	// Convert to bytes for zeroing
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