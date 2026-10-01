//go:build !linux && !darwin

package agent

import "errors"

// Harden is not implemented on this platform.
func Harden() error {
	return errors.New("process hardening not implemented on this platform")
}

// WithLockedKeyMemory has no effect on this platform; the key stays on
// the heap.
func WithLockedKeyMemory() Option {
	return func(*Server) {}
}
