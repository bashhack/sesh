//go:build !linux && !darwin

package agent

import "errors"

// Harden is not implemented on this platform.
func Harden() error {
	return errors.New("process hardening not implemented on this platform")
}

// mapLockedPage is not implemented on this platform, so an agent asked
// for locked key memory refuses to start.
func mapLockedPage() ([]byte, error) {
	return nil, errors.New("locked key memory not implemented on this platform")
}
