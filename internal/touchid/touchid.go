// Package touchid unlocks a secret with Touch ID through the Mac's Secure
// Enclave, without the Keychain.
//
// A Secure Enclave key that only a currently enrolled fingerprint can use
// is created once. The private key never leaves the chip; what's kept is a
// chip-bound handle (the key's blob), useless on any other Mac, which the
// caller stores in an ordinary file. A secret is wrapped to the key's public
// half in pure Go, with no prompt. Unwrapping needs the chip to do an ECDH
// with the private half, which asks for a fingerprint.
//
// The native calls exist only on macOS builds with cgo. Elsewhere Available
// reports false and the native calls return ErrUnavailable.
package touchid

import (
	"errors"
	"fmt"

	"github.com/bashhack/sesh/internal/keywrap"
)

var (
	// ErrUnavailable means Touch ID can't be used here: no sensor, no
	// enrolled fingerprint, no GUI session (e.g. over SSH), or a build
	// without the native code.
	ErrUnavailable = errors.New("touch ID is not available")
	// ErrCancelled means the person dismissed the Touch ID prompt.
	ErrCancelled = errors.New("touch ID was cancelled")
	// ErrLockedOut means too many failed attempts locked Touch ID until the
	// Mac's password is entered.
	ErrLockedOut = errors.New("touch ID is locked out")
	// ErrFailed means the fingerprint wasn't recognised.
	ErrFailed = errors.New("touch ID did not recognise the fingerprint")
	// ErrWrapMismatch means a wrapped secret doesn't open: it was wrapped
	// for another key or another binding, or was changed.
	ErrWrapMismatch = keywrap.ErrMismatch
)

// hkdfInfo names this use of a wrap (see keywrap), so a Touch ID wrap
// never opens as another kind.
const hkdfInfo = "sesh touch id unlock v1"

// Wrapped is a secret wrapped to a Secure Enclave key's public half.
type Wrapped = keywrap.Wrapped

// Wrap seals secret to pub, the uncompressed P-256 public key of a Secure
// Enclave key, binding it to aad. It needs no prompt and no native code.
func Wrap(pub, secret, aad []byte) (Wrapped, error) {
	return keywrap.Wrap(pub, secret, aad, hkdfInfo)
}

// Unwrap recovers a secret wrapped to the Secure Enclave key in blob. The
// chip asks for a fingerprint; macOS shows "<program> is trying to
// <reason>", so reason reads as a verb phrase ("unlock your vault"). aad
// must match the wrap's.
// cancelLabel, when not empty, relabels the prompt's Cancel button, e.g.
// "Type Password in Terminal" when cancelling means the caller asks for its
// own password; pressing it returns ErrCancelled. (A separate fallback button
// isn't shown for Secure Enclave keys, so relabelling Cancel is the way to
// offer one.) The prompt never accepts the Mac's login password.
func Unwrap(blob []byte, w Wrapped, aad []byte, reason, cancelLabel string) ([]byte, error) {
	return UnwrapWith(func(peer []byte) ([]byte, error) { return sharedSecret(blob, peer, reason, cancelLabel) }, w, aad)
}

// UnwrapWith recovers a wrapped secret using agree, the key agreement
// between the wrap's private key and the one-off public key it's given.
// Unwrap passes the Secure Enclave's; tests pass a software key's.
func UnwrapWith(agree func(peer []byte) ([]byte, error), w Wrapped, aad []byte) ([]byte, error) {
	return keywrap.Unwrap(agree, w, aad, hkdfInfo)
}

// Available reports whether this process can ask for a fingerprint now.
func Available() bool { return available() }

// NewKey creates a Secure Enclave key that only a currently enrolled
// fingerprint can use. Adding or removing a fingerprint makes it unusable
// for good. It returns the key's chip-bound blob, for the caller to store,
// and its uncompressed P-256 public key. No prompt is shown.
func NewKey() (blob, pub []byte, err error) { return newKey() }

// BiometryState returns an identifier for the set of enrolled fingerprints.
// It changes when a fingerprint is added or removed, which is also what
// makes a key from NewKey unusable for good. No prompt is shown.
func BiometryState() ([]byte, error) { return biometryState() }

// LocalAuthentication error codes (LAError) and OSStatus values that the
// Secure Enclave reports for a fingerprint check.
const (
	laAuthenticationFailed = -1
	laUserCancel           = -2
	laSystemCancel         = -4
	laPasscodeNotSet       = -5
	laBiometryNotAvailable = -6
	laBiometryNotEnrolled  = -7
	laBiometryLockout      = -8
	laAppCancel            = -9
	osUserCanceled         = -128   // errSecUserCanceled
	osAuthFailed           = -25293 // errSecAuthFailed
)

// classify turns a native error (domain and code) into one of this
// package's errors, or a descriptive one.
func classify(domain string, code int64) error {
	if domain == "com.apple.LocalAuthentication" {
		switch code {
		case laUserCancel, laSystemCancel, laAppCancel:
			return ErrCancelled
		case laPasscodeNotSet, laBiometryNotAvailable, laBiometryNotEnrolled:
			return ErrUnavailable
		case laBiometryLockout:
			return ErrLockedOut
		case laAuthenticationFailed:
			return ErrFailed
		}
	}
	switch code {
	case osUserCanceled:
		return ErrCancelled
	case osAuthFailed:
		return ErrFailed
	}
	return fmt.Errorf("touch ID: %s error %d", domain, code)
}

// sharedSecret is the ECDH between the Secure Enclave key in blob and peer,
// which needs a fingerprint. Tests replace it.
var sharedSecret = nativeSharedSecret
