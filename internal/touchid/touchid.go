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
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
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
	ErrWrapMismatch = errors.New("touch ID wrapped secret doesn't open with this key")
)

// hkdfInfo separates this use of the shared secret from any other.
const hkdfInfo = "sesh touch id unlock v1"

// Wrapped is a secret wrapped to a Secure Enclave key's public half.
type Wrapped struct {
	// EphemeralPub is the uncompressed P-256 public key of the one-off key
	// the wrap used.
	EphemeralPub []byte
	// Ciphertext is the AES-256-GCM nonce followed by the sealed secret.
	Ciphertext []byte
}

// Wrap seals secret to pub, the uncompressed P-256 public key of a Secure
// Enclave key, binding it to aad. It needs no prompt and no native code.
func Wrap(pub, secret, aad []byte) (Wrapped, error) {
	peer, err := ecdh.P256().NewPublicKey(pub)
	if err != nil {
		return Wrapped{}, fmt.Errorf("touch ID public key: %w", err)
	}
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return Wrapped{}, err
	}
	shared, err := eph.ECDH(peer)
	if err != nil {
		return Wrapped{}, err
	}
	aead, err := wrapAEAD(shared, eph.PublicKey().Bytes())
	clear(shared)
	if err != nil {
		return Wrapped{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Wrapped{}, err
	}
	return Wrapped{
		EphemeralPub: eph.PublicKey().Bytes(),
		Ciphertext:   aead.Seal(nonce, nonce, secret, aad),
	}, nil
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
	shared, err := agree(w.EphemeralPub)
	if err != nil {
		return nil, err
	}
	aead, err := wrapAEAD(shared, w.EphemeralPub)
	clear(shared)
	if err != nil {
		return nil, err
	}
	n := aead.NonceSize()
	if len(w.Ciphertext) < n {
		return nil, errors.New("touch ID wrapped secret is too short")
	}
	secret, err := aead.Open(nil, w.Ciphertext[:n], w.Ciphertext[n:], aad)
	if err != nil {
		return nil, ErrWrapMismatch
	}
	return secret, nil
}

// wrapAEAD derives the AES-256-GCM key from an ECDH shared secret, salted
// with the one-off public key.
func wrapAEAD(shared, ephPub []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, shared, ephPub, hkdfInfo, 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Available reports whether this process can ask for a fingerprint now.
func Available() bool { return available() }

// NewKey creates a Secure Enclave key that only a currently enrolled
// fingerprint can use. Adding or removing a fingerprint makes it unusable
// for good. It returns the key's chip-bound blob, for the caller to store,
// and its uncompressed P-256 public key. No prompt is shown.
func NewKey() (blob, pub []byte, err error) { return newKey() }

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
