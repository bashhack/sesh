// Package keywrap seals a secret to a P-256 public key, so that only the
// holder of the private key can open it: an ephemeral P-256 ECDH, HKDF-SHA256
// salted with the one-off public key, and AES-256-GCM. Wrapping needs only
// the public key; unwrapping needs the key agreement with the private one,
// which the caller supplies (a Secure Enclave key, or one derived from a
// recovery key).
//
// Each use names itself with an info string, mixed into the derived key, so
// a wrap made for one use never opens as another.
package keywrap

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

// ErrMismatch means a wrapped secret doesn't open: it was wrapped for
// another key, another binding, or another use, or it was changed.
var ErrMismatch = errors.New("wrapped secret doesn't open with this key")

// Wrapped is a secret wrapped to a P-256 public key.
type Wrapped struct {
	// EphemeralPub is the uncompressed P-256 public key of the one-off key
	// the wrap used.
	EphemeralPub []byte
	// Ciphertext is the AES-256-GCM nonce followed by the sealed secret.
	Ciphertext []byte
}

// Wrap seals secret to pub, an uncompressed P-256 public key, binding it to
// aad. info names the use.
func Wrap(pub, secret, aad []byte, info string) (Wrapped, error) {
	peer, err := ecdh.P256().NewPublicKey(pub)
	if err != nil {
		return Wrapped{}, fmt.Errorf("wrap public key: %w", err)
	}
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return Wrapped{}, err
	}
	shared, err := eph.ECDH(peer)
	if err != nil {
		return Wrapped{}, err
	}
	aead, err := newAEAD(shared, eph.PublicKey().Bytes(), info)
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

// Unwrap recovers a wrapped secret. agree is the key agreement between the
// wrap's private key and the one-off public key it's given; aad and info
// must match the wrap's.
func Unwrap(agree func(peer []byte) ([]byte, error), w Wrapped, aad []byte, info string) ([]byte, error) {
	shared, err := agree(w.EphemeralPub)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(shared, w.EphemeralPub, info)
	clear(shared)
	if err != nil {
		return nil, err
	}
	n := aead.NonceSize()
	if len(w.Ciphertext) < n {
		return nil, errors.New("wrapped secret is too short")
	}
	secret, err := aead.Open(nil, w.Ciphertext[:n], w.Ciphertext[n:], aad)
	if err != nil {
		return nil, ErrMismatch
	}
	return secret, nil
}

// newAEAD derives the AES-256-GCM key from an ECDH shared secret, salted
// with the one-off public key.
func newAEAD(shared, ephPub []byte, info string) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, shared, ephPub, info, 32)
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
