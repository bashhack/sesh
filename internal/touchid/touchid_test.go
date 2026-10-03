package touchid

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

// softwareEnclave stands in for the chip: a software P-256 key whose ECDH
// plays the Secure Enclave's part. blob names the key, as the chip's does.
func softwareEnclave(t *testing.T) (blob, pub []byte) {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blob = []byte("software key")
	orig := sharedSecret
	sharedSecret = func(b, peer []byte, reason, _ string) ([]byte, error) {
		if !bytes.Equal(b, blob) {
			return nil, errors.New("unknown key blob")
		}
		if reason == "" {
			t.Error("no prompt reason given")
		}
		p, err := ecdh.P256().NewPublicKey(peer)
		if err != nil {
			return nil, err
		}
		return priv.ECDH(p)
	}
	t.Cleanup(func() { sharedSecret = orig })
	return blob, priv.PublicKey().Bytes()
}

func TestWrapUnwrap(t *testing.T) {
	blob, pub := softwareEnclave(t)
	secret := bytes.Repeat([]byte{0x5e}, 32)
	aad := []byte("vault unlock id")

	w, err := Wrap(pub, secret, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(w.Ciphertext, secret) {
		t.Fatal("the secret appears in the ciphertext")
	}
	got, err := Unwrap(blob, w, aad, "unlock the test vault", "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Errorf("unwrapped %x, want %x", got, secret)
	}

	again, err := Wrap(pub, secret, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(again.EphemeralPub, w.EphemeralPub) || bytes.Equal(again.Ciphertext, w.Ciphertext) {
		t.Error("two wraps of the same secret are identical; the one-off key isn't one-off")
	}
}

func TestUnwrap_Refuses(t *testing.T) {
	blob, pub := softwareEnclave(t)
	secret := []byte("0123456789abcdef0123456789abcdef")
	w, err := Wrap(pub, secret, []byte("vault A"))
	if err != nil {
		t.Fatal(err)
	}
	tampered := Wrapped{EphemeralPub: w.EphemeralPub, Ciphertext: bytes.Clone(w.Ciphertext)}
	tampered.Ciphertext[len(tampered.Ciphertext)-1] ^= 1

	for name, tt := range map[string]struct {
		aad string
		w   Wrapped
	}{
		"another vault's binding": {"vault B", w},
		"tampered ciphertext":     {"vault A", tampered},
		"truncated ciphertext":    {"vault A", Wrapped{EphemeralPub: w.EphemeralPub, Ciphertext: w.Ciphertext[:5]}},
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := Unwrap(blob, tt.w, []byte(tt.aad), "reason", ""); err == nil {
				t.Fatalf("unwrapped %q, want a refusal", got)
			}
		})
	}

	_, otherPub := softwareEnclave(t) // a different chip key
	w2, err := Wrap(otherPub, secret, []byte("vault A"))
	if err != nil {
		t.Fatal(err)
	}
	softwareEnclave(t) // and yet another one answering the unwrap
	if _, err := Unwrap([]byte("software key"), w2, []byte("vault A"), "reason", ""); err == nil {
		t.Error("a different key unwrapped the secret")
	}
}

func TestWrap_RejectsABadPublicKey(t *testing.T) {
	if _, err := Wrap([]byte("not a key"), []byte("s"), nil); err == nil || !strings.Contains(err.Error(), "public key") {
		t.Fatalf("err = %v", err)
	}
}

func TestClassify(t *testing.T) {
	const la = "com.apple.LocalAuthentication"
	for _, tt := range []struct {
		want   error
		domain string
		code   int64
	}{
		{ErrCancelled, la, laUserCancel},
		{ErrCancelled, la, laSystemCancel},
		{ErrCancelled, la, laAppCancel},
		{ErrUnavailable, la, laBiometryNotAvailable},
		{ErrUnavailable, la, laBiometryNotEnrolled},
		{ErrUnavailable, la, laPasscodeNotSet},
		{ErrLockedOut, la, laBiometryLockout},
		{ErrFailed, la, laAuthenticationFailed},
		{ErrCancelled, "NSOSStatusErrorDomain", osUserCanceled},
		{ErrFailed, "NSOSStatusErrorDomain", osAuthFailed},
	} {
		if got := classify(tt.domain, tt.code); !errors.Is(got, tt.want) {
			t.Errorf("classify(%s, %d) = %v, want %v", tt.domain, tt.code, got, tt.want)
		}
	}
	if got := classify("CryptoTokenKit", -3); got == nil || !strings.Contains(got.Error(), "CryptoTokenKit error -3") {
		t.Errorf("unknown error = %v, want it described", got)
	}
}
