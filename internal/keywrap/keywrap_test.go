package keywrap

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func softwareKey(t *testing.T) (agree func([]byte) ([]byte, error), pub []byte) {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return func(peer []byte) ([]byte, error) {
		p, err := ecdh.P256().NewPublicKey(peer)
		if err != nil {
			return nil, err
		}
		return priv.ECDH(p)
	}, priv.PublicKey().Bytes()
}

func TestWrapUnwrap(t *testing.T) {
	agree, pub := softwareKey(t)
	secret := bytes.Repeat([]byte{0x5e}, 32)
	w, err := Wrap(pub, secret, []byte("vault"), "use A")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unwrap(agree, w, []byte("vault"), "use A")
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("Unwrap = %x, %v", got, err)
	}
	for name, tt := range map[string]struct{ aad, info string }{
		"another binding": {"other vault", "use A"},
		"another use":     {"vault", "use B"},
	} {
		if _, err := Unwrap(agree, w, []byte(tt.aad), tt.info); !errors.Is(err, ErrMismatch) {
			t.Errorf("%s: err = %v, want ErrMismatch", name, err)
		}
	}
	otherAgree, _ := softwareKey(t)
	if _, err := Unwrap(otherAgree, w, []byte("vault"), "use A"); !errors.Is(err, ErrMismatch) {
		t.Errorf("another private key: err = %v, want ErrMismatch", err)
	}
}

func TestWrap_RejectsABadPublicKey(t *testing.T) {
	if _, err := Wrap([]byte("not a key"), []byte("s"), nil, "x"); err == nil || !strings.Contains(err.Error(), "public key") {
		t.Fatalf("err = %v", err)
	}
}

func TestUnwrap_TooShort(t *testing.T) {
	agree, pub := softwareKey(t)
	w, err := Wrap(pub, []byte("s"), nil, "x")
	if err != nil {
		t.Fatal(err)
	}
	w.Ciphertext = w.Ciphertext[:5]
	if _, err := Unwrap(agree, w, nil, "x"); err == nil || !strings.Contains(err.Error(), "too short") {
		t.Fatalf("err = %v", err)
	}
}
