package database

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/keychain"
)

// kcKeyMock satisfies the unexported keychainKeyProvider interface that
// KeychainSource wraps. Kept minimal — we only need to probe the length
// validation branches.
type kcKeyMock struct {
	// Fields ordered pointer-heavy first so govet's fieldalignment is happy.
	getErr   error
	setErr   error
	stored   []byte
	setCount int
}

func (m *kcKeyMock) GetSecret(_, _ string) ([]byte, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	if m.stored == nil {
		return nil, keychain.ErrNotFound
	}
	return append([]byte{}, m.stored...), nil
}

func (m *kcKeyMock) SetSecret(_, _ string, secret []byte) error {
	if m.setErr != nil {
		return m.setErr
	}
	m.setCount++
	m.stored = append([]byte{}, secret...)
	return nil
}

func TestKeychainSource_GetEncryptionKey_RejectsShortStoredValue(t *testing.T) {
	// Stored value too short to be a hex-encoded 32-byte key.
	kc := &kcKeyMock{stored: bytes.Repeat([]byte{0xAB}, 16)}
	ks := NewKeychainSource(kc, "testuser")

	got, err := ks.GetEncryptionKey()
	if err == nil {
		t.Fatal("expected error for wrong-length stored value, got nil")
	}
	if !strings.Contains(err.Error(), "invalid encryption key encoding") {
		t.Errorf("error = %v, want contains 'invalid encryption key encoding'", err)
	}
	if got != nil {
		t.Errorf("returned key = %v, want nil when length check fails", got)
	}
}

func TestKeychainSource_GetEncryptionKey_RejectsNonHexStoredValue(t *testing.T) {
	// Right length for hex (64 chars) but non-hex bytes — e.g., raw
	// binary left over from an older sesh build that didn't encode.
	kc := &kcKeyMock{stored: bytes.Repeat([]byte{0xAB}, 64)}
	ks := NewKeychainSource(kc, "testuser")

	_, err := ks.GetEncryptionKey()
	if err == nil {
		t.Fatal("expected error for non-hex stored value, got nil")
	}
	if !strings.Contains(err.Error(), "decode encryption key") {
		t.Errorf("error = %v, want contains 'decode encryption key'", err)
	}
}

func TestKeychainSource_GetEncryptionKey_PassesThroughUnderlyingError(t *testing.T) {
	// Non-length errors (locked keychain, permission denied) must reach
	// the caller so they can distinguish "key missing" from "can't read".
	sentinel := errors.New("operation not permitted")
	kc := &kcKeyMock{getErr: sentinel}
	ks := NewKeychainSource(kc, "testuser")

	_, err := ks.GetEncryptionKey()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("error = %v, want wraps %v", err, sentinel)
	}
}

func TestKeychainSource_StoreEncryptionKey_RejectsWrongLength(t *testing.T) {
	kc := &kcKeyMock{}
	ks := NewKeychainSource(kc, "testuser")

	err := ks.StoreEncryptionKey(bytes.Repeat([]byte{0xAB}, 16))
	if err == nil {
		t.Fatal("expected error for wrong-length key, got nil")
	}
	if !strings.Contains(err.Error(), "invalid encryption key length") {
		t.Errorf("error = %v, want contains 'invalid encryption key length'", err)
	}
	if kc.setCount != 0 {
		t.Errorf("SetSecret should not be invoked on invalid input; got %d calls", kc.setCount)
	}
}

func TestKeychainSource_RoundTrip(t *testing.T) {
	kc := &kcKeyMock{}
	ks := NewKeychainSource(kc, "testuser")

	want := bytes.Repeat([]byte{0xAB}, encryptionKeyLength)
	if err := ks.StoreEncryptionKey(want); err != nil {
		t.Fatalf("StoreEncryptionKey: %v", err)
	}
	got, err := ks.GetEncryptionKey()
	if err != nil {
		t.Fatalf("GetEncryptionKey: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("key mismatch: got %x, want %x", got, want)
	}
}

func TestKeychainSource_StoresAsHexEncoded(t *testing.T) {
	// The at-rest representation must be hex so random binary keys can't
	// trip the keychain backend's `security -i` text parser.
	kc := &kcKeyMock{}
	ks := NewKeychainSource(kc, "testuser")

	// Deliberately contains bytes that would break shell parsing raw:
	// 0x0A (newline), 0x20 (space), 0x09 (tab), 0x00 (null).
	raw := make([]byte, encryptionKeyLength)
	copy(raw, []byte{0x0A, 0x20, 0x09, 0x00, 0x22, 0x27, 0x5C})
	if err := ks.StoreEncryptionKey(raw); err != nil {
		t.Fatalf("StoreEncryptionKey on byte-hostile input: %v", err)
	}
	// Stored value must be hex (ASCII [0-9a-f]) regardless of input bytes.
	for _, b := range kc.stored {
		if (b < '0' || b > '9') && (b < 'a' || b > 'f') {
			t.Fatalf("stored value contains non-hex byte 0x%02x — not shell-safe", b)
		}
	}
	if len(kc.stored) != 2*encryptionKeyLength {
		t.Errorf("stored length = %d, want %d (2×key length for hex)", len(kc.stored), 2*encryptionKeyLength)
	}
}
