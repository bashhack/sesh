package database

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	tests := map[string]struct {
		key       []byte
		plaintext []byte
	}{
		"short plaintext": {
			key:       bytes.Repeat([]byte{0xAA}, 32),
			plaintext: []byte("secret"),
		},
		"longer plaintext": {
			key:       bytes.Repeat([]byte{0xBB}, 32),
			plaintext: []byte("a-much-longer-secret-value-that-exceeds-a-block"),
		},
		"empty plaintext": {
			key:       bytes.Repeat([]byte{0xCC}, 32),
			plaintext: []byte(""),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ciphertext, err := Encrypt(tc.key, tc.plaintext)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			if len(tc.plaintext) > 0 && bytes.Equal(ciphertext, tc.plaintext) {
				t.Fatal("ciphertext should differ from plaintext")
			}

			got, err := Decrypt(tc.key, ciphertext)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}

			if !bytes.Equal(got, tc.plaintext) {
				t.Fatalf("round-trip failed: got %q, want %q", got, tc.plaintext)
			}
		})
	}
}

func TestDecryptErrors(t *testing.T) {
	tests := map[string]struct {
		key        []byte
		ciphertext []byte
	}{
		"wrong key": {
			key: func() []byte {
				key := bytes.Repeat([]byte{0x00}, 32)
				ct, err := Encrypt(key, []byte("secret"))
				if err != nil {
					panic(err)
				}
				wrongKey := bytes.Repeat([]byte{0xFF}, 32)
				// Store ciphertext in the test case via closure
				_ = ct
				return wrongKey
			}(),
			ciphertext: func() []byte {
				key := bytes.Repeat([]byte{0x00}, 32)
				ct, err := Encrypt(key, []byte("secret"))
				if err != nil {
					panic(err)
				}
				return ct
			}(),
		},
		"too short": {
			key:        bytes.Repeat([]byte{0x00}, 32),
			ciphertext: []byte{1, 2, 3},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Decrypt(tc.key, tc.ciphertext)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestEncryptEntryDecryptEntry(t *testing.T) {
	tests := map[string]struct {
		masterKey []byte
		plaintext []byte
	}{
		"totp secret": {
			masterKey: bytes.Repeat([]byte{0x01}, 32),
			plaintext: []byte("JBSWY3DPEHPK3PXP"),
		},
		"password": {
			masterKey: bytes.Repeat([]byte{0x02}, 32),
			plaintext: []byte("hunter2"),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			encData, salt, err := EncryptEntry(tc.masterKey, tc.plaintext)
			if err != nil {
				t.Fatalf("EncryptEntry: %v", err)
			}

			if len(salt) != 16 {
				t.Fatalf("expected 16-byte salt, got %d", len(salt))
			}

			got, err := DecryptEntry(tc.masterKey, encData, salt)
			if err != nil {
				t.Fatalf("DecryptEntry: %v", err)
			}

			if !bytes.Equal(got, tc.plaintext) {
				t.Fatalf("round-trip failed: got %q, want %q", got, tc.plaintext)
			}
		})
	}
}

func TestEncryptEntryUniqueSalts(t *testing.T) {
	masterKey := bytes.Repeat([]byte{0xAB}, 32)
	plaintext := []byte("same-data")

	_, salt1, err := EncryptEntry(masterKey, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	_, salt2, err := EncryptEntry(masterKey, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(salt1, salt2) {
		t.Fatal("two calls should produce different salts")
	}
}

func TestDeriveKey(t *testing.T) {
	tests := map[string]struct {
		password []byte
		salt     []byte
	}{
		"standard inputs": {
			password: []byte("test-password"),
			salt:     []byte("test-salt-16byte"),
		},
		"empty password": {
			password: []byte(""),
			salt:     []byte("some-salt-value!"),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			params := DefaultArgon2idParams()
			key := DeriveKey(tc.password, tc.salt, params)

			if len(key) != int(params.KeyLen) {
				t.Fatalf("expected %d-byte key, got %d", params.KeyLen, len(key))
			}

			// Deterministic: same inputs produce same key
			key2 := DeriveKey(tc.password, tc.salt, params)
			if !bytes.Equal(key, key2) {
				t.Fatal("same inputs should produce same key")
			}
		})
	}
}

func TestDeriveKeyDifferentInputs(t *testing.T) {
	params := DefaultArgon2idParams()
	salt := []byte("test-salt-16byte")

	key1 := DeriveKey([]byte("password-a"), salt, params)
	key2 := DeriveKey([]byte("password-b"), salt, params)

	if bytes.Equal(key1, key2) {
		t.Fatal("different passwords should produce different keys")
	}
}

func TestGenerateSalt(t *testing.T) {
	tests := map[string]struct {
		length int
	}{
		"16 bytes": {length: 16},
		"32 bytes": {length: 32},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			salt, err := GenerateSalt(tc.length)
			if err != nil {
				t.Fatalf("GenerateSalt: %v", err)
			}
			if len(salt) != tc.length {
				t.Fatalf("expected %d bytes, got %d", tc.length, len(salt))
			}

			allZero := true
			for _, b := range salt {
				if b != 0 {
					allZero = false
					break
				}
			}
			if allZero {
				t.Fatal("salt should not be all zeros")
			}
		})
	}
}

func TestArgon2idParamsMarshalRoundTrip(t *testing.T) {
	params := DefaultArgon2idParams()
	data := params.MarshalParams()

	got, err := UnmarshalArgon2idParams(data)
	if err != nil {
		t.Fatalf("UnmarshalArgon2idParams: %v", err)
	}

	if got != params {
		t.Fatalf("round-trip failed: got %+v, want %+v", got, params)
	}
}
