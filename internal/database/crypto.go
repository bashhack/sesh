package database

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/bashhack/sesh/internal/kdf"
	"github.com/bashhack/sesh/internal/secure"
)

// Argon2idParams are the Argon2id settings a vault's key record holds.
type Argon2idParams = kdf.Params

// DefaultArgon2idParams returns the settings a new key record uses unless
// configured otherwise.
func DefaultArgon2idParams() Argon2idParams { return kdf.Default() }

// UnmarshalArgon2idParams deserialises Argon2id parameters from JSON.
func UnmarshalArgon2idParams(data string) (Argon2idParams, error) {
	var p Argon2idParams
	if err := json.Unmarshal([]byte(data), &p); err != nil {
		return p, fmt.Errorf("unmarshal argon2id params: %w", err)
	}
	return p, nil
}

// DeriveKey uses Argon2id to derive an encryption key from a password and salt.
func DeriveKey(password, salt []byte, params Argon2idParams) []byte {
	return kdf.Derive(password, salt, params)
}

// GenerateSalt produces a cryptographically random salt of the given length.
func GenerateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}

// Encrypt encrypts plaintext using AES-256-GCM with the provided key.
// The returned ciphertext is nonce || encrypted_data || tag. The key must
// be exactly 32 bytes; shorter keys are rejected rather than accepted as
// AES-128 or AES-192.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	return seal(key, plaintext, nil)
}

// seal is Encrypt with associated data.
func seal(key, plaintext, aad []byte) ([]byte, error) {
	if len(key) != encryptionKeyLength {
		return nil, fmt.Errorf("encrypt: key must be %d bytes (AES-256), got %d", encryptionKeyLength, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Seal appends the ciphertext+tag after the nonce.
	ciphertext := gcm.Seal(nonce, nonce, plaintext, aad)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext produced by Encrypt using AES-256-GCM.
// The key must be exactly 32 bytes.
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	return open(key, ciphertext, nil)
}

// open is Decrypt with associated data.
func open(key, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != encryptionKeyLength {
		return nil, fmt.Errorf("decrypt: key must be %d bytes (AES-256), got %d", encryptionKeyLength, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, enc := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, enc, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// entryKeyParams are the Argon2id parameters used for per-entry key derivation.
// Lighter than the master-key params because the master key is already strong
// random material — we only need domain separation per entry, not password stretching.
// These params must stay in sync between EncryptEntry and DecryptEntry.
var entryKeyParams = Argon2idParams{
	Time:    1,
	Memory:  16 * 1024, // 16 MiB
	Threads: 1,
	KeyLen:  32,
}

// EncryptEntry encrypts plaintext for storage, generating a per-entry salt
// and deriving a per-entry key from the master key material + salt. aad is
// authenticated but not encrypted: decrypting needs the same aad, which
// binds the ciphertext to what aad names (an entry's key). Returns
// (encryptedData, salt, error).
func EncryptEntry(masterKey, plaintext, aad []byte) (encryptedData, salt []byte, err error) {
	salt, err = GenerateSalt(16)
	if err != nil {
		return nil, nil, err
	}

	entryKey := DeriveKey(masterKey, salt, entryKeyParams)
	defer secure.SecureZeroBytes(entryKey)

	encryptedData, err = seal(entryKey, plaintext, aad)
	if err != nil {
		return nil, nil, err
	}

	return encryptedData, salt, nil
}

// DecryptEntry decrypts data produced by EncryptEntry with the same aad.
func DecryptEntry(masterKey, encryptedData, salt, aad []byte) ([]byte, error) {
	entryKey := DeriveKey(masterKey, salt, entryKeyParams)
	defer secure.SecureZeroBytes(entryKey)

	return open(entryKey, encryptedData, aad)
}
