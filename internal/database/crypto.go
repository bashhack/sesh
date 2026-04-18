package database

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"

	"github.com/bashhack/sesh/internal/secure"
)

// Argon2idParams holds the tuning parameters for Argon2id key derivation.
type Argon2idParams struct {
	Time    uint32 `json:"time"`    // iterations
	Memory  uint32 `json:"memory"`  // KiB
	Threads uint8  `json:"threads"` // parallelism
	KeyLen  uint32 `json:"key_len"` // derived key length in bytes
}

// DefaultArgon2idParams returns production-grade Argon2id parameters.
// Time=3, Memory=64 MiB, Threads=4, KeyLen=32 (AES-256).
func DefaultArgon2idParams() Argon2idParams {
	return Argon2idParams{
		Time:    3,
		Memory:  64 * 1024, // 64 MiB
		Threads: 4,
		KeyLen:  32,
	}
}

// MarshalParams serialises Argon2id parameters to JSON for storage in key_metadata.
// The struct is composed of fixed-width integers, so json.Marshal cannot fail for
// any valid Argon2idParams value — a non-nil error here indicates a programming
// bug (e.g. someone added an unmarshalable field).
func (p Argon2idParams) MarshalParams() string {
	b, err := json.Marshal(p)
	if err != nil {
		panic(fmt.Sprintf("marshal Argon2idParams: %v (unreachable — fields are all numeric)", err))
	}
	return string(b)
}

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
	return argon2.IDKey(password, salt, params.Time, params.Memory, params.Threads, params.KeyLen)
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
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext produced by Encrypt using AES-256-GCM.
// The key must be exactly 32 bytes.
func Decrypt(key, ciphertext []byte) ([]byte, error) {
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
	plaintext, err := gcm.Open(nil, nonce, enc, nil)
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
// and deriving a per-entry key from the master key material + salt.
// Returns (encryptedData, salt, error).
func EncryptEntry(masterKey, plaintext []byte) (encryptedData, salt []byte, err error) {
	salt, err = GenerateSalt(16)
	if err != nil {
		return nil, nil, err
	}

	entryKey := DeriveKey(masterKey, salt, entryKeyParams)
	defer secure.SecureZeroBytes(entryKey)

	encryptedData, err = Encrypt(entryKey, plaintext)
	if err != nil {
		return nil, nil, err
	}

	return encryptedData, salt, nil
}

// DecryptEntry decrypts data produced by EncryptEntry.
func DecryptEntry(masterKey, encryptedData, salt []byte) ([]byte, error) {
	entryKey := DeriveKey(masterKey, salt, entryKeyParams)
	defer secure.SecureZeroBytes(entryKey)

	return Decrypt(entryKey, encryptedData)
}
