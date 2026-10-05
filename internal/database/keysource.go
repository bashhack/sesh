package database

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bashhack/sesh/internal/secure"
)

const (
	// keychainEncKeyService is the keychain service name for the SQLite encryption key.
	keychainEncKeyService = "sesh-sqlite-encryption-key"

	// encryptionKeyLength is the length in bytes of the master encryption key.
	encryptionKeyLength = 32
)

// KeySource abstracts where the master encryption key comes from.
// The keychain source is implemented now; a master-password source
// can be added later without changing the store.
type KeySource interface {
	// GetEncryptionKey returns the master encryption key.
	// The caller must zero the returned slice after use.
	GetEncryptionKey() ([]byte, error)

	// StoreEncryptionKey persists a new master encryption key.
	StoreEncryptionKey(key []byte) error

	// RequiresUserInput reports whether retrieving the key
	// needs interactive input (e.g. a master password prompt).
	RequiresUserInput() bool

	// Name returns a human-readable name for this key source.
	Name() string
}

// CryptoOracle encrypts and decrypts entry secrets without exposing the
// raw master key to the caller. Store depends only on this. The agent's
// key source implements it directly; a KeySource becomes one through
// NewKeySourceOracle.
type CryptoOracle interface {
	// EncryptEntry seals plaintext under the master key and returns the
	// ciphertext plus the per-entry salt.
	EncryptEntry(plaintext []byte) (encryptedData, salt []byte, err error)

	// DecryptEntry opens a blob produced by EncryptEntry.
	DecryptEntry(encryptedData, salt []byte) ([]byte, error)
}

// keychainKeyProvider reads and writes the Keychain item KeychainSource
// keeps the key in (keychain.Items, or a stand-in in tests).
type keychainKeyProvider interface {
	GetSecret(account, service string) ([]byte, error)
	SetSecret(account, service string, secret []byte) error
}

// KeychainSource retrieves and stores the master encryption key in the OS keychain.
type KeychainSource struct {
	keychain keychainKeyProvider
	account  string // OS username
}

// NewKeychainSource creates a KeychainSource that stores the encryption key
// under the given account in the OS keychain.
func NewKeychainSource(kc keychainKeyProvider, account string) *KeychainSource {
	return &KeychainSource{keychain: kc, account: account}
}

// GetEncryptionKey reads the master key from the keychain. The stored
// value is a hex-encoded string of the raw 32-byte key. The key is
// written through `security -i`, whose tokenizer splits on
// whitespace and control bytes — random binary keys regularly contain
// those bytes and fail to store, so we keep the at-rest form in
// ASCII-safe hex.
func (s *KeychainSource) GetEncryptionKey() ([]byte, error) {
	stored, err := s.keychain.GetSecret(s.account, keychainEncKeyService)
	if err != nil {
		return nil, fmt.Errorf("get encryption key from keychain: %w", err)
	}
	defer secure.SecureZeroBytes(stored)

	// Hex-encoded key is 2*N chars (UTF-8 ASCII, 1 byte each). Raw keys
	// stored by earlier builds used base64 or raw bytes and would have a
	// different length.
	expectedEncodedLen := hex.EncodedLen(encryptionKeyLength)
	if len(stored) != expectedEncodedLen {
		return nil, fmt.Errorf("invalid encryption key encoding: got %d bytes, want %d hex chars (did an older sesh store a different format? re-init with `security delete-generic-password -s %s`)",
			len(stored), expectedEncodedLen, keychainEncKeyService)
	}

	key := make([]byte, encryptionKeyLength)
	if _, err := hex.Decode(key, stored); err != nil {
		secure.SecureZeroBytes(key)
		return nil, fmt.Errorf("decode encryption key: %w", err)
	}
	return key, nil
}

// StoreEncryptionKey persists the master key in the keychain. The raw
// 32-byte key is hex-encoded before storage so the resulting string is
// guaranteed to contain only [0-9a-f] — safe for the `security -i` text
// protocol the item is written through. See GetEncryptionKey for context.
func (s *KeychainSource) StoreEncryptionKey(key []byte) error {
	if len(key) != encryptionKeyLength {
		return fmt.Errorf("invalid encryption key length: got %d bytes, want %d", len(key), encryptionKeyLength)
	}
	encoded := make([]byte, hex.EncodedLen(len(key)))
	hex.Encode(encoded, key)
	defer secure.SecureZeroBytes(encoded)

	if err := s.keychain.SetSecret(s.account, keychainEncKeyService, encoded); err != nil {
		return fmt.Errorf("store encryption key in keychain: %w", err)
	}
	return nil
}

func (s *KeychainSource) RequiresUserInput() bool { return false }
func (s *KeychainSource) Name() string            { return "keychain" }

// GenerateEncryptionKey creates a new random 256-bit encryption key.
func GenerateEncryptionKey() ([]byte, error) {
	key := make([]byte, encryptionKeyLength)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		secure.SecureZeroBytes(key)
		return nil, fmt.Errorf("generate encryption key: %w", err)
	}
	return key, nil
}
