package database

import (
	"crypto/rand"
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

// keychainKeyProvider is the subset of keychain.Provider that KeychainSource needs.
// Using a narrow interface avoids importing the full keychain package in tests.
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

func (s *KeychainSource) GetEncryptionKey() ([]byte, error) {
	key, err := s.keychain.GetSecret(s.account, keychainEncKeyService)
	if err != nil {
		return nil, fmt.Errorf("get encryption key from keychain: %w", err)
	}
	return key, nil
}

func (s *KeychainSource) StoreEncryptionKey(key []byte) error {
	if err := s.keychain.SetSecret(s.account, keychainEncKeyService, key); err != nil {
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
