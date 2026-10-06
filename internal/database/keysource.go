package database

// encryptionKeyLength is the length in bytes of the master encryption key.
const encryptionKeyLength = 32

// KeySource provides the master encryption key: MasterPasswordSource
// derives it from the master password.
type KeySource interface {
	// GetEncryptionKey returns the master encryption key.
	// The caller must zero the returned slice after use.
	GetEncryptionKey() ([]byte, error)
}

// CryptoOracle encrypts and decrypts entry secrets without exposing the
// raw master key to the caller. Store depends only on this. The agent's
// key source implements it directly; a KeySource becomes one through
// NewKeySourceOracle.
type CryptoOracle interface {
	// EncryptEntry seals plaintext under the master key and returns the
	// ciphertext plus the per-entry salt.
	EncryptEntry(plaintext, aad []byte) (encryptedData, salt []byte, err error)

	// DecryptEntry opens a blob produced by EncryptEntry.
	DecryptEntry(encryptedData, salt, aad []byte) ([]byte, error)
}
