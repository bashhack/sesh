package keychain

import "time"

// Provider defines the interface for credential storage operations.
// Implementations include the macOS system keychain and the SQLite store.
type Provider interface {
	// GetSecret retrieves a secret as a byte slice.
	// The returned byte slice should be zeroed after use with secure.SecureZeroBytes.
	GetSecret(account, service string) ([]byte, error)

	// SetSecret stores a secret as a byte slice.
	SetSecret(account, service string, secret []byte) error

	// GetSecretString retrieves a secret as a string.
	// Less secure than GetSecret — use only when necessary.
	GetSecretString(account, service string) (string, error)

	// SetSecretString stores a string secret.
	// Less secure than SetSecret — use only when necessary.
	SetSecretString(account, service, secret string) error

	// GetMFASerialBytes retrieves the MFA serial as bytes.
	GetMFASerialBytes(account, profile string) ([]byte, error)

	// ListEntries lists all entries whose service key starts with the given prefix.
	ListEntries(service string) ([]KeychainEntry, error)

	// DeleteEntry removes an entry.
	DeleteEntry(account, service string) error

	// SetDescription sets a human-readable description on an existing entry.
	SetDescription(service, account, description string) error
}

// TimestampedStore is an optional interface for stores that can persist
// explicit create/update timestamps on write, instead of always using the
// current wall clock. The vault implements it.
//
// Callers should use a type assertion to detect support:
//
//	if ts, ok := provider.(keychain.TimestampedStore); ok {
//	    ts.SetSecretAt(...)
//	}
//
// Zero-valued timestamps passed to these methods mean "use now" — matching
// the non-timestamped path exactly.
type TimestampedStore interface {
	// SetSecretAt stores a secret with explicit create/update timestamps.
	SetSecretAt(account, service string, secret []byte, createdAt, updatedAt time.Time) error
	// SetDescriptionAt sets a description and stamps the entry's updated_at
	// with the given timestamp instead of the current time.
	SetDescriptionAt(service, account, description string, updatedAt time.Time) error
}

// KeychainEntry represents an entry in the credential store.
type KeychainEntry struct {
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Service     string
	Account     string
	Description string
}
