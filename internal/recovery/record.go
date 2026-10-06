package recovery

import (
	"fmt"
	"time"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/keywrap"
)

// NewRecord assembles the recovery key record for the vault whose key
// record has the id unlockID, from a recovery key's public key and the
// vault key wrapped to it.
func NewRecord(unlockID string, publicKey []byte, w keywrap.Wrapped) *database.RecoveryRecord {
	return &database.RecoveryRecord{
		UnlockID:     unlockID,
		PublicKey:    publicKey,
		EphemeralPub: w.EphemeralPub,
		Ciphertext:   w.Ciphertext,
		CreatedAt:    time.Now().UTC(),
	}
}

// Wrapped returns the vault key wrapped in r.
func Wrapped(r *database.RecoveryRecord) keywrap.Wrapped {
	return keywrap.Wrapped{EphemeralPub: r.EphemeralPub, Ciphertext: r.Ciphertext}
}

// wrappedKeyLen is the length of a wrapped vault key: the AES-GCM nonce,
// the 32-byte key, and the tag.
const wrappedKeyLen = 12 + 32 + 16

// CheckRecord reports whether r is shaped like a record a recovery key can
// open: valid public keys, and a wrapped vault key of the right length.
// Whether the wrap itself is intact can only be known with the recovery
// key.
func CheckRecord(r *database.RecoveryRecord) error {
	if err := CheckPublicKey(r.PublicKey); err != nil {
		return fmt.Errorf("its public key: %w", err)
	}
	if err := CheckPublicKey(r.EphemeralPub); err != nil {
		return fmt.Errorf("its one-off public key: %w", err)
	}
	if len(r.Ciphertext) != wrappedKeyLen {
		return fmt.Errorf("its wrapped vault key is %d bytes, not %d", len(r.Ciphertext), wrappedKeyLen)
	}
	return nil
}
