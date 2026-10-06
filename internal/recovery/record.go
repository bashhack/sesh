package recovery

import (
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
