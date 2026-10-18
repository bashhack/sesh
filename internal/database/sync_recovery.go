package database

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"

	"github.com/bashhack/sesh/internal/syncfolder"
)

// ErrRecoveryChanged means the vault's recovery key record changed (another
// sesh command made or removed one) while a sync was taking the folder's:
// nothing was taken, and the next sync looks again.
var ErrRecoveryChanged = errors.New("the vault's recovery key changed meanwhile")

// SeenRecovery is the sync folder's recovery key record as the vault last
// saw it, taken or sent: a Count of 0 when it saw none.
type SeenRecovery struct {
	// RestoredKey: see Restored.
	RestoredKey []byte
	syncfolder.Recovery
	// Mine says this vault sent it. Earlier says the folder's record goes
	// before it: it was seen under a key the vault had before a master
	// password change it took from another computer (someone who knew the
	// old password could have made it). Restored says the vault's own
	// record was put back by a restore since, with the key RestoredKey
	// (nil for none): while it's that one, it isn't a change to send, and
	// the folder's (or this one) is taken in its place.
	Mine, Earlier, Restored bool
}

// SyncRecovery is the sync folder's recovery key record as the vault last
// saw it.
func (s *Store) SyncRecovery() (SeenRecovery, error) {
	return syncRecoverySeen(s.db)
}

func syncRecoverySeen(q querier) (SeenRecovery, error) {
	var r SeenRecovery
	var made sql.NullTime
	err := q.QueryRow(`SELECT recovery_count, recovery_key, recovery_made, recovery_by, recovery_prior_count, recovery_prior_key, recovery_mine, recovery_earlier, recovery_restored, recovery_restored_key FROM sync_info WHERE id = 1`).
		Scan(&r.Count, &r.PublicKey, &made, &r.Computer, &r.PriorCount, &r.PriorKey, &r.Mine, &r.Earlier, &r.Restored, &r.RestoredKey)
	if errors.Is(err, sql.ErrNoRows) {
		return SeenRecovery{}, nil
	}
	if err != nil {
		return SeenRecovery{}, fmt.Errorf("read the sync folder's recovery key record as the vault saw it: %w", err)
	}
	if len(r.PublicKey) == 0 {
		r.PublicKey = nil
	}
	if len(r.PriorKey) == 0 {
		r.PriorKey = nil
	}
	if len(r.RestoredKey) == 0 {
		r.RestoredKey = nil
	}
	r.Made = made.Time
	return r, nil
}

// VaultSyncRecovery is the vault at dbPath's SyncRecovery, read without
// unlocking it.
func VaultSyncRecovery(dbPath string) (_ SeenRecovery, err error) {
	db, err := openExisting(dbPath)
	if errors.Is(err, ErrNoVault) {
		return SeenRecovery{}, nil
	}
	if err != nil {
		return SeenRecovery{}, err
	}
	defer func() { err = closeVault(db, err) }()
	return syncRecoverySeen(db)
}

// Recovery is the vault's recovery key record: ErrNoRecovery when it has
// none.
func (s *Store) Recovery() (*RecoveryRecord, error) { return scanRecovery(s.db) }

// SyncRecoverySent records r as the sync folder's recovery key record, the
// vault's own, written there.
func (s *Store) SyncRecoverySent(r *syncfolder.Recovery) error {
	return s.inTx(func(tx *sql.Tx) error { return putRecoverySeen(tx, &SeenRecovery{Recovery: *r, Mine: true}) })
}

// SyncTakeRecovery makes rec, nil for none, the vault's recovery key record,
// and r the folder's as the vault saw it, in one transaction; rec is for
// the vault's key record as it is. had is the public key of the vault's
// record the sync looked at (nil for none): when it isn't that any more,
// nothing changes (ErrRecoveryChanged).
func (s *Store) SyncTakeRecovery(r *SeenRecovery, rec *RecoveryRecord, had []byte) error {
	return s.inTx(func(tx *sql.Tx) error {
		now, err := scanRecovery(tx)
		switch {
		case errors.Is(err, ErrNoRecovery):
			now = nil
		case err != nil:
			return err
		}
		if !bytes.Equal(recoveryPublicKey(now), had) {
			return ErrRecoveryChanged
		}
		if rec == nil {
			if _, err := tx.Exec(`DELETE FROM recovery`); err != nil {
				return fmt.Errorf("remove the recovery key record: %w", err)
			}
		} else {
			var verify []byte
			if err := tx.QueryRow(`SELECT verify FROM vault_key WHERE id = 1`).Scan(&verify); err != nil {
				return fmt.Errorf("read the vault's key record: %w", err)
			}
			if UnlockID(verify) != rec.UnlockID {
				return ErrVaultKeyChanged
			}
			if err := putRecovery(tx, rec); err != nil {
				return err
			}
		}
		return putRecoverySeen(tx, r)
	})
}

// recoveryPublicKey is r's public key, nil for no record.
func recoveryPublicKey(r *RecoveryRecord) []byte {
	if r == nil {
		return nil
	}
	return r.PublicKey
}

func putRecoverySeen(tx *sql.Tx, r *SeenRecovery) error {
	var made any
	if !r.Made.IsZero() {
		made = r.Made.UTC()
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO sync_info (id, computer_id) VALUES (1, lower(hex(randomblob(8))))`); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE sync_info SET recovery_count = ?, recovery_key = ?, recovery_made = ?, recovery_by = ?,
		recovery_prior_count = ?, recovery_prior_key = ?, recovery_mine = ?, recovery_earlier = ?, recovery_restored = ?, recovery_restored_key = ? WHERE id = 1`,
		r.Count, recoveryKeyBytes(r.PublicKey), made, r.Computer, r.PriorCount, recoveryKeyBytes(r.PriorKey), r.Mine, r.Earlier, r.Restored, recoveryKeyBytes(r.RestoredKey)); err != nil {
		return fmt.Errorf("keep the sync folder's recovery key record: %w", err)
	}
	return nil
}

// recoveryKeyBytes is pub as sync_info holds it: empty, not NULL, for none.
func recoveryKeyBytes(pub []byte) []byte {
	if pub == nil {
		return []byte{}
	}
	return pub
}

// noRecoverySeen is what sync_info holds of a folder's recovery key record
// the vault hasn't seen: none.
const noRecoverySeen = `recovery_count = 0, recovery_key = x'', recovery_made = NULL, recovery_by = '',
	recovery_prior_count = 0, recovery_prior_key = x'', recovery_mine = 0, recovery_earlier = 0, recovery_restored = 0, recovery_restored_key = x''`
