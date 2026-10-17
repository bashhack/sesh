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

// SyncRecovery is the sync folder's recovery key record as the vault last
// saw it, taken or sent: a Count of 0 when it saw none.
func (s *Store) SyncRecovery() (syncfolder.Recovery, error) {
	return syncRecoverySeen(s.db)
}

func syncRecoverySeen(q querier) (syncfolder.Recovery, error) {
	var r syncfolder.Recovery
	var made sql.NullTime
	err := q.QueryRow(`SELECT recovery_count, recovery_key, recovery_made, recovery_by FROM sync_info WHERE id = 1`).
		Scan(&r.Count, &r.PublicKey, &made, &r.Computer)
	if errors.Is(err, sql.ErrNoRows) {
		return syncfolder.Recovery{}, nil
	}
	if err != nil {
		return syncfolder.Recovery{}, fmt.Errorf("read the sync folder's recovery key record as the vault saw it: %w", err)
	}
	if len(r.PublicKey) == 0 {
		r.PublicKey = nil
	}
	r.Made = made.Time
	return r, nil
}

// VaultSyncRecovery is the vault at dbPath's SyncRecovery, read without
// unlocking it.
func VaultSyncRecovery(dbPath string) (_ syncfolder.Recovery, err error) {
	db, err := openExisting(dbPath)
	if errors.Is(err, ErrNoVault) {
		return syncfolder.Recovery{}, nil
	}
	if err != nil {
		return syncfolder.Recovery{}, err
	}
	defer func() { err = closeVault(db, err) }()
	return syncRecoverySeen(db)
}

// Recovery is the vault's recovery key record: ErrNoRecovery when it has
// none.
func (s *Store) Recovery() (*RecoveryRecord, error) { return scanRecovery(s.db) }

// SyncRecoverySent records r as the sync folder's recovery key record, the
// vault's own, written there.
func (s *Store) SyncRecoverySent(r syncfolder.Recovery) error {
	return s.inTx(func(tx *sql.Tx) error { return putRecoverySeen(tx, r) })
}

// SyncTakeRecovery makes rec, nil for none, the vault's recovery key record,
// and r the folder's as the vault saw it, in one transaction; rec is for
// the vault's key record as it is. had is the public key of the vault's
// record the sync looked at (nil for none): when it isn't that any more,
// nothing changes (ErrRecoveryChanged).
func (s *Store) SyncTakeRecovery(r syncfolder.Recovery, rec *RecoveryRecord, had []byte) error {
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

func putRecoverySeen(tx *sql.Tx, r syncfolder.Recovery) error {
	var made any
	if !r.Made.IsZero() {
		made = r.Made.UTC()
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO sync_info (id, computer_id) VALUES (1, lower(hex(randomblob(8))))`); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE sync_info SET recovery_count = ?, recovery_key = ?, recovery_made = ?, recovery_by = ? WHERE id = 1`,
		r.Count, recoveryKeyBytes(r.PublicKey), made, r.Computer); err != nil {
		return fmt.Errorf("keep the sync folder's recovery key record: %w", err)
	}
	return nil
}

// recoveryKeyBytes is pub as recovery_key holds it: empty, not NULL, for
// none.
func recoveryKeyBytes(pub []byte) []byte {
	if pub == nil {
		return []byte{}
	}
	return pub
}

// noRecoverySeen is what sync_info holds of a folder's recovery key record
// the vault hasn't seen: none.
const noRecoverySeen = `recovery_count = 0, recovery_key = x'', recovery_made = NULL, recovery_by = ''`
