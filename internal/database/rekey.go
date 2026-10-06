package database

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

// ErrVaultKeyChanged means the vault's master password was changed after
// this command unlocked it: its key no longer opens the vault.
var ErrVaultKeyChanged = errors.New("the vault's master password was changed by another sesh command while this one ran; run this again")

// querier is a *sql.DB or a *sql.Tx.
type querier interface {
	QueryRow(query string, args ...any) *sql.Row
}

// unlockedID is the id of the key record the store's key was checked
// against, or "" when its key source can't say (a bare key, in tests).
func (s *Store) unlockedID() (string, error) {
	o, ok := s.oracle.(interface{ UnlockID() (string, error) })
	if !ok {
		return "", nil
	}
	return o.UnlockID()
}

// keyUnchanged returns ErrVaultKeyChanged unless the vault's key record,
// read through q, is the one the store's key was checked against.
func (s *Store) keyUnchanged(q querier) error {
	id, err := s.unlockedID()
	if err != nil || id == "" {
		return err
	}
	var verify []byte
	if err := q.QueryRow(`SELECT verify FROM vault_key WHERE id = 1`).Scan(&verify); err != nil {
		return fmt.Errorf("read the vault's key record: %w", err)
	}
	if UnlockID(verify) != id {
		return ErrVaultKeyChanged
	}
	return nil
}

// inTx runs f in a write transaction that first checks the vault's key is
// still the one the store's key was checked against, so nothing is written
// under a key a password change has replaced.
func (s *Store) inTx(f func(tx *sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if err := s.keyUnchanged(tx); err != nil {
		_ = tx.Rollback() //nolint:errcheck // already failing
		return err
	}
	if err := f(tx); err != nil {
		_ = tx.Rollback() //nolint:errcheck // already failing
		return err
	}
	return tx.Commit()
}

// RecoveryOutcome is what a password change did with the vault's recovery
// key record.
type RecoveryOutcome int

// The outcomes.
const (
	// RecoveryNone: the vault had no recovery key record.
	RecoveryNone RecoveryOutcome = iota
	// RecoveryKept: the record was re-wrapped to the new key.
	RecoveryKept
	// RecoveryRemoved: the record was removed, as a recovery asks.
	RecoveryRemoved
	// RecoveryStale: the record was for another vault, so it was removed.
	RecoveryStale
)

// RekeyResult reports a password change.
type RekeyResult struct {
	Entries  int
	Recovery RecoveryOutcome
}

// Rekey re-encrypts the vault in place under newKey, whose key record is
// rec, in one transaction: every entry, the key record, and the recovery
// key record, which rewrap re-wraps to the new key. The recovery key record
// is removed instead when rewrap is nil (a recovery, whose key has been
// used) or when it was made for another vault. Nothing changes unless all
// of it does, and the audit log is kept, with one event for the change.
//
// It refuses with ErrVaultKeyChanged when the vault's key isn't the one the
// store's key was checked against. Afterwards the store's key no longer
// opens the vault, so the caller closes it.
func (s *Store) Rekey(newKey []byte, rec UnlockMaterial, rewrap func(r *RecoveryRecord, newID string) (*RecoveryRecord, error)) (RekeyResult, error) {
	var res RekeyResult
	oldID, err := s.unlockedID()
	if err != nil {
		return res, err
	}
	if oldID == "" {
		return res, errors.New("change the master password: the key source doesn't say which vault it unlocked")
	}
	newID := UnlockID(rec.Verify)
	err = s.inTx(func(tx *sql.Tx) error {
		n, err := s.reencrypt(tx, newKey)
		if err != nil {
			return err
		}
		res.Entries = n
		if res.Recovery, err = rewrapRecoveryRecord(tx, oldID, newID, rewrap); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE vault_key SET salt = ?, kdf = ?, kdf_params = ?, verify = ? WHERE id = 1`,
			rec.Salt, kdfArgon2id, rec.Params.MarshalParams(), rec.Verify); err != nil {
			return fmt.Errorf("record the new key: %w", err)
		}
		entries := fmt.Sprintf("%d entries", n)
		if n == 1 {
			entries = "1 entry"
		}
		if _, err := tx.Exec(`INSERT INTO audit_log (event_type, entry_id, detail, created_at) VALUES ('rekey', NULL, ?, ?)`,
			"master password changed, "+entries+" re-encrypted", time.Now().UTC()); err != nil {
			return fmt.Errorf("log the change: %w", err)
		}
		return nil
	})
	return res, err
}

// reencrypt re-encrypts every entry in tx under newKey, and returns how
// many there were.
func (s *Store) reencrypt(tx *sql.Tx, newKey []byte) (int, error) {
	type row struct {
		k          vault.Key
		data, salt []byte
		id         int64
	}
	rows, err := tx.Query(`SELECT id, kind, service, username, encrypted_data, salt FROM entries`)
	if err != nil {
		return 0, fmt.Errorf("read entries: %w", err)
	}
	var all []row
	for rows.Next() {
		var r row
		var kind string
		if err := rows.Scan(&r.id, &kind, &r.k.Service, &r.k.Username, &r.data, &r.salt); err != nil {
			_ = rows.Close() //nolint:errcheck // already failing
			return 0, fmt.Errorf("read entries: %w", err)
		}
		r.k.Kind = vault.Kind(kind)
		all = append(all, r)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("read entries: %w", err)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("read entries: %w", err)
	}
	for _, r := range all {
		aad := entryAAD(r.k)
		plain, err := s.oracle.DecryptEntry(r.data, r.salt, aad)
		if err != nil {
			return 0, fmt.Errorf("decrypt %s: %w", r.k, err)
		}
		data, salt, err := EncryptEntry(newKey, plain, aad)
		secure.SecureZeroBytes(plain)
		if err != nil {
			return 0, fmt.Errorf("encrypt %s: %w", r.k, err)
		}
		if _, err := tx.Exec(`UPDATE entries SET encrypted_data = ?, salt = ? WHERE id = ?`, data, salt, r.id); err != nil {
			return 0, fmt.Errorf("store %s: %w", r.k, err)
		}
	}
	return len(all), nil
}

// rewrapRecoveryRecord re-wraps the recovery key record in tx from the key
// record oldID to newID with rewrap, or removes it (see Rekey).
func rewrapRecoveryRecord(tx *sql.Tx, oldID, newID string, rewrap func(*RecoveryRecord, string) (*RecoveryRecord, error)) (RecoveryOutcome, error) {
	r, err := scanRecovery(tx)
	if errors.Is(err, ErrNoRecovery) {
		return RecoveryNone, nil
	}
	if err != nil {
		return RecoveryNone, err
	}
	outcome := RecoveryKept
	switch {
	case r.UnlockID != oldID:
		outcome = RecoveryStale
	case rewrap == nil:
		outcome = RecoveryRemoved
	}
	if outcome != RecoveryKept {
		if _, err := tx.Exec(`DELETE FROM recovery`); err != nil {
			return outcome, fmt.Errorf("remove the recovery key record: %w", err)
		}
		return outcome, nil
	}
	nr, err := rewrap(r, newID)
	if err != nil {
		return outcome, fmt.Errorf("keep the recovery key: %w", err)
	}
	if err := putRecovery(tx, nr); err != nil {
		return outcome, err
	}
	return outcome, nil
}
