package database

import (
	"bytes"
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
	// NewID is the id of the vault's new key record.
	NewID    string
	Entries  int
	Recovery RecoveryOutcome
	// OldVaultInFile means another sesh command had the vault open, so the
	// change couldn't be folded into the vault file yet: until that command
	// ends, the file on its own still holds the vault under the old key.
	OldVaultInFile bool
}

// Rekey re-encrypts the vault in place under newKey, whose key record is
// rec, in one transaction: every entry's secret and details, the key record, and the recovery
// key record, which rewrap re-wraps to the new key. The recovery key record
// is removed instead when rewrap is nil (a recovery, whose key has been
// used) or when it was made for another vault. Nothing changes unless all
// of it does, and the audit log is kept, with one event for the change.
//
// The slow part, re-encrypting each entry, happens before the transaction,
// so other sesh commands wait for it only briefly; an entry saved in the
// meantime is re-encrypted inside it.
//
// It refuses with ErrVaultKeyChanged when the vault's key isn't the one the
// store's key was checked against. Afterwards the store's key no longer
// opens the vault, so the caller closes it.
func (s *Store) Rekey(newKey []byte, rec UnlockMaterial, rewrap func(r *RecoveryRecord, newID string) (*RecoveryRecord, error)) (RekeyResult, error) {
	res := RekeyResult{NewID: UnlockID(rec.Verify)}
	oldID, err := s.unlockedID()
	if err != nil {
		return res, err
	}
	if oldID == "" {
		return res, errors.New("change the master password: the key source doesn't say which vault it unlocked")
	}
	before, err := sealedEntries(s.db)
	if err != nil {
		return res, err
	}
	sealed := make(map[int64]sealedEntry, len(before))
	for i := range before {
		e := &before[i]
		if err := s.reseal(s.db, e, newKey); err != nil {
			return res, err
		}
		sealed[e.id] = *e
	}
	err = s.inTx(func(tx *sql.Tx) error {
		now, err := sealedEntries(tx)
		if err != nil {
			return err
		}
		for i := range now {
			e := &now[i]
			// An entry unchanged since it was re-encrypted ahead takes that;
			// one saved since is re-encrypted now.
			if done, ok := sealed[e.id]; ok && done.unchangedFrom(e) {
				*e = done
			} else if err := s.reseal(tx, e, newKey); err != nil {
				return err
			}
			if _, err := tx.Exec(`UPDATE entries SET encrypted_data = ?, salt = ?, sealed_details = ?, details_salt = ? WHERE id = ?`,
				e.data, e.salt, e.details, e.detailsSalt, e.id); err != nil {
				return fmt.Errorf("store %s: %w", e.k, err)
			}
		}
		res.Entries = len(now)
		if res.Recovery, err = rewrapRecoveryRecord(tx, oldID, res.NewID, rewrap); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE vault_key SET salt = ?, kdf = ?, kdf_params = ?, verify = ? WHERE id = 1`,
			rec.Salt, kdfArgon2id, rec.Params.MarshalParams(), rec.Verify); err != nil {
			return fmt.Errorf("record the new key: %w", err)
		}
		entries := fmt.Sprintf("%d entries", res.Entries)
		if res.Entries == 1 {
			entries = "1 entry"
		}
		if _, err := tx.Exec(`INSERT INTO audit_log (event_type, entry_id, detail, created_at) VALUES ('rekey', NULL, ?, ?)`,
			"master password changed, "+entries+" re-encrypted", time.Now().UTC()); err != nil {
			return fmt.Errorf("log the change: %w", err)
		}
		return nil
	})
	if err != nil {
		return res, fmt.Errorf("change the master password: %w", err)
	}
	// Fold the change into the vault file now, so a copy of the file alone
	// isn't the old vault. Another command with the vault open can hold
	// this off; the change is committed either way.
	var busy, logFrames, checkpointed int
	if err := s.db.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &checkpointed); err != nil || busy != 0 {
		res.OldVaultInFile = true
	}
	return res, nil
}

// sealedEntry is an entry's encrypted secret and details: as stored
// (data, salt, details, detailsSalt), and as stored before resealing (the
// old ones).
type sealedEntry struct {
	k                          vault.Key
	data, salt                 []byte
	details, detailsSalt       []byte
	oldData, oldSalt           []byte
	oldDetails, oldDetailsSalt []byte
	id                         int64
}

// unchangedFrom reports whether now, as stored, is what e was resealed
// from.
func (e *sealedEntry) unchangedFrom(now *sealedEntry) bool {
	return e.k == now.k && bytes.Equal(e.oldData, now.data) && bytes.Equal(e.oldSalt, now.salt) &&
		bytes.Equal(e.oldDetails, now.details) && bytes.Equal(e.oldDetailsSalt, now.detailsSalt)
}

// sealedEntries reads every entry's encrypted secret and details through q.
func sealedEntries(q interface {
	Query(query string, args ...any) (*sql.Rows, error)
}) (_ []sealedEntry, err error) {
	rows, err := q.Query(`SELECT id, kind, service, username, encrypted_data, salt, sealed_details, details_salt FROM entries`)
	if err != nil {
		return nil, fmt.Errorf("read entries: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("read entries: %w", cerr)
		}
	}()
	var all []sealedEntry
	for rows.Next() {
		var e sealedEntry
		var kind string
		if err := rows.Scan(&e.id, &kind, &e.k.Service, &e.k.Username, &e.data, &e.salt, &e.details, &e.detailsSalt); err != nil {
			return nil, fmt.Errorf("read entries: %w", err)
		}
		e.k.Kind = vault.Kind(kind)
		e.oldData, e.oldSalt = e.data, e.salt
		e.oldDetails, e.oldDetailsSalt = e.details, e.detailsSalt
		all = append(all, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read entries: %w", err)
	}
	return all, nil
}

// reseal decrypts e's secret and details with the store's key and
// encrypts them under newKey, into e. q is what the vault is read through:
// the transaction, inside one, since the store has a single connection.
func (s *Store) reseal(q querier, e *sealedEntry, newKey []byte) error {
	var err error
	if e.data, e.salt, err = s.resealOne(q, e.k, e.oldData, e.oldSalt, entryAAD(e.k), newKey, ""); err != nil {
		return err
	}
	if e.oldDetails != nil {
		if e.details, e.detailsSalt, err = s.resealOne(q, e.k, e.oldDetails, e.oldDetailsSalt, detailsAAD(e.k), newKey, "the details of "); err != nil {
			return err
		}
	}
	return nil
}

// resealOne decrypts one sealed value of k's, what in errors, with the
// store's key and encrypts it under newKey.
func (s *Store) resealOne(q querier, k vault.Key, data, salt, aad, newKey []byte, what string) (newData, newSalt []byte, err error) {
	plain, err := s.oracle.DecryptEntry(data, salt, aad)
	if err != nil {
		if kerr := s.keyUnchanged(q); errors.Is(kerr, ErrVaultKeyChanged) {
			err = kerr
		}
		return nil, nil, fmt.Errorf("decrypt %s%s: %w", what, k, err)
	}
	defer secure.SecureZeroBytes(plain)
	if newData, newSalt, err = EncryptEntry(newKey, plain, aad); err != nil {
		return nil, nil, fmt.Errorf("encrypt %s%s: %w", what, k, err)
	}
	return newData, newSalt, nil
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
