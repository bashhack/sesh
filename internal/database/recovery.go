package database

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"
)

// RecoveryRecord is what lets a recovery key open the vault: the recovery
// key's public key, and the vault key wrapped to it (internal/recovery).
// Nothing in it opens the vault without the written-down recovery key. A
// vault has at most one.
type RecoveryRecord struct {
	CreatedAt time.Time
	// UnlockID is the id of the key record the wrap is bound to.
	UnlockID     string
	PublicKey    []byte
	EphemeralPub []byte
	Ciphertext   []byte
}

// ErrNoRecovery means the vault has no recovery key.
var ErrNoRecovery = errors.New("this vault has no recovery key")

// ReadRecovery reads the recovery key record of the vault at dbPath:
// ErrNoRecovery when it has none, ErrNoVault when there's no vault there.
func ReadRecovery(dbPath string) (_ *RecoveryRecord, err error) {
	db, err := openExisting(dbPath)
	if err != nil {
		return nil, err
	}
	defer func() { err = closeVault(db, err) }()
	return scanRecovery(db)
}

// scanRecovery reads the recovery key record through q.
func scanRecovery(q querier) (*RecoveryRecord, error) {
	var r RecoveryRecord
	err := q.QueryRow(`SELECT unlock_id, public_key, ephemeral_pub, ciphertext, created_at FROM recovery WHERE id = 1`).
		Scan(&r.UnlockID, &r.PublicKey, &r.EphemeralPub, &r.Ciphertext, &r.CreatedAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, ErrNoRecovery
	case err != nil:
		return nil, fmt.Errorf("read the vault's recovery key record: %w", err)
	case r.UnlockID == "" || len(r.PublicKey) == 0 || len(r.EphemeralPub) == 0 || len(r.Ciphertext) == 0:
		return nil, errors.New("the vault's recovery key record is incomplete")
	}
	return &r, nil
}

// WriteRecovery makes r the recovery key record of the vault at dbPath,
// replacing any earlier one. It refuses with ErrVaultKeyChanged when r was
// made for a key record the vault no longer has.
func WriteRecovery(dbPath string, r *RecoveryRecord) (err error) {
	db, err := openExisting(dbPath)
	if err != nil {
		return err
	}
	defer func() { err = closeVault(db, err) }()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	var verify []byte
	if err := tx.QueryRow(`SELECT verify FROM vault_key WHERE id = 1`).Scan(&verify); err != nil {
		_ = tx.Rollback() //nolint:errcheck // already failing
		return fmt.Errorf("read the vault's key record: %w", err)
	}
	if UnlockID(verify) != r.UnlockID {
		_ = tx.Rollback() //nolint:errcheck // already failing
		return ErrVaultKeyChanged
	}
	if err := putRecovery(tx, r); err != nil {
		_ = tx.Rollback() //nolint:errcheck // already failing
		return err
	}
	return tx.Commit()
}

// putRecovery writes r as the recovery key record in tx.
func putRecovery(tx *sql.Tx, r *RecoveryRecord) error {
	if _, err := tx.Exec(`INSERT OR REPLACE INTO recovery (id, unlock_id, public_key, ephemeral_pub, ciphertext, created_at) VALUES (1, ?, ?, ?, ?, ?)`,
		r.UnlockID, r.PublicKey, r.EphemeralPub, r.Ciphertext, r.CreatedAt.UTC()); err != nil {
		return fmt.Errorf("save the recovery key record: %w", err)
	}
	return nil
}

// RemoveRecovery removes the recovery key record of the vault at dbPath,
// if it has one.
func RemoveRecovery(dbPath string) (err error) {
	db, err := openExisting(dbPath)
	if err != nil {
		return err
	}
	defer func() { err = closeVault(db, err) }()
	if _, err := db.Exec(`DELETE FROM recovery`); err != nil {
		return fmt.Errorf("remove the recovery key record: %w", err)
	}
	return nil
}

// openExisting opens the vault at dbPath, or returns ErrNoVault when there
// is no file there; it never creates one.
func openExisting(dbPath string) (*sql.DB, error) {
	switch _, err := os.Stat(dbPath); {
	case errors.Is(err, os.ErrNotExist):
		return nil, ErrNoVault
	case err != nil:
		return nil, fmt.Errorf("check for the vault: %w", err)
	}
	return openDB(dbPath)
}

// closeVault closes db and returns err, or the close's error if err is nil.
func closeVault(db *sql.DB, err error) error {
	if cerr := db.Close(); err == nil && cerr != nil {
		return fmt.Errorf("close the vault: %w", cerr)
	}
	return err
}
