package database

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// The vault's key record is the one row of vault_key: what turns the master
// password into the vault's key. It holds a random salt, the Argon2id
// settings, and verify, a known phrase encrypted with the key, which tells
// a wrong password from the right one before any entry is read. None of it
// is secret: without the password it opens nothing.

// kdfArgon2id is the key record's kdf for Argon2id, the only one.
const kdfArgon2id = "argon2id"

// UnlockMaterial is the vault's key record: what an unlock derives the key
// from and checks it against. Nothing here is the key.
type UnlockMaterial struct {
	Salt   []byte
	Verify []byte
	Params Argon2idParams
}

// UnlockID names a vault's key record by its verify blob: the hex SHA-256
// of it. The blob is stored in the vault, so the id is not a secret. A
// password change gives the vault a new one.
func UnlockID(verify []byte) string {
	sum := sha256.Sum256(verify)
	return hex.EncodeToString(sum[:])
}

// CheckKey confirms that the store's oracle holds this vault's key: that
// the key record it was checked against is the one in the file the store
// has open. The vault's key can change between unlocking and opening, when
// another sesh command changes the master password; entries written then
// would be unreadable with the new key.
// Callers run it right after Open, before any read or write.
func (s *Store) CheckKey() error {
	o, ok := s.oracle.(interface{ UnlockID() (string, error) })
	if !ok {
		return errors.New("check the vault's key: the key source doesn't say which vault it unlocked")
	}
	id, err := o.UnlockID()
	if err != nil {
		return err
	}
	m, err := readKeyRecord(s.db, s.path)
	if err != nil {
		return err
	}
	if UnlockID(m.Verify) != id {
		return fmt.Errorf("the vault at %s changed while sesh was unlocking it (another sesh command changed its master password); run this again", s.path)
	}
	return nil
}

// ErrNoVault means there is no vault at the path yet, or one whose master
// password was never set: the next open creates it.
var ErrNoVault = errors.New("no vault yet")

// ReadUnlockMaterial reads the key record of the vault at dbPath, without
// any key. It returns ErrNoVault when there is no vault there yet, and
// never creates one.
func ReadUnlockMaterial(dbPath string) (_ UnlockMaterial, err error) {
	db, err := openExisting(dbPath)
	if err != nil {
		return UnlockMaterial{}, err
	}
	defer func() { err = closeVault(db, err) }()
	return readKeyRecord(db, dbPath)
}

// readKeyRecord reads and checks the key record. A vault without one is
// new (ErrNoVault), unless it holds entries: then the record was lost, and
// a new one would make a key that can't read them.
func readKeyRecord(db *sql.DB, dbPath string) (UnlockMaterial, error) {
	var m UnlockMaterial
	var kdf, params string
	err := db.QueryRow(`SELECT salt, kdf, kdf_params, verify FROM vault_key WHERE id = 1`).Scan(&m.Salt, &kdf, &params, &m.Verify)
	if errors.Is(err, sql.ErrNoRows) {
		var hasEntries bool
		if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM entries)`).Scan(&hasEntries); err != nil {
			return UnlockMaterial{}, fmt.Errorf("read the vault: %w", err)
		}
		if hasEntries {
			return UnlockMaterial{}, damaged(fmt.Errorf("the vault at %s holds entries but not the record its key is made from, so it can't be opened; restore it from a backup", dbPath))
		}
		return UnlockMaterial{}, ErrNoVault
	}
	if err != nil {
		return UnlockMaterial{}, fmt.Errorf("read the vault's key record: %w", err)
	}
	if kdf != kdfArgon2id {
		return UnlockMaterial{}, damaged(fmt.Errorf("the vault's key record uses %q, which this sesh doesn't support", kdf))
	}
	if m.Params, err = UnmarshalArgon2idParams(params); err != nil {
		return UnlockMaterial{}, damaged(fmt.Errorf("the vault's key record: %w", err))
	}
	if err := ValidateUnlockMaterial(m.Salt, m.Verify, m.Params); err != nil {
		return UnlockMaterial{}, damaged(fmt.Errorf("the vault's key record: %w", err))
	}
	return m, nil
}

// writeKeyRecord records m as the vault's key record, unless it already
// has one or holds entries; it reports whether m was recorded.
func writeKeyRecord(db *sql.DB, m UnlockMaterial) (bool, error) {
	res, err := db.Exec(
		`INSERT INTO vault_key (id, salt, kdf, kdf_params, verify, created_at)
		 SELECT 1, ?, ?, ?, ?, ?
		 WHERE NOT EXISTS (SELECT 1 FROM vault_key) AND NOT EXISTS (SELECT 1 FROM entries)`,
		m.Salt, kdfArgon2id, m.Params.MarshalParams(), m.Verify, time.Now().UTC(),
	)
	if err != nil {
		return false, fmt.Errorf("record the vault's key: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("record the vault's key: %w", err)
	}
	return n == 1, nil
}
