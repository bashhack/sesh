package database

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

// keyCheckPlaintext is what the vault's check value decrypts to under the
// vault's key.
const keyCheckPlaintext = "sesh vault key check v1"

// migrateV2 adds vault_key: one row holding a value encrypted with the
// vault's key, and the name of the key source that protects it. CheckKey
// uses it to refuse a key that can't open the vault before anything is
// read or written.
func migrateV2(tx *sql.Tx) error {
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS vault_key (
		id         INTEGER PRIMARY KEY CHECK (id = 1),
		key_source TEXT NOT NULL,
		check_data BLOB NOT NULL,
		check_salt BLOB NOT NULL,
		created_at DATETIME NOT NULL
	)`); err != nil {
		return fmt.Errorf("migration v2: %w", err)
	}
	return nil
}

// WrongKeyError means the key sesh is using can't open this vault. Writing
// with it would store entries the vault's real key can't read.
type WrongKeyError struct {
	// VaultSource is the key source the vault recorded ("keychain" or
	// "password"), or "" for a vault that predates the record.
	VaultSource string
	// Source is the key source in use.
	Source string
}

func (e *WrongKeyError) Error() string {
	switch {
	case e.VaultSource == "":
		return fmt.Sprintf("this vault's entries don't decrypt with the %s key", e.Source)
	case e.VaultSource != e.Source:
		return fmt.Sprintf("this vault uses the %s key source, but sesh is using %s", e.VaultSource, e.Source)
	default:
		return fmt.Sprintf("the %s key in use is not the one this vault was created with", e.Source)
	}
}

// CheckKey confirms the store's oracle holds this vault's key, and records
// the vault's check value if it has none yet. Callers run it right after
// Open, before any read or write. source names the key source in use
// ("keychain" or "password"), for the record and for errors.
//
// A vault with a check value must decrypt it. A vault without one is new,
// or predates the check: if it has entries, one of them must decrypt.
func (s *Store) CheckKey(source string) error {
	err := s.verifyKeyCheck(source)
	if !errors.Is(err, errNoKeyCheck) {
		return err
	}
	if err := s.verifyAnEntry(source); err != nil {
		return err
	}
	checkData, checkSalt, err := s.oracle.EncryptEntry([]byte(keyCheckPlaintext), nil)
	if err != nil {
		return fmt.Errorf("encrypt vault key check: %w", err)
	}
	// OR IGNORE: if another sesh recorded a check value first, verify
	// against that one instead.
	if _, err := s.db.Exec(
		`INSERT OR IGNORE INTO vault_key (id, key_source, check_data, check_salt, created_at) VALUES (1, ?, ?, ?, ?)`,
		source, checkData, checkSalt, time.Now().UTC(),
	); err != nil {
		return fmt.Errorf("record vault key check: %w", err)
	}
	return s.verifyKeyCheck(source)
}

// VerifyKey is CheckKey without the write: it never records a check value.
// Rekey and rotation use it on the vault they copy from, which a cancelled
// run must leave untouched.
func (s *Store) VerifyKey(source string) error {
	err := s.verifyKeyCheck(source)
	if !errors.Is(err, errNoKeyCheck) {
		return err
	}
	return s.verifyAnEntry(source)
}

// verifyAnEntry decrypts one entry, if the vault has any.
func (s *Store) verifyAnEntry(source string) error {
	var data, salt []byte
	var kind string
	var k vault.Key
	switch err := s.db.QueryRow(`SELECT kind, service, username, encrypted_data, salt FROM entries LIMIT 1`).Scan(&kind, &k.Service, &k.Username, &data, &salt); {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return fmt.Errorf("read an entry to check the vault key: %w", err)
	}
	k.Kind = vault.Kind(kind)
	plain, err := s.oracle.DecryptEntry(data, salt, entryAAD(k))
	secure.SecureZeroBytes(plain)
	if err != nil {
		return &WrongKeyError{Source: source}
	}
	return nil
}

// errNoKeyCheck means the vault has no check value yet.
var errNoKeyCheck = errors.New("vault has no key check")

// verifyKeyCheck decrypts the recorded check value with the store's
// oracle, returning errNoKeyCheck when there isn't one yet.
func (s *Store) verifyKeyCheck(source string) error {
	var recorded string
	var data, salt []byte
	if err := s.db.QueryRow(
		`SELECT key_source, check_data, check_salt FROM vault_key WHERE id = 1`,
	).Scan(&recorded, &data, &salt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errNoKeyCheck
		}
		return fmt.Errorf("read vault key check: %w", err)
	}
	plain, err := s.oracle.DecryptEntry(data, salt, nil)
	defer secure.SecureZeroBytes(plain)
	if err != nil || !bytes.Equal(plain, []byte(keyCheckPlaintext)) {
		return &WrongKeyError{VaultSource: recorded, Source: source}
	}
	return nil
}

// RecordedKeySource reads, without any key, the key source the vault at
// dbPath records in its key check ("password" or "keychain"). It's "" for
// a vault without a key check yet. The vault is opened read-only, and a
// missing file is an error rather than a new vault.
func RecordedKeySource(dbPath string) (_ string, err error) {
	if _, err := os.Stat(dbPath); err != nil {
		return "", err
	}
	db, err := sql.Open("sqlite", fileURI(dbPath, "mode=ro"))
	if err != nil {
		return "", fmt.Errorf("open vault: %w", err)
	}
	defer func() {
		if cerr := db.Close(); err == nil {
			err = cerr
		}
	}()
	var source string
	switch err := db.QueryRow(`SELECT key_source FROM vault_key WHERE id = 1`).Scan(&source); {
	case errors.Is(err, sql.ErrNoRows):
		return "", nil
	case err != nil && strings.Contains(err.Error(), "no such table"):
		return "", nil // a vault from before the key check
	case err != nil:
		return "", fmt.Errorf("read the vault's key source: %w", err)
	}
	return source, nil
}
