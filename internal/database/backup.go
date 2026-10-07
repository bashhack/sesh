package database

import (
	"fmt"
	"strings"
)

// VaultID returns the vault's id: random, made with it, and never changed.
func VaultID(dbPath string) (_ string, err error) {
	db, err := openExisting(dbPath)
	if err != nil {
		return "", err
	}
	defer func() { err = closeVault(db, err) }()
	var id string
	if err := db.QueryRow(`SELECT vault_id FROM vault_info WHERE id = 1`).Scan(&id); err != nil {
		return "", damaged(fmt.Errorf("read the vault's id: %w", err))
	}
	return id, nil
}

// CopyTo writes a consistent copy of the vault at dbPath to dest, which
// must not exist: SQLite's VACUUM INTO, safe while other sesh commands use
// the vault. The copy holds what the vault does, secrets still encrypted,
// so making it needs no key. A vault SQLite's integrity check finds damaged
// is refused, so a damaged vault never replaces good backups. (The quick
// check doesn't compare indexes with their tables, and a personal vault is
// small enough for the full one.)
func CopyTo(dbPath, dest string) (err error) {
	db, err := openExisting(dbPath)
	if err != nil {
		return err
	}
	defer func() { err = closeVault(db, err) }()
	found, err := integrityCheck(db)
	if err != nil {
		return fmt.Errorf("check the vault before copying it: %w", err)
	}
	if len(found) > 0 {
		return damaged(fmt.Errorf("the vault is damaged (SQLite reports: %s), so it wasn't copied", strings.Join(found[:min(3, len(found))], "; ")))
	}
	if _, err := db.Exec(`VACUUM INTO ?`, dest); err != nil {
		return fmt.Errorf("copy the vault: %w", err)
	}
	return nil
}

// HasEntries reports whether the vault holds any entry, reading none.
func (s *Store) HasEntries() (bool, error) {
	var has bool
	if err := s.db.QueryRow(`SELECT EXISTS (SELECT 1 FROM entries)`).Scan(&has); err != nil {
		return false, fmt.Errorf("check for entries: %w", err)
	}
	return has, nil
}
