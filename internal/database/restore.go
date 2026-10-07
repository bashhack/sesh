package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// BackupSummary is what InspectBackup found in a backup: whose it is, and
// how many entries it holds.
type BackupSummary struct {
	VaultID string
	Entries int
}

// openReadOnly opens the SQLite file at path without writing to it: no
// schema change, no journal mode, nothing beside it.
func openReadOnly(path string) (*sql.DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", fileURI(path, "mode=ro&_pragma=busy_timeout(5000)"))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

// InspectBackup checks that the file at path is a sound sesh vault this
// build can restore: its schema is this build's, SQLite's integrity check
// passes, and it has a key record and an id. It never writes to the file.
func InspectBackup(path string) (_ BackupSummary, err error) {
	db, err := openReadOnly(path)
	if err != nil {
		return BackupSummary{}, fmt.Errorf("open the backup: %w", err)
	}
	defer func() { err = closeVault(db, err) }()
	var version int
	if err := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version); err != nil {
		return BackupSummary{}, fmt.Errorf("%s isn't a sesh vault: %w", filepath.Base(path), err)
	}
	if version != currentSchemaVersion {
		return BackupSummary{}, fmt.Errorf("%s was made by a sesh with vault format %d; this one reads %d", filepath.Base(path), version, currentSchemaVersion)
	}
	found, err := integrityCheck(db)
	if err != nil {
		return BackupSummary{}, fmt.Errorf("check the backup: %w", err)
	}
	if len(found) > 0 {
		return BackupSummary{}, damaged(fmt.Errorf("the backup is damaged (SQLite reports: %s)", strings.Join(found[:min(3, len(found))], "; ")))
	}
	if _, err := readKeyRecord(db, path); err != nil {
		if errors.Is(err, ErrNoVault) {
			return BackupSummary{}, fmt.Errorf("the backup has no key record, so it can't be opened")
		}
		return BackupSummary{}, err
	}
	var s BackupSummary
	if err := db.QueryRow(`SELECT vault_id FROM vault_info WHERE id = 1`).Scan(&s.VaultID); err != nil {
		return BackupSummary{}, damaged(fmt.Errorf("read the backup's id: %w", err))
	}
	if err := db.QueryRow(`SELECT count(*) FROM entries`).Scan(&s.Entries); err != nil {
		return BackupSummary{}, fmt.Errorf("count the backup's entries: %w", err)
	}
	return s, nil
}

// VaultSummary is InspectBackup for the vault itself, read only: its id and
// entries, or an error saying why it can't be read (damaged, or missing:
// ErrNoVault).
func VaultSummary(dbPath string) (BackupSummary, error) {
	if _, err := os.Stat(dbPath); errors.Is(err, os.ErrNotExist) {
		return BackupSummary{}, ErrNoVault
	}
	return InspectBackup(dbPath)
}

// restoredTables are the tables a restore takes from the backup: all but
// the audit log, which keeps what happened, and the schema version, which
// is the same.
var restoredTables = []string{"vault_info", "vault_key", "recovery", "entries", "entry_tags"}

// RestoreFrom replaces the vault at dbPath with the backup at backupPath,
// which InspectBackup has passed.
//
// A sound vault is replaced in place, in one transaction: every table but
// the audit log comes from the backup, and a "restore" event is added. A
// sesh command with the vault open never sees a half-restored vault, and
// one that unlocked it before is refused its next write if the key changed
// (ErrVaultKeyChanged).
//
// A vault that's missing or damaged is replaced whole: the backup is
// copied beside it and renamed over it, with its own audit log, after
// removing the vault's -wal and -shm files, which SQLite would otherwise
// apply to the copy. No sesh command should be using it then. inPlace says
// which happened.
func RestoreFrom(dbPath, backupPath string) (inPlace bool, err error) {
	if _, err := VaultSummary(dbPath); err == nil {
		return true, restoreInPlace(dbPath, backupPath)
	}
	return false, replaceWhole(dbPath, backupPath)
}

func restoreInPlace(dbPath, backupPath string) (err error) {
	db, err := openExisting(dbPath)
	if err != nil {
		return err
	}
	defer func() { err = closeVault(db, err) }()
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := conn.Close(); err == nil && cerr != nil {
			err = cerr
		}
	}()
	// ATTACH can't run inside a transaction; the backup is read only.
	if _, err := conn.ExecContext(ctx, `ATTACH DATABASE ? AS backup`, fileURI(backupPath, "mode=ro")); err != nil {
		return fmt.Errorf("open the backup: %w", err)
	}
	defer func() {
		if _, derr := conn.ExecContext(ctx, `DETACH DATABASE backup`); err == nil && derr != nil {
			err = derr
		}
	}()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	// Children first, then parents, so the entries' tags go before them.
	for _, t := range slices.Backward(restoredTables) {
		if _, err := tx.Exec(`DELETE FROM main.` + t); err != nil { //nolint:gosec // t is one of restoredTables
			_ = tx.Rollback() //nolint:errcheck // already failing
			return fmt.Errorf("restore: %w", err)
		}
	}
	for _, t := range restoredTables {
		if _, err := tx.Exec(`INSERT INTO main.` + t + ` SELECT * FROM backup.` + t); err != nil { //nolint:gosec // t is one of restoredTables
			_ = tx.Rollback() //nolint:errcheck // already failing
			return fmt.Errorf("restore %s: %w", t, err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO main.audit_log (event_type, entry_id, detail, created_at) VALUES ('restore', NULL, ?, ?)`,
		"from "+filepath.Base(backupPath), time.Now().UTC()); err != nil {
		_ = tx.Rollback() //nolint:errcheck // already failing
		return fmt.Errorf("restore: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	// Fold the change into the vault file, as a password change does.
	_, _ = conn.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`) //nolint:errcheck // best effort; SQLite folds it in later
	return nil
}

func replaceWhole(dbPath, backupPath string) (err error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return fmt.Errorf("create the vault's folder: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dbPath), "."+filepath.Base(dbPath)+".*.restore")
	if err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() //nolint:errcheck // gone once renamed
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	src, err := openReadOnly(backupPath)
	if err != nil {
		return fmt.Errorf("open the backup: %w", err)
	}
	if _, err := src.Exec(`VACUUM INTO ?`, tmpPath); err != nil {
		_ = src.Close() //nolint:errcheck // already failing
		return fmt.Errorf("copy the backup: %w", err)
	}
	if err := src.Close(); err != nil {
		return err
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(dbPath + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove the vault's %s file: %w", suffix, err)
		}
	}
	if err := os.Rename(tmpPath, dbPath); err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	db, err := openExisting(dbPath)
	if err != nil {
		return err
	}
	defer func() { err = closeVault(db, err) }()
	if _, err := db.Exec(`INSERT INTO audit_log (event_type, entry_id, detail, created_at) VALUES ('restore', NULL, ?, ?)`,
		"from "+filepath.Base(backupPath)+", replacing a damaged or missing vault", time.Now().UTC()); err != nil {
		return fmt.Errorf("record the restore: %w", err)
	}
	return nil
}
