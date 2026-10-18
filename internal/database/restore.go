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

	"github.com/bashhack/sesh/internal/syncfolder"
)

// BackupSummary is what InspectBackup found in a backup: whose it is, and
// how many entries it holds.
type BackupSummary struct {
	VaultID string
	// Entries is how many entries the backup holds; Trashed, how many of
	// its entries are in the trash.
	Entries, Trashed int
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
func InspectBackup(path string) (BackupSummary, error) {
	return inspect(path, "the backup")
}

// VaultSummary is InspectBackup for the vault itself, read only: its id and
// entries, or why it can't be read. A vault that's missing, or new (no key
// record and no entries), is ErrNoVault; a damaged one, IsDamaged.
func VaultSummary(dbPath string) (BackupSummary, error) {
	if _, err := os.Stat(dbPath); errors.Is(err, os.ErrNotExist) {
		return BackupSummary{}, ErrNoVault
	}
	return inspect(dbPath, "the vault")
}

// inspect checks the vault file at path; what names it in errors.
func inspect(path, what string) (_ BackupSummary, err error) {
	db, err := openReadOnly(path)
	if err != nil {
		return BackupSummary{}, fmt.Errorf("open %s: %w", what, err)
	}
	defer func() { err = closeVault(db, err) }()
	var version int
	if err := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version); err != nil {
		if IsDamaged(err) {
			return BackupSummary{}, damaged(fmt.Errorf("%s isn't a sesh vault, or is damaged: %w", what, err))
		}
		return BackupSummary{}, fmt.Errorf("%s isn't a sesh vault: %w", what, err)
	}
	if version != currentSchemaVersion {
		return BackupSummary{}, fmt.Errorf("%s was made by a sesh with vault format %d; this one reads %d", what, version, currentSchemaVersion)
	}
	found, err := integrityCheck(db)
	if err != nil {
		return BackupSummary{}, fmt.Errorf("check %s: %w", what, err)
	}
	if len(found) > 0 {
		return BackupSummary{}, damaged(fmt.Errorf("%s is damaged (SQLite reports: %s)", what, strings.Join(found[:min(3, len(found))], "; ")))
	}
	if _, err := readKeyRecord(db, path); err != nil {
		if errors.Is(err, ErrNoVault) && what == "the backup" {
			return BackupSummary{}, fmt.Errorf("the backup has no key record, so it can't be opened")
		}
		return BackupSummary{}, err
	}
	var s BackupSummary
	if err := db.QueryRow(`SELECT vault_id FROM vault_info WHERE id = 1`).Scan(&s.VaultID); err != nil {
		return BackupSummary{}, damaged(fmt.Errorf("read the id of %s: %w", what, err))
	}
	if err := db.QueryRow(`SELECT (SELECT count(*) FROM entries), (SELECT count(*) FROM trash)`).Scan(&s.Entries, &s.Trashed); err != nil {
		return BackupSummary{}, fmt.Errorf("count the entries in %s: %w", what, err)
	}
	return s, nil
}

// restoredTables are the tables a restore takes from the backup: all but
// the audit log, which keeps what happened, the schema version, which is
// the same, quiet_writes, which is empty outside a write, and what sync
// keeps: sync_state (what this computer last agreed with the sync folder
// doesn't go back with the entries, so the restored ones, their revs
// raised, are changes to sync; restoredForSync readies it), sync_info (this
// computer's sync ID is its own), history_forgotten (what was forgotten
// on purpose stays forgotten) and key_links (the master password changes
// stay known, so files sealed with an old key still open).
var restoredTables = []string{"vault_info", "vault_key", "recovery", "entries", "entry_tags", "trash", "history"}

// RestoreInPlace replaces the sound vault at dbPath with the backup at
// backupPath, which InspectBackup has passed, in one transaction: every
// table but the audit log comes from the backup, and a "restore" event is
// added. A sesh command with the vault open never sees a half-restored
// vault, and one that unlocked it before is refused its next write if the
// key changed (ErrVaultKeyChanged). Once the transaction commits, the
// restore stands: tidying up after it only warns.
func RestoreInPlace(dbPath, backupPath string) error {
	return restoreInPlace(dbPath, backupPath)
}

func restoreInPlace(dbPath, backupPath string) (err error) {
	db, err := openExisting(dbPath)
	if err != nil {
		return err
	}
	// After the commit, closing up only warns: the vault is restored.
	committed := false
	defer func() {
		if err != nil && committed {
			fmt.Fprintf(os.Stderr, "warning: after the restore: %v\n", err) //nolint:errcheck // best-effort warning
			err = nil
		}
	}()
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
	// The entries are put back as the backup has them, but for their revs:
	// a rev never goes down, so each is raised above any this vault had,
	// the restore a change to every entry. The writes are quiet, so
	// that's all they raise.
	var revs int64
	if err := tx.QueryRow(`SELECT MAX((SELECT COALESCE(MAX(rev), 0) FROM main.entries), (SELECT COALESCE(MAX(rev), 0) FROM main.trash))`).Scan(&revs); err != nil {
		_ = tx.Rollback() //nolint:errcheck // already failing
		return fmt.Errorf("restore: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO main.quiet_writes (id) VALUES (1)`); err != nil {
		_ = tx.Rollback() //nolint:errcheck // already failing
		return fmt.Errorf("restore: %w", err)
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
	for _, t := range []string{"entries", "trash"} {
		if _, err := tx.Exec(`UPDATE main.`+t+` SET rev = rev + ?, changed_at = ?`, revs, time.Now().UTC()); err != nil { //nolint:gosec // t is entries or trash
			_ = tx.Rollback() //nolint:errcheck // already failing
			return fmt.Errorf("restore: %w", err)
		}
	}
	if err := restoredForSync(tx, "main.", "backup."); err != nil {
		_ = tx.Rollback() //nolint:errcheck // already failing
		return fmt.Errorf("restore: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM main.quiet_writes`); err != nil {
		_ = tx.Rollback() //nolint:errcheck // already failing
		return fmt.Errorf("restore: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO main.audit_log (event_type, entry_id, detail, created_at) VALUES ('restore', NULL, ?, ?)`,
		"from "+filepath.Base(backupPath), time.Now().UTC()); err != nil {
		_ = tx.Rollback() //nolint:errcheck // already failing
		return fmt.Errorf("restore: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	committed = true
	// Fold the change into the vault file, as a password change does.
	_, _ = conn.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`) //nolint:errcheck // best effort; SQLite folds it in later
	return nil
}

// staleRestoreTemp is how old a temporary file from a restore cut short
// must be before a later restore removes it.
const staleRestoreTemp = time.Hour

// ReplaceVault replaces the vault at dbPath, missing or damaged, with a
// copy of the backup at backupPath, which InspectBackup has passed. A
// vault there is moved aside, never deleted: to <vault>.before-restore-<time>,
// with its -wal and -shm, so what can still be read of it isn't lost, and
// its returned path says where. The -wal and -shm go with it rather than
// staying, where SQLite would apply them to the copy. A symlinked vault is
// replaced where it really is. No sesh command should be using the vault
// meanwhile. Once the copy is in place the restore stands: recording it
// only warns.
func ReplaceVault(dbPath, backupPath string, now time.Time) (aside string, err error) {
	target := dbPath
	if resolved, err := filepath.EvalSymlinks(dbPath); err == nil {
		target = resolved
	}
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create the vault's folder: %w", err)
	}
	removeStaleRestoreTemps(target, now)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(target)+".*.restore")
	if err != nil {
		return "", fmt.Errorf("restore: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() //nolint:errcheck // gone once renamed
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("restore: %w", err)
	}
	src, err := openReadOnly(backupPath)
	if err != nil {
		return "", fmt.Errorf("open the backup: %w", err)
	}
	if _, err := src.Exec(`VACUUM INTO ?`, tmpPath); err != nil {
		_ = src.Close() //nolint:errcheck // already failing
		return "", fmt.Errorf("copy the backup: %w", err)
	}
	if err := src.Close(); err != nil {
		return "", err
	}
	// The backup's sync ID and change count may be another computer's, or
	// this one's from before changes it has made since: it gets a new one.
	if err := replacedForSync(tmpPath); err != nil {
		return "", fmt.Errorf("restore: %w", err)
	}
	if _, err := os.Lstat(target); err == nil {
		aside = target + ".before-restore-" + now.UTC().Format("2006-01-02T150405Z")
		if err := os.Rename(target, aside); err != nil {
			return "", fmt.Errorf("move the vault aside: %w", err)
		}
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Lstat(target + suffix); err != nil {
			continue
		}
		var err error
		if aside != "" {
			err = os.Rename(target+suffix, aside+suffix)
		} else {
			err = os.Remove(target + suffix)
		}
		if err != nil {
			return aside, fmt.Errorf("move the vault's %s file aside: %w", suffix, err)
		}
	}
	if err := os.Rename(tmpPath, target); err != nil {
		return aside, fmt.Errorf("restore: %w", err)
	}
	if err := recordRestore(target, backupPath); err != nil {
		fmt.Fprintf(os.Stderr, "warning: record the restore in the audit log: %v\n", err) //nolint:errcheck // best-effort warning
	}
	return aside, nil
}

// recordRestore adds a restore event to the restored vault at path.
func recordRestore(path, backupPath string) (err error) {
	db, err := openExisting(path)
	if err != nil {
		return err
	}
	defer func() { err = closeVault(db, err) }()
	_, err = db.Exec(`INSERT INTO audit_log (event_type, entry_id, detail, created_at) VALUES ('restore', NULL, ?, ?)`,
		"from "+filepath.Base(backupPath)+", replacing a damaged or missing vault", time.Now().UTC())
	return err
}

// removeStaleRestoreTemps removes the temporary files beside the vault at
// target left by restores cut short long ago. Failures are ignored.
func removeStaleRestoreTemps(target string, now time.Time) {
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".*.restore"))
	if err != nil {
		return
	}
	for _, m := range matches {
		if info, err := os.Lstat(m); err == nil && info.Mode().IsRegular() && now.Sub(info.ModTime()) > staleRestoreTemp {
			_ = os.Remove(m) //nolint:errcheck // only clutter
		}
	}
}

// restoredForSync readies, in tx, a vault just restored from a backup for
// syncing: what it agreed with the sync folder of entries the backup
// doesn't have is forgotten, so they come back from the folder (nothing
// made since is deleted), and the restored entries are marked
// (sync_restored) at their revs. Until one is changed here, the next sync
// takes it as restored (vaultsync): its values over the folder's, the
// folder's secrets kept in its history, unless the folder has it deleted
// (to the trash, or for good), which stays. The backup's recovery key
// record is taken as the one the vault saw in the folder, so it's never
// sent as a change: the folder's, if it differs, comes back at the next
// sync (decided with the user), and a key replaced since doesn't return.
// schema is "main." or "".
func restoredForSync(tx *sql.Tx, schema, backup string) error {
	// Changed in the backup and not synced from it (its rev isn't the one
	// it agreed; made since it last synced): an edit, which wins over a
	// deletion in the folder as any does. A backup that never synced has
	// none.
	changed := `CASE WHEN bs.uid IS NOT NULL THEN bs.rev != b.rev ELSE EXISTS (SELECT 1 FROM ` + backup + `sync_state) END`
	now := time.Now().UTC()
	for _, q := range []string{
		`DELETE FROM ` + schema + `sync_restored`,
		`INSERT INTO ` + schema + `sync_restored (uid, rev, changed)
			SELECT e.uid, e.rev, COALESCE((SELECT ` + changed + ` FROM (SELECT uid, rev FROM ` + backup + `entries UNION ALL SELECT uid, rev FROM ` + backup + `trash) b
				LEFT JOIN ` + backup + `sync_state bs ON bs.uid = b.uid WHERE b.uid = e.uid), 0)
			FROM (SELECT uid, rev FROM ` + schema + `entries UNION ALL SELECT uid, rev FROM ` + schema + `trash) e`,
		`DELETE FROM ` + schema + `sync_state WHERE uid NOT IN (SELECT uid FROM ` + schema + `entries UNION SELECT uid FROM ` + schema + `trash)`,
		`UPDATE ` + schema + `sync_info SET recovery_key = COALESCE((SELECT public_key FROM ` + schema + `recovery WHERE id = 1), x''), recovery_mine = 0, recovery_earlier = 1`,
	} {
		if _, err := tx.Exec(q); err != nil { //nolint:gosec // schema and backup are "main.", "backup." or ""
			return err
		}
	}
	// In the trash since now, not since it was deleted before the backup:
	// trash.keep_days counts from the restore, so an entry restored into
	// the trash isn't deleted for good at once.
	if _, err := tx.Exec(`UPDATE `+schema+`trash SET deleted_at = ?`, now); err != nil { //nolint:gosec // schema is "main." or ""
		return err
	}
	// Agreed versions sealed with another key (a backup from before a new
	// master password) don't open: dropped, so those entries merge as never
	// synced.
	var verify []byte
	if err := tx.QueryRow(`SELECT verify FROM ` + schema + `vault_key WHERE id = 1`).Scan(&verify); err != nil { //nolint:gosec // schema is "main." or ""
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	keyID := UnlockID(verify)
	rows, err := tx.Query(`SELECT uid, base FROM ` + schema + `sync_state`) //nolint:gosec // schema is "main." or ""
	if err != nil {
		return err
	}
	var other []string
	for rows.Next() {
		var uid string
		var base []byte
		if err := rows.Scan(&uid, &base); err != nil {
			_ = rows.Close() //nolint:errcheck // already failing
			return err
		}
		if h, err := syncfolder.ParseHeader(base); err != nil || h.KeyIDString() != keyID {
			other = append(other, uid)
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}
	for _, uid := range other {
		if _, err := tx.Exec(`DELETE FROM `+schema+`sync_state WHERE uid = ?`, uid); err != nil { //nolint:gosec // schema is "main." or ""
			return err
		}
	}
	return nil
}

// replacedForSync readies the vault file at path, a backup's copy about to
// replace the vault, for syncing: as restoredForSync, and with no sync ID,
// so it's given a new one.
func replacedForSync(path string) error {
	db, err := openDB(path)
	if err != nil {
		return err
	}
	err = func() error {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if err := restoredForSync(tx, "", ""); err != nil {
			_ = tx.Rollback() //nolint:errcheck // already failing
			return err
		}
		// A new sync ID, its count afresh; the folder it syncs with kept.
		if _, err := tx.Exec(`UPDATE sync_info SET computer_id = lower(hex(randomblob(8))), changes = 0, prev_key_id = ''`); err != nil {
			_ = tx.Rollback() //nolint:errcheck // already failing
			return err
		}
		return tx.Commit()
	}()
	return errors.Join(err, db.Close())
}
