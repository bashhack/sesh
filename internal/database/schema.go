// Package database provides a pure-Go SQLite-backed credential store.
package database

import (
	"database/sql"
	"fmt"
	"time"
)

// Current schema version. Bump this and add a migration function when the schema changes.
const currentSchemaVersion = 1

// AuditEntry represents a row in the audit_log table.
type AuditEntry struct {
	CreatedAt time.Time
	EventType string
	EntryID   string // nullable — empty for auth events
	Detail    string
	ID        int64
}

// migrations maps schema version → DDL to apply. Each function receives a *sql.Tx
// so the migration is atomic.
var migrations = map[int]func(tx *sql.Tx) error{
	1: migrateV1,
}

// migrateV1 creates the schema: the vault's id, the entries and their tags, the trash, the
// entries' history, the triggers that count changes to entries, the vault's key record
// (vault_key), its recovery key record, and the audit log.
func migrateV1(tx *sql.Tx) error {
	for _, q := range []string{
		// uid is the entry's own id, random, made with it and kept
		// through every change of name, the trash and back: it's how
		// computers syncing the vault tell one entry from another. rev
		// counts the entry's changes; the triggers below raise it.
		`CREATE TABLE entries (
			id             INTEGER PRIMARY KEY,
			uid            TEXT NOT NULL UNIQUE DEFAULT (lower(hex(randomblob(16)))),
			rev            INTEGER NOT NULL DEFAULT 1,
			kind           TEXT NOT NULL,
			service        TEXT NOT NULL,
			username       TEXT NOT NULL DEFAULT '',
			encrypted_data BLOB NOT NULL,
			salt           BLOB NOT NULL,
			settings       TEXT,
			folder         TEXT NOT NULL DEFAULT '',
			url            TEXT NOT NULL DEFAULT '',
			-- The readable part of the notes and custom fields, as JSON,
			-- and the sealed part; see details.go.
			details        TEXT NOT NULL DEFAULT '',
			sealed_details BLOB,
			details_salt   BLOB,
			created_at     DATETIME NOT NULL,
			updated_at     DATETIME NOT NULL,
			-- When anything of it last changed (updated_at follows the
			-- secret alone): which of two changes is newer, for sync.
			changed_at     DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
			UNIQUE (kind, service, username)
		)`,
		`CREATE INDEX idx_entries_folder ON entries(folder)`,
		// Deleted entries, kept a while to be restored: an entry's row as
		// it was, its tags as a JSON array, and when it was deleted. The
		// secret and details stay sealed for its name; see trash.go.
		// Their ids aren't reused, so one listed names only that entry.
		`CREATE TABLE trash (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			uid            TEXT NOT NULL UNIQUE,
			rev            INTEGER NOT NULL,
			kind           TEXT NOT NULL,
			service        TEXT NOT NULL,
			username       TEXT NOT NULL DEFAULT '',
			encrypted_data BLOB NOT NULL,
			salt           BLOB NOT NULL,
			settings       TEXT,
			folder         TEXT NOT NULL DEFAULT '',
			url            TEXT NOT NULL DEFAULT '',
			details        TEXT NOT NULL DEFAULT '',
			sealed_details BLOB,
			details_salt   BLOB,
			tags           TEXT NOT NULL DEFAULT '[]',
			created_at     DATETIME NOT NULL,
			updated_at     DATETIME NOT NULL,
			deleted_at     DATETIME NOT NULL,
			changed_at     DATETIME NOT NULL
		)`,
		`CREATE INDEX idx_trash_deleted_at ON trash(deleted_at)`,
		// Entries' earlier secrets, each sealed for its entry's name, and
		// when it was replaced. While its entry is in the trash, trash_id
		// is that entry's, and it goes with it; see history.go.
		// Their ids aren't reused, so one listed names only that secret.
		`CREATE TABLE history (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			kind           TEXT NOT NULL,
			service        TEXT NOT NULL,
			username       TEXT NOT NULL DEFAULT '',
			trash_id       INTEGER REFERENCES trash(id) ON DELETE CASCADE,
			encrypted_data BLOB NOT NULL,
			salt           BLOB NOT NULL,
			replaced_at    DATETIME NOT NULL,
			-- A file entry's file's name, as it was then.
			file_name      TEXT NOT NULL DEFAULT '',
			-- The computer whose change replaced it, when another synced
			-- it here; "" for this one.
			computer       TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX idx_history_entry ON history(kind, service, username, trash_id)`,
		`CREATE INDEX idx_history_trash ON history(trash_id)`,
		// An entry's tags go with it when it's deleted.
		`CREATE TABLE entry_tags (
			entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
			tag      TEXT NOT NULL,
			PRIMARY KEY (entry_id, tag)
		)`,
		`CREATE INDEX idx_entry_tags_tag ON entry_tags(tag)`,
		// While it has its one row, writes don't count as changes to an
		// entry: re-encrypting for a new master password, trimming
		// history to history.keep, a restore. See quietly.
		// What this computer and the sync folder last agreed on, for each
		// entry synced: its rev here then, the hash of the folder's file,
		// and the version agreed, sealed as a sync file is (for merging
		// what changes after). A row stays when its entry is
		// deleted for good, so the deletion is synced.
		`CREATE TABLE sync_state (
			uid       TEXT PRIMARY KEY,
			rev       INTEGER NOT NULL,
			file_hash BLOB NOT NULL,
			base      BLOB NOT NULL,
			-- SHA-256 of base, so damage to it is seen without opening it.
			base_hash BLOB NOT NULL DEFAULT x''
		)`,
		// At most one row: this computer's sync ID, made when it first
		// syncs, the count of the changes it has written
		// (syncfolder.Versions), which only goes up, the ID of the sync
		// folder it syncs with (kept when it leaves, so it can join again),
		// and, after a master password change made here that the folder
		// hasn't taken yet, the ID of the key record the vault had before
		// (the folder's), or "".
		`CREATE TABLE sync_info (
			id          INTEGER PRIMARY KEY CHECK (id = 1),
			computer_id TEXT NOT NULL,
			changes     INTEGER NOT NULL DEFAULT 0,
			folder_id   TEXT NOT NULL DEFAULT '',
			prev_key_id TEXT NOT NULL DEFAULT '',
			-- The sync folder's recovery key record as the vault last saw
			-- it (syncfolder.Recovery): its count, public key (empty for
			-- none), when and where it was made.
			recovery_count INTEGER NOT NULL DEFAULT 0,
			recovery_key   BLOB NOT NULL DEFAULT x'',
			recovery_made  DATETIME,
			recovery_by    TEXT NOT NULL DEFAULT ''
		)`,
		// Earlier secrets forgotten on purpose, by their entry's uid, a
		// hash of the secret (syncfolder.Forget) and when, so a sync
		// forgets them on every computer. Kept for good, as the sync folder's records
		// of entries deleted for good are.
		`CREATE TABLE history_forgotten (
			uid  TEXT NOT NULL,
			hash TEXT NOT NULL,
			at   DATETIME NOT NULL,
			PRIMARY KEY (uid, hash)
		)`,
		// Entries restored from a backup, at their revs then, not yet
		// synced since, and whether the backup had them changed and not
		// synced (vaultsync).
		// The vault's master password changes, as syncfolder.KeyLink: each
		// from a key record (from_id) to the next (to_id), the old key
		// sealed with the new (key), and to_id sealed with the old (proof).
		// The sync folder holds them too; files sealed with an old key are
		// opened through them.
		`CREATE TABLE key_links (
			from_id    TEXT NOT NULL,
			to_id      TEXT NOT NULL,
			key        BLOB NOT NULL,
			key_salt   BLOB NOT NULL,
			proof      BLOB NOT NULL,
			proof_salt BLOB NOT NULL,
			PRIMARY KEY (from_id, to_id)
		)`,
		`CREATE TABLE sync_restored (uid TEXT PRIMARY KEY, rev INTEGER NOT NULL, changed INTEGER NOT NULL DEFAULT 0)`,
		`CREATE TABLE quiet_writes (id INTEGER PRIMARY KEY CHECK (id = 1))`,
		// Any change to an entry, its tags, or (forgetting one) its
		// earlier secrets raises its rev, however it's made; a write of
		// what the entry already holds doesn't.
		`CREATE TRIGGER entry_changed AFTER UPDATE ON entries
			WHEN NEW.rev = OLD.rev AND NOT EXISTS (SELECT 1 FROM quiet_writes) AND (
				NEW.kind IS NOT OLD.kind
				OR NEW.service IS NOT OLD.service
				OR NEW.username IS NOT OLD.username
				OR NEW.encrypted_data IS NOT OLD.encrypted_data
				OR NEW.salt IS NOT OLD.salt
				OR NEW.settings IS NOT OLD.settings
				OR NEW.folder IS NOT OLD.folder
				OR NEW.url IS NOT OLD.url
				OR NEW.details IS NOT OLD.details
				OR NEW.sealed_details IS NOT OLD.sealed_details
				OR NEW.details_salt IS NOT OLD.details_salt
				OR NEW.created_at IS NOT OLD.created_at
				OR NEW.updated_at IS NOT OLD.updated_at)
			BEGIN UPDATE entries SET rev = rev + 1, changed_at = strftime('%Y-%m-%d %H:%M:%f', 'now') WHERE id = NEW.id; END`,
		`CREATE TRIGGER entry_tag_added AFTER INSERT ON entry_tags
			WHEN NOT EXISTS (SELECT 1 FROM quiet_writes)
			BEGIN UPDATE entries SET rev = rev + 1, changed_at = strftime('%Y-%m-%d %H:%M:%f', 'now') WHERE id = NEW.entry_id; END`,
		`CREATE TRIGGER entry_tag_removed AFTER DELETE ON entry_tags
			WHEN NOT EXISTS (SELECT 1 FROM quiet_writes)
			BEGIN UPDATE entries SET rev = rev + 1, changed_at = strftime('%Y-%m-%d %H:%M:%f', 'now') WHERE id = OLD.entry_id; END`,
		`CREATE TRIGGER entry_history_removed AFTER DELETE ON history
			WHEN OLD.trash_id IS NULL AND NOT EXISTS (SELECT 1 FROM quiet_writes)
			BEGIN UPDATE entries SET rev = rev + 1, changed_at = strftime('%Y-%m-%d %H:%M:%f', 'now') WHERE kind = OLD.kind AND service = OLD.service AND username = OLD.username; END`,
		// One row: what turns the master password into the vault's key.
		// None of it is secret; see vault_key.go.
		`CREATE TABLE vault_key (
			id         INTEGER PRIMARY KEY CHECK (id = 1),
			salt       BLOB NOT NULL,
			kdf        TEXT NOT NULL,
			kdf_params TEXT NOT NULL,
			verify     BLOB NOT NULL,
			created_at DATETIME NOT NULL
		)`,
		// At most one row: the vault key wrapped to a recovery key's public
		// key; see recovery.go.
		`CREATE TABLE recovery (
			id            INTEGER PRIMARY KEY CHECK (id = 1),
			unlock_id     TEXT NOT NULL,
			public_key    BLOB NOT NULL,
			ephemeral_pub BLOB NOT NULL,
			ciphertext    BLOB NOT NULL,
			created_at    DATETIME NOT NULL
		)`,
		`CREATE TABLE audit_log (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			event_type TEXT NOT NULL,
			entry_id   TEXT,
			detail     TEXT,
			created_at DATETIME NOT NULL
		)`,
		// Pruning old events on every open goes by time.
		`CREATE INDEX idx_audit_log_created_at ON audit_log(created_at)`,
		// One row: a random id for the vault, made with it and never
		// changed, not even by a new master password. Backups are named
		// with it, so two vaults sharing a backups folder keep their own.
		`CREATE TABLE vault_info (
			id       INTEGER PRIMARY KEY CHECK (id = 1),
			vault_id TEXT NOT NULL
		)`,
		`INSERT INTO vault_info (id, vault_id) VALUES (1, lower(hex(randomblob(8))))`,
	} {
		if _, err := tx.Exec(q); err != nil {
			return fmt.Errorf("migration v1: %w", err)
		}
	}
	return nil
}

// applyMigrations brings the database up to currentSchemaVersion.
func applyMigrations(db *sql.DB) error {
	// Ensure the schema_migrations table exists so we can query it.
	// This is idempotent — the v1 migration also creates it, but we
	// need it before we can check which version we're on.
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at DATETIME NOT NULL
	)`); err != nil {
		return fmt.Errorf("bootstrap schema_migrations: %w", err)
	}

	var applied int
	row := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`)
	if err := row.Scan(&applied); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}

	// Refuse to open a database whose schema was written by a newer sesh
	// build. Silently proceeding would let reads/writes hit an unsupported
	// schema and potentially corrupt or skip rows.
	if applied > currentSchemaVersion {
		return fmt.Errorf("database schema version %d is newer than this binary supports (max %d) — upgrade sesh or point at a matching database", applied, currentSchemaVersion)
	}

	for v := applied + 1; v <= currentSchemaVersion; v++ {
		fn, ok := migrations[v]
		if !ok {
			return fmt.Errorf("no migration function for version %d", v)
		}

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin migration v%d: %w", v, err)
		}
		// Another sesh may have applied it since the version was read; the
		// transaction holds the write lock, so this answer stands.
		var done bool
		if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = ?)`, v).Scan(&done); err != nil {
			_ = tx.Rollback() //nolint:errcheck // already failing
			return fmt.Errorf("check migration v%d: %w", v, err)
		}
		if done {
			if err := tx.Rollback(); err != nil {
				return fmt.Errorf("end migration v%d: %w", v, err)
			}
			continue
		}

		if err := fn(tx); err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				return fmt.Errorf("apply migration v%d: %w (rollback also failed: %v)", v, err, rbErr)
			}
			return fmt.Errorf("apply migration v%d: %w", v, err)
		}

		if _, err := tx.Exec(
			`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
			v, time.Now().UTC(),
		); err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				return fmt.Errorf("record migration v%d: %w (rollback also failed: %v)", v, err, rbErr)
			}
			return fmt.Errorf("record migration v%d: %w", v, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration v%d: %w", v, err)
		}
	}

	return nil
}
