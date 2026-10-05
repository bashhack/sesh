// Package database provides a pure-Go SQLite-backed credential store.
package database

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Current schema version. Bump this and add a migration function when the schema changes.
const currentSchemaVersion = 5

// KeyMetadata stores key derivation parameters for a given key version.
// This table is readable without decryption so the store can derive the
// decryption key before reading any password entries.
type KeyMetadata struct {
	CreatedAt time.Time
	Algorithm string // "argon2id", "pbkdf2"
	Params    string // JSON: time, memory, threads (argon2id) or iterations (pbkdf2)
	Salt      []byte
	Version   int
	Active    bool
}

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
	2: migrateV2,
	3: migrateV3,
	4: migrateV4,
	5: migrateV5,
}

// migrateV1 creates the initial four-table schema.
func migrateV1(tx *sql.Tx) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS passwords (
			id             TEXT PRIMARY KEY,
			service        TEXT NOT NULL,
			account        TEXT NOT NULL,
			entry_type     TEXT NOT NULL,
			encrypted_data BLOB NOT NULL,
			salt           BLOB NOT NULL,
			key_version    INTEGER NOT NULL DEFAULT 1,
			metadata       TEXT,
			created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_passwords_service ON passwords(service)`,
		`CREATE INDEX IF NOT EXISTS idx_passwords_account ON passwords(account)`,
		`CREATE INDEX IF NOT EXISTS idx_passwords_type ON passwords(entry_type)`,
		`CREATE INDEX IF NOT EXISTS idx_passwords_service_account ON passwords(service, account)`,

		`CREATE TABLE IF NOT EXISTS key_metadata (
			version    INTEGER PRIMARY KEY,
			algorithm  TEXT NOT NULL,
			params     TEXT NOT NULL,
			salt       BLOB NOT NULL,
			created_at DATETIME NOT NULL,
			active     BOOLEAN NOT NULL DEFAULT 1
		)`,

		`CREATE TABLE IF NOT EXISTS audit_log (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			event_type TEXT NOT NULL,
			entry_id   TEXT,
			detail     TEXT,
			created_at DATETIME NOT NULL
		)`,

		`CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			applied_at DATETIME NOT NULL
		)`,

		// FTS5 virtual table for full-text search across service, account,
		// metadata. v4 drops it, with its triggers.
		`CREATE VIRTUAL TABLE IF NOT EXISTS passwords_fts USING fts5(
			service, account, metadata,
			content='passwords',
			content_rowid='rowid'
		)`,

		// Triggers to keep FTS in sync with the passwords table.
		`CREATE TRIGGER IF NOT EXISTS passwords_ai AFTER INSERT ON passwords BEGIN
			INSERT INTO passwords_fts(rowid, service, account, metadata)
			VALUES (new.rowid, new.service, new.account, new.metadata);
		END`,
		`CREATE TRIGGER IF NOT EXISTS passwords_ad AFTER DELETE ON passwords BEGIN
			INSERT INTO passwords_fts(passwords_fts, rowid, service, account, metadata)
			VALUES ('delete', old.rowid, old.service, old.account, old.metadata);
		END`,
		`CREATE TRIGGER IF NOT EXISTS passwords_au AFTER UPDATE ON passwords BEGIN
			INSERT INTO passwords_fts(passwords_fts, rowid, service, account, metadata)
			VALUES ('delete', old.rowid, old.service, old.account, old.metadata);
			INSERT INTO passwords_fts(rowid, service, account, metadata)
			VALUES (new.rowid, new.service, new.account, new.metadata);
		END`,
	}

	for _, s := range stmts {
		if _, err := tx.Exec(s); err != nil {
			return fmt.Errorf("migration v1: %w", err)
		}
	}
	return nil
}

// migrateV4 drops the full-text index v1 made, and the triggers that kept
// it in step: search matches service names and usernames in Go, so
// nothing reads the index.
func migrateV4(tx *sql.Tx) error {
	for _, q := range []string{
		`DROP TRIGGER IF EXISTS passwords_ai`,
		`DROP TRIGGER IF EXISTS passwords_ad`,
		`DROP TRIGGER IF EXISTS passwords_au`,
		`DROP TABLE IF EXISTS passwords_fts`,
	} {
		if _, err := tx.Exec(q); err != nil {
			return fmt.Errorf("migration v4: %w", err)
		}
	}
	return nil
}

// ErrOldVault is returned for a vault an earlier development build made
// with entries in the old table: sesh had no releases then, so v5
// doesn't convert one.
var ErrOldVault = errors.New("this vault was made by an earlier development build of sesh, which this version can't open: start a new vault, or export this one with that build and import the export")

// migrateV5 gives entries their own table, with kind, service name, and
// username as columns, unique together. A vault whose old table holds
// entries is refused (ErrOldVault), unchanged.
func migrateV5(tx *sql.Tx) error {
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM passwords`).Scan(&n); err != nil {
		return fmt.Errorf("migration v5: %w", err)
	}
	if n > 0 {
		return ErrOldVault
	}
	for _, q := range []string{
		`DROP TABLE passwords`,
		`CREATE TABLE entries (
			id             INTEGER PRIMARY KEY,
			kind           TEXT NOT NULL,
			service        TEXT NOT NULL,
			username       TEXT NOT NULL DEFAULT '',
			encrypted_data BLOB NOT NULL,
			salt           BLOB NOT NULL,
			key_version    INTEGER NOT NULL DEFAULT 1,
			settings       TEXT,
			created_at     DATETIME NOT NULL,
			updated_at     DATETIME NOT NULL,
			UNIQUE (kind, service, username)
		)`,
	} {
		if _, err := tx.Exec(q); err != nil {
			return fmt.Errorf("migration v5: %w", err)
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
