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

// migrateV1 creates the schema: the entries, the vault's key record
// (vault_key), and the audit log.
func migrateV1(tx *sql.Tx) error {
	for _, q := range []string{
		`CREATE TABLE entries (
			id             INTEGER PRIMARY KEY,
			kind           TEXT NOT NULL,
			service        TEXT NOT NULL,
			username       TEXT NOT NULL DEFAULT '',
			encrypted_data BLOB NOT NULL,
			salt           BLOB NOT NULL,
			settings       TEXT,
			created_at     DATETIME NOT NULL,
			updated_at     DATETIME NOT NULL,
			UNIQUE (kind, service, username)
		)`,
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
		`CREATE TABLE audit_log (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			event_type TEXT NOT NULL,
			entry_id   TEXT,
			detail     TEXT,
			created_at DATETIME NOT NULL
		)`,
		// Pruning old events on every open goes by time.
		`CREATE INDEX idx_audit_log_created_at ON audit_log(created_at)`,
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
