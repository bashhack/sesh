// Package database provides a pure-Go SQLite-backed credential store.
package database

import (
	"database/sql"
	"fmt"
	"time"
)

// Current schema version. Bump this and add a migration function when the schema changes.
const currentSchemaVersion = 1

// EntryType classifies what kind of credential is stored.
type EntryType string

const (
	EntryTypePassword EntryType = "password"
	EntryTypeAPIKey   EntryType = "api_key"
	EntryTypeTOTP     EntryType = "totp"
	EntryTypeNote     EntryType = "secure_note"
	EntryTypeMFA      EntryType = "mfa_serial"
)

// PasswordEntry represents a row in the passwords table.
type PasswordEntry struct {
	CreatedAt     time.Time
	UpdatedAt     time.Time
	ID            string
	Service       string
	Account       string
	EntryType     EntryType
	Metadata      string
	EncryptedData []byte
	Salt          []byte
	KeyVersion    int
}

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

		// FTS5 virtual table for full-text search across service, account, metadata.
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
