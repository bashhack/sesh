package database

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

// Store is the vault: entries in a SQLite file, each encrypted, through the
// vault.Store methods (entries.go).
type Store struct {
	db     *sql.DB
	oracle CryptoOracle
	path   string
}

// MaxSecretSize is the largest secret the store accepts. It applies however
// the store encrypts, so a secret that saves directly also saves through
// the agent, whose wire frames must carry it.
const MaxSecretSize = 1 << 20 // 1 MiB

// ErrSecretTooLarge is returned when a secret exceeds MaxSecretSize.
var ErrSecretTooLarge = errors.New("secret too large")

// Open creates or opens the SQLite database at dbPath, runs any pending
// migrations, and returns a ready-to-use Store.
func Open(dbPath string, oracle CryptoOracle) (*Store, error) {
	db, err := openDB(dbPath)
	if err != nil {
		return nil, err
	}
	return &Store{db: db, oracle: oracle, path: dbPath}, nil
}

// openDB opens the vault file at dbPath, creating it readable only by its
// owner if it doesn't exist, and brings its schema up to date.
func openDB(dbPath string) (*sql.DB, error) {
	f, err := os.OpenFile(dbPath, os.O_CREATE|os.O_RDONLY, 0o600) //nolint:gosec // the user's own vault location
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	// Another sesh may be writing: wait for it rather than fail, and take
	// the write lock when a transaction starts, so two first runs can't
	// both create the schema.
	db, err := sql.Open("sqlite", fileURI(dbPath, "_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_txlock=immediate"))
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Single connection — SQLite serialises writes anyway, and this avoids
	// "database is locked" under concurrent goroutines.
	db.SetMaxOpenConns(1)

	if err := applyMigrations(db); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			return nil, fmt.Errorf("apply migrations: %w (close also failed: %v)", err, closeErr)
		}
		return nil, fmt.Errorf("apply migrations: %w", err)
	}
	return db, nil
}

// fileURI is the SQLite address of the file at path, with query options.
// The path is escaped, so a ?, #, or % in it is part of the name rather
// than the start of options (which would open, or create, another file).
func fileURI(path, query string) string {
	return (&url.URL{Scheme: "file", Path: path, RawQuery: query}).String()
}

// Close releases the database connection and clears any cached key
// material held by the key source.
func (s *Store) Close() error {
	if closer, ok := s.oracle.(interface{ Close() }); ok {
		closer.Close()
	}
	return s.db.Close()
}

// audit writes an append-only event to the audit_log table.
// Errors are logged to stderr — audit failure must never block operations.
func (s *Store) audit(eventType, entryID, detail string) {
	if _, err := s.db.Exec(
		`INSERT INTO audit_log (event_type, entry_id, detail, created_at) VALUES (?, ?, ?, ?)`,
		eventType, entryID, detail, time.Now().UTC(),
	); err != nil {
		fmt.Fprintf(os.Stderr, "audit log write failed: %v\n", err)
	}
}
