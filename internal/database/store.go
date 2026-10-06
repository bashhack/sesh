package database

import (
	"database/sql"
	"encoding/json"
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
	db, err := sql.Open("sqlite", fileURI(dbPath, "_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)"))
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Single connection — SQLite serialises writes anyway, and this avoids
	// "database is locked" under concurrent goroutines.
	db.SetMaxOpenConns(1)

	if err := applyMigrations(db); err != nil {
		if errors.Is(err, ErrOldVault) {
			_ = db.Close() //nolint:errcheck // the refusal is what matters
			return nil, fmt.Errorf("%s: %w", dbPath, ErrOldVault)
		}
		if closeErr := db.Close(); closeErr != nil {
			return nil, fmt.Errorf("apply migrations: %w (close also failed: %v)", err, closeErr)
		}
		return nil, fmt.Errorf("apply migrations: %w", err)
	}

	return &Store{db: db, oracle: oracle, path: dbPath}, nil
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

// --- Key metadata helpers (for future key rotation) ---

// StoreKeyMetadata records key derivation parameters for the given key version.
func (s *Store) StoreKeyMetadata(meta *KeyMetadata) error {
	_, err := s.db.Exec(
		`INSERT INTO key_metadata (version, algorithm, params, salt, created_at, active) VALUES (?, ?, ?, ?, ?, ?)`,
		meta.Version, meta.Algorithm, meta.Params, meta.Salt, meta.CreatedAt, meta.Active,
	)
	if err != nil {
		return fmt.Errorf("store key metadata: %w", err)
	}
	return nil
}

// GetActiveKeyMetadata returns the currently active key metadata.
func (s *Store) GetActiveKeyMetadata() (*KeyMetadata, error) {
	var m KeyMetadata
	var paramsJSON string
	err := s.db.QueryRow(
		`SELECT version, algorithm, params, salt, created_at, active FROM key_metadata WHERE active = 1 ORDER BY version DESC LIMIT 1`,
	).Scan(&m.Version, &m.Algorithm, &paramsJSON, &m.Salt, &m.CreatedAt, &m.Active)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get active key metadata: %w", err)
	}
	m.Params = paramsJSON
	return &m, nil
}

// InitKeyMetadata creates the initial key metadata entry if none exists.
// Called when the store is opened.
func (s *Store) InitKeyMetadata() error {
	existing, err := s.GetActiveKeyMetadata()
	if err != nil {
		return err
	}
	if existing != nil {
		return nil // already initialised
	}

	salt, err := GenerateSalt(16)
	if err != nil {
		return err
	}

	params := DefaultArgon2idParams()
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("marshal argon2id params: %w", err)
	}

	return s.StoreKeyMetadata(&KeyMetadata{
		Version:   1,
		Algorithm: "argon2id",
		Params:    string(paramsJSON),
		Salt:      salt,
		CreatedAt: time.Now().UTC(),
		Active:    true,
	})
}
