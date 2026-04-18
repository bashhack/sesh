package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/secure"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

// Store is a SQLite-backed credential store that satisfies keychain.Provider.
type Store struct {
	db        *sql.DB
	keySource KeySource
}

// compile-time check
var _ keychain.Provider = (*Store)(nil)

// Open creates or opens the SQLite database at dbPath, runs any pending
// migrations, and returns a ready-to-use Store.
func Open(dbPath string, ks KeySource) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)")
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

	return &Store{db: db, keySource: ks}, nil
}

// Close releases the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// --- keychain.Provider implementation ---

func (s *Store) GetSecret(account, service string) ([]byte, error) {
	masterKey, err := s.keySource.GetEncryptionKey()
	if err != nil {
		return nil, err
	}
	defer secure.SecureZeroBytes(masterKey)

	var encData, salt []byte
	err = s.db.QueryRow(
		`SELECT encrypted_data, salt FROM passwords WHERE service = ? AND account = ? LIMIT 1`,
		service, account,
	).Scan(&encData, &salt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w for account %q and service %q", keychain.ErrNotFound, account, service)
	}
	if err != nil {
		return nil, fmt.Errorf("query secret: %w", err)
	}

	plaintext, err := DecryptEntry(masterKey, encData, salt)
	if err != nil {
		return nil, fmt.Errorf("decrypt secret for service %q: %w", service, err)
	}

	s.audit("access", service+"/"+account, "GetSecret")
	return plaintext, nil
}

func (s *Store) SetSecret(account, service string, secret []byte) error {
	return s.upsertSecret(account, service, secret, inferEntryType(service))
}

func (s *Store) GetSecretString(account, service string) (string, error) {
	b, err := s.GetSecret(account, service)
	if err != nil {
		return "", err
	}
	str := string(b)
	secure.SecureZeroBytes(b)
	return str, nil
}

func (s *Store) SetSecretString(account, service, secret string) error {
	b := []byte(secret)
	defer secure.SecureZeroBytes(b)
	return s.SetSecret(account, service, b)
}

func (s *Store) GetMFASerialBytes(account, profile string) ([]byte, error) {
	service := "sesh-aws-serial"
	if profile != "" {
		service += "/" + profile
	}
	return s.GetSecret(account, service)
}

func (s *Store) ListEntries(service string) (_ []keychain.KeychainEntry, err error) {
	// Range query for prefix matching — avoids LIKE escaping issues with % and _.
	upper := service + "\xff"
	rows, err := s.db.Query(
		`SELECT service, account, metadata, created_at, updated_at FROM passwords WHERE service >= ? AND service < ? ORDER BY service`,
		service, upper,
	)
	if err != nil {
		return nil, fmt.Errorf("list entries: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close rows: %w", closeErr)
		}
	}()

	var entries []keychain.KeychainEntry
	for rows.Next() {
		var svc, acct string
		var meta sql.NullString
		var created, updated time.Time
		if err := rows.Scan(&svc, &acct, &meta, &created, &updated); err != nil {
			return nil, fmt.Errorf("scan entry: %w", err)
		}
		entries = append(entries, keychain.KeychainEntry{
			Service:     svc,
			Account:     acct,
			Description: meta.String,
			CreatedAt:   created,
			UpdatedAt:   updated,
		})
	}
	return entries, rows.Err()
}

func (s *Store) DeleteEntry(account, service string) error {
	res, err := s.db.Exec(
		`DELETE FROM passwords WHERE service = ? AND account = ?`,
		service, account,
	)
	if err != nil {
		return fmt.Errorf("delete entry: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("check rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("%w for account %q and service %q", keychain.ErrNotFound, account, service)
	}

	s.audit("delete", service+"/"+account, "DeleteEntry")
	return nil
}

func (s *Store) SetDescription(service, account, description string) error {
	res, err := s.db.Exec(
		`UPDATE passwords SET metadata = ?, updated_at = ? WHERE id = ?`,
		description, time.Now().UTC(), entryID(service, account),
	)
	if err != nil {
		return fmt.Errorf("set description: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("check rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("%w for account %q and service %q", keychain.ErrNotFound, account, service)
	}
	return nil
}

// SearchEntries performs a full-text search across service, account, and metadata
// using the FTS5 index. Returns matching KeychainEntry rows.
// An empty or whitespace-only query returns no results (FTS5 would reject it).
func (s *Store) SearchEntries(query string) (_ []keychain.KeychainEntry, err error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, nil
	}
	// FTS5 prefix query: quote the user input and append * for prefix matching.
	// This allows "git" to match "github", "gitlab", etc.
	escaped := strings.ReplaceAll(query, `"`, `""`)
	ftsQuery := `"` + escaped + `"*`

	rows, err := s.db.Query(`
		SELECT p.service, p.account, p.metadata, p.created_at, p.updated_at
		FROM passwords p
		JOIN passwords_fts f ON f.rowid = p.rowid
		WHERE passwords_fts MATCH ?
		ORDER BY rank`, ftsQuery)
	if err != nil {
		return nil, fmt.Errorf("fts search: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close rows: %w", closeErr)
		}
	}()

	var entries []keychain.KeychainEntry
	for rows.Next() {
		var svc, acct string
		var meta sql.NullString
		var created, updated time.Time
		if err := rows.Scan(&svc, &acct, &meta, &created, &updated); err != nil {
			return nil, fmt.Errorf("scan fts result: %w", err)
		}
		entries = append(entries, keychain.KeychainEntry{
			Service:     svc,
			Account:     acct,
			Description: meta.String,
			CreatedAt:   created,
			UpdatedAt:   updated,
		})
	}
	return entries, rows.Err()
}

// --- internal helpers ---

// upsertSecret encrypts and stores (or updates) a secret.
func (s *Store) upsertSecret(account, service string, secret []byte, entryType EntryType) error {
	masterKey, err := s.keySource.GetEncryptionKey()
	if err != nil {
		return err
	}
	defer secure.SecureZeroBytes(masterKey)

	encData, salt, err := EncryptEntry(masterKey, secret)
	if err != nil {
		return fmt.Errorf("encrypt secret: %w", err)
	}

	now := time.Now().UTC()
	id := entryID(service, account)

	_, err = s.db.Exec(`
		INSERT INTO passwords (id, service, account, entry_type, encrypted_data, salt, key_version, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			encrypted_data = excluded.encrypted_data,
			salt           = excluded.salt,
			entry_type     = excluded.entry_type,
			updated_at     = excluded.updated_at`,
		id, service, account, string(entryType), encData, salt, now, now,
	)
	if err != nil {
		return fmt.Errorf("upsert secret: %w", err)
	}

	s.audit("modify", service+"/"+account, "SetSecret")
	return nil
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

// entryID returns a deterministic primary key for a (service, account) pair.
// Uses ":" as separator, consistent with provider.ParseEntryID and password.Entry.ID.
func entryID(service, account string) string {
	return service + ":" + account
}

// inferEntryType derives the entry type from the service key.
// For sesh-password/ keys the type is the second segment (e.g. sesh-password/totp/...).
func inferEntryType(service string) EntryType {
	switch {
	case strings.HasPrefix(service, "sesh-totp"):
		return EntryTypeTOTP
	case strings.HasPrefix(service, "sesh-aws-serial"):
		return EntryTypeMFA
	case strings.HasPrefix(service, "sesh-aws"):
		return EntryTypeTOTP
	case strings.HasPrefix(service, "sesh-password/"):
		if rest, ok := strings.CutPrefix(service, "sesh-password/"); ok {
			if seg, _, found := strings.Cut(rest, "/"); found {
				switch EntryType(seg) {
				case EntryTypeTOTP, EntryTypeAPIKey, EntryTypeNote:
					return EntryType(seg)
				}
			}
		}
		return EntryTypePassword
	default:
		return EntryTypePassword
	}
}

// extractPrefix returns the namespace portion of a service key (before the first "/").
func extractPrefix(service string) string {
	if prefix, _, ok := strings.Cut(service, "/"); ok {
		return prefix
	}
	return service
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
// Called during store initialisation when using a keychain key source.
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
