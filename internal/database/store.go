package database

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/url"
	"os"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// Store is the vault: entries in a SQLite file, each encrypted, through the
// vault.Store methods (entries.go).
type Store struct {
	db     *sql.DB
	oracle CryptoOracle
	path   string
	// trashDays is how many days deleted entries stay in the trash; 0
	// deletes for good.
	trashDays int
	// historyKeep is how many earlier secrets each entry keeps; 0 keeps
	// none.
	historyKeep int
	// borrowed says the key is another store's (see Reader), which Close
	// leaves open.
	borrowed bool
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
// owner if it doesn't exist, and brings its schema up to date. A database
// another program made is refused before anything in it changes.
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
	// both create the schema. Deleted rows are overwritten with zeros, so
	// a removed recovery key record or entry leaves nothing in the file.
	db, err := sql.Open("sqlite", fileURI(dbPath, "_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)&_pragma=secure_delete(ON)&_txlock=immediate"))
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Single connection — SQLite serialises writes anyway, and this avoids
	// "database is locked" under concurrent goroutines.
	db.SetMaxOpenConns(1)

	if err := setUpWhenFree(func() error { return setUp(db, dbPath) }); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			return nil, fmt.Errorf("%w (close also failed: %v)", err, closeErr)
		}
		return nil, err
	}
	return db, nil
}

// setUp refuses a database another program made, then turns on WAL mode
// and brings the schema up to date.
func setUp(db *sql.DB, dbPath string) error {
	var foreign bool
	if err := db.QueryRow(`SELECT NOT EXISTS (SELECT 1 FROM sqlite_master WHERE name = 'schema_migrations')
		AND EXISTS (SELECT 1 FROM sqlite_master)`).Scan(&foreign); err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	if foreign {
		return fmt.Errorf("%s isn't a sesh vault: it holds another program's data; choose another location for the vault", dbPath)
	}
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	if err := applyMigrations(db); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}

// setUpWhenFree runs setUp, trying again for a few seconds while another
// sesh holds the file: turning on WAL mode in a new file can report it busy
// at once, without waiting for the busy timeout.
func setUpWhenFree(setUp func() error) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := setUp()
		var se *sqlite.Error
		if err == nil || !errors.As(err, &se) || se.Code()&0xff != sqlite3.SQLITE_BUSY || time.Now().After(deadline) {
			return err
		}
		time.Sleep(time.Duration(10+rand.IntN(40)) * time.Millisecond) //nolint:gosec // jitter between tries, not a secret
	}
}

// fileURI is the SQLite address of the file at path, with query options.
// The path is escaped, so a ?, #, or % in it is part of the name rather
// than the start of options (which would open, or create, another file).
func fileURI(path, query string) string {
	return (&url.URL{Scheme: "file", Path: path, RawQuery: query}).String()
}

// DataVersion is a number that changes when another connection to the
// vault file, such as another sesh command, commits a change (SQLite's
// data_version, read on the store's one connection): two that differ say
// the vault may have changed between them.
func (s *Store) DataVersion() (int64, error) {
	var v int64
	if err := s.db.QueryRow(`PRAGMA data_version`).Scan(&v); err != nil {
		return 0, fmt.Errorf("check the vault for changes: %w", err)
	}
	return v, nil
}

// Fingerprint is a hash of what the entries are: every entry's names,
// filing, details and sealed values, their tags, and the key record. It
// changes when any of those does, and not for what else is written, such
// as the audit log, so a change it shows is one to what's stored.
func (s *Store) Fingerprint() ([sha256.Size]byte, error) {
	h := sha256.New()
	write := func(query string) error {
		rows, err := s.db.Query(query)
		if err != nil {
			return err
		}
		defer rows.Close() //nolint:errcheck // read-only query
		cols, err := rows.Columns()
		if err != nil {
			return err
		}
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		for rows.Next() {
			if err := rows.Scan(ptrs...); err != nil {
				return err
			}
			for _, v := range vals {
				fmt.Fprintf(h, "%d:%v|", len(fmt.Sprint(v)), v) //nolint:errcheck // hash writes don't fail
			}
			h.Write([]byte{'\n'}) //nolint:errcheck // hash writes don't fail
		}
		return rows.Err()
	}
	for _, q := range []string{
		`SELECT id, kind, service, username, encrypted_data, salt, settings, folder, url, details, sealed_details, details_salt, created_at, updated_at FROM entries ORDER BY id`,
		`SELECT entry_id, tag FROM entry_tags ORDER BY entry_id, tag`,
		`SELECT verify FROM vault_key`,
	} {
		if err := write(q); err != nil {
			return [sha256.Size]byte{}, fmt.Errorf("check the vault for changes: %w", err)
		}
	}
	return [sha256.Size]byte(h.Sum(nil)), nil
}

// Close releases the database connection and clears any cached key
// material held by the key source.
func (s *Store) Close() error {
	// What was typed and kept for syncing, checked against what the vault
	// still has, before the key goes.
	s.typedChecksWarn()
	if closer, ok := s.oracle.(interface{ Close() }); ok && !s.borrowed {
		closer.Close()
	}
	return s.db.Close()
}

// typedChecksWarn runs SyncTypedChecks after what it follows has been
// written: one that fails is said, not returned, as that stands.
func (s *Store) typedChecksWarn() {
	if err := s.SyncTypedChecks(); err != nil {
		fmt.Fprintf(os.Stderr, "check what's kept of what was typed, for syncing: %v\n", err)
	}
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

// Reader is the vault opened again, on its own connection, for a long read
// (sesh doctor's checks) that would otherwise hold the one connection this
// store has, and with it every other read and write, until it's done. It
// shares this store's key, as it is (so it still notices a master password
// changed or an agent locked), which its Close leaves open. A vault file
// gone from its place isn't made again.
func (s *Store) Reader() (*Store, error) {
	if info, err := os.Stat(s.path); err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("the vault is gone from %s", s.path)
	}
	db, err := openDB(s.path)
	if err != nil {
		return nil, err
	}
	return &Store{db: db, oracle: s.oracle, path: s.path, trashDays: s.trashDays, historyKeep: s.historyKeep, borrowed: true}, nil
}
