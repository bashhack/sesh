package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os/user"
	"strings"
	"sync"
	"time"

	"github.com/bashhack/sesh/internal/constants"
	"github.com/bashhack/sesh/internal/vault"
)

// The vault.Store methods. An entry is a row named
// sesh-password/<kind>/<service>[/<username>], that is "sesh-password/"
// followed by its key's text form, with its settings as JSON in the
// metadata column.

var _ vault.Store = (*Store)(nil)

const entryPrefix = constants.PasswordServicePrefix + "/"

func storedName(k vault.Key) (string, error) {
	if err := k.Validate(); err != nil {
		return "", err
	}
	return entryPrefix + k.String(), nil
}

func notFound(k vault.Key) error {
	return fmt.Errorf("%w: %s", vault.ErrNotFound, k)
}

// owner is the account rows are stored under: the OS user, as the
// keychain.Provider methods' callers pass.
var owner = sync.OnceValues(func() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("determine current user: %w", err)
	}
	return u.Username, nil
})

func encodeSettings(s vault.Settings) (sql.NullString, error) {
	if s.IsZero() {
		return sql.NullString{}, nil
	}
	b, err := json.Marshal(s)
	if err != nil {
		return sql.NullString{}, fmt.Errorf("encode settings: %w", err)
	}
	return sql.NullString{String: string(b), Valid: true}, nil
}

// decodeSettings reads the metadata column; text that isn't settings (a
// description written through the keychain.Provider methods) is none.
func decodeSettings(meta sql.NullString) vault.Settings {
	var s vault.Settings
	if !meta.Valid || !strings.HasPrefix(meta.String, "{") || json.Unmarshal([]byte(meta.String), &s) != nil {
		return vault.Settings{}
	}
	return s
}

// Get implements vault.Store.
func (s *Store) Get(k vault.Key) ([]byte, error) {
	name, err := storedName(k)
	if err != nil {
		return nil, err
	}
	var encData, salt []byte
	err = s.db.QueryRow(`SELECT encrypted_data, salt FROM passwords WHERE service = ? LIMIT 1`, name).Scan(&encData, &salt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, notFound(k)
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", k, err)
	}
	secret, err := s.oracle.DecryptEntry(encData, salt)
	if err != nil {
		return nil, fmt.Errorf("decrypt %s: %w", k, err)
	}
	s.audit("access", k.String(), "Get")
	return secret, nil
}

// Put implements vault.Store.
func (s *Store) Put(k vault.Key, secret []byte) error {
	return s.write(&vault.Entry{Key: k}, secret, false)
}

// Save implements vault.Store.
func (s *Store) Save(e *vault.Entry, secret []byte) error {
	return s.write(e, secret, true)
}

// write stores e's secret. whole also replaces its settings and times;
// otherwise an existing entry keeps them, except its update time.
func (s *Store) write(e *vault.Entry, secret []byte, whole bool) error {
	name, err := storedName(e.Key)
	if err != nil {
		return err
	}
	if len(secret) > MaxSecretSize {
		return fmt.Errorf("%w: %d bytes (max %d)", ErrSecretTooLarge, len(secret), MaxSecretSize)
	}
	acct, err := owner()
	if err != nil {
		return err
	}
	meta, err := encodeSettings(e.Settings)
	if err != nil {
		return err
	}
	encData, salt, err := s.oracle.EncryptEntry(secret)
	if err != nil {
		return fmt.Errorf("encrypt %s: %w", e.Key, err)
	}
	now := time.Now().UTC()
	created, updated := e.CreatedAt, e.UpdatedAt
	if created.IsZero() {
		created = now
	}
	if updated.IsZero() {
		updated = now
	}
	onConflict := `encrypted_data = excluded.encrypted_data, salt = excluded.salt, updated_at = excluded.updated_at`
	if whole {
		onConflict += `, metadata = excluded.metadata, created_at = excluded.created_at`
	}
	_, err = s.db.Exec(`
		INSERT INTO passwords (id, service, account, entry_type, encrypted_data, salt, key_version, metadata, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET `+onConflict,
		entryID(name, acct), name, acct, string(e.Kind), encData, salt, meta, created, updated,
	)
	if err != nil {
		return fmt.Errorf("store %s: %w", e.Key, err)
	}
	s.audit("modify", e.Key.String(), "Put")
	return nil
}

// SetSettings implements vault.Store.
func (s *Store) SetSettings(k vault.Key, settings vault.Settings) error {
	name, err := storedName(k)
	if err != nil {
		return err
	}
	meta, err := encodeSettings(settings)
	if err != nil {
		return err
	}
	res, err := s.db.Exec(`UPDATE passwords SET metadata = ?, updated_at = ? WHERE service = ?`, meta, time.Now().UTC(), name)
	if err != nil {
		return fmt.Errorf("set settings of %s: %w", k, err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("set settings of %s: %w", k, err)
	} else if n == 0 {
		return notFound(k)
	}
	return nil
}

// Lookup implements vault.Store.
func (s *Store) Lookup(k vault.Key) (vault.Entry, error) {
	name, err := storedName(k)
	if err != nil {
		return vault.Entry{}, err
	}
	var meta sql.NullString
	e := vault.Entry{Key: k}
	err = s.db.QueryRow(`SELECT metadata, created_at, updated_at FROM passwords WHERE service = ? LIMIT 1`, name).Scan(&meta, &e.CreatedAt, &e.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return vault.Entry{}, notFound(k)
	}
	if err != nil {
		return vault.Entry{}, fmt.Errorf("look up %s: %w", k, err)
	}
	e.Settings = decodeSettings(meta)
	return e, nil
}

// List implements vault.Store.
func (s *Store) List(f vault.Filter) (_ []vault.Entry, err error) {
	prefix := entryPrefix
	if f.Kind != "" {
		prefix += string(f.Kind) + "/"
	}
	// A range rather than LIKE, so "%" and "_" in names need no escaping.
	rows, err := s.db.Query(`SELECT service, metadata, created_at, updated_at FROM passwords WHERE service >= ? AND service < ? ORDER BY service`, prefix, prefix+"\xff")
	if err != nil {
		return nil, fmt.Errorf("list entries: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("list entries: %w", cerr)
		}
	}()
	var out []vault.Entry
	for rows.Next() {
		var name string
		var meta sql.NullString
		var e vault.Entry
		if err := rows.Scan(&name, &meta, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, fmt.Errorf("list entries: %w", err)
		}
		k, err := vault.ParseKey(strings.TrimPrefix(name, entryPrefix))
		if err != nil {
			continue // not an entry this interface names
		}
		e.Key, e.Settings = k, decodeSettings(meta)
		if f.Matches(&e) {
			out = append(out, e)
		}
	}
	return out, rows.Err()
}

// Delete implements vault.Store.
func (s *Store) Delete(k vault.Key) error {
	name, err := storedName(k)
	if err != nil {
		return err
	}
	res, err := s.db.Exec(`DELETE FROM passwords WHERE service = ?`, name)
	if err != nil {
		return fmt.Errorf("delete %s: %w", k, err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("delete %s: %w", k, err)
	} else if n == 0 {
		return notFound(k)
	}
	s.audit("delete", k.String(), "Delete")
	return nil
}
