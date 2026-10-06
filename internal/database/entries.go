package database

import (
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bashhack/sesh/internal/vault"
)

// The vault.Store methods, on the entries table: kind, service name, and
// username are columns, unique together; the secret is encrypted per
// entry; settings are JSON.

var _ vault.Store = (*Store)(nil)

// entryAAD binds an entry's ciphertext to its key: a secret copied into
// another entry's row doesn't decrypt there.
//
// It's part of every stored secret, so its bytes never change: a version
// tag, then the kind, service, and username, each as a 4-byte big-endian
// length and its bytes. The lengths keep fields from running together
// (service "a/b" is not service "a", username "b"), whatever they contain.
func entryAAD(k vault.Key) []byte {
	aad := []byte("sesh-entry-v1")
	for _, f := range []string{string(k.Kind), k.Service, k.Username} {
		aad = binary.BigEndian.AppendUint32(aad, uint32(len(f))) //nolint:gosec // field lengths are far below 4 GiB
		aad = append(aad, f...)
	}
	return aad
}

func notFound(k vault.Key) error {
	return fmt.Errorf("%w: %s", vault.ErrNotFound, k)
}

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

func decodeSettings(k vault.Key, col sql.NullString) (vault.Settings, error) {
	var s vault.Settings
	if !col.Valid {
		return s, nil
	}
	if err := json.Unmarshal([]byte(col.String), &s); err != nil {
		return s, fmt.Errorf("read the settings of %s: %w", k, err)
	}
	return s, nil
}

// Get implements vault.Store.
func (s *Store) Get(k vault.Key) ([]byte, error) {
	var encData, salt []byte
	err := s.db.QueryRow(`SELECT encrypted_data, salt FROM entries WHERE kind = ? AND service = ? AND username = ?`,
		string(k.Kind), k.Service, k.Username).Scan(&encData, &salt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, notFound(k)
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", k, err)
	}
	secret, err := s.oracle.DecryptEntry(encData, salt, entryAAD(k))
	if err != nil {
		if kerr := s.keyUnchanged(s.db); errors.Is(kerr, ErrVaultKeyChanged) {
			err = kerr
		}
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
	if err := e.Key.Validate(); err != nil {
		return err
	}
	if len(secret) > MaxSecretSize {
		return fmt.Errorf("%w: %d bytes (max %d)", ErrSecretTooLarge, len(secret), MaxSecretSize)
	}
	settings, err := encodeSettings(e.Settings)
	if err != nil {
		return err
	}
	encData, salt, err := s.oracle.EncryptEntry(secret, entryAAD(e.Key))
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
		onConflict += `, settings = excluded.settings, created_at = excluded.created_at`
	}
	err = s.inTx(func(tx *sql.Tx) error {
		_, err := tx.Exec(`
			INSERT INTO entries (kind, service, username, encrypted_data, salt, settings, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (kind, service, username) DO UPDATE SET `+onConflict,
			string(e.Kind), e.Service, e.Username, encData, salt, settings, created, updated,
		)
		return err
	})
	if err != nil {
		return fmt.Errorf("store %s: %w", e.Key, err)
	}
	detail := "Put"
	if whole {
		detail = "Save"
	}
	s.audit("modify", e.Key.String(), detail)
	return nil
}

// SetSettings implements vault.Store.
func (s *Store) SetSettings(k vault.Key, settings vault.Settings) error {
	col, err := encodeSettings(settings)
	if err != nil {
		return err
	}
	var res sql.Result
	err = s.inTx(func(tx *sql.Tx) (err error) {
		res, err = tx.Exec(`UPDATE entries SET settings = ?, updated_at = ? WHERE kind = ? AND service = ? AND username = ?`,
			col, time.Now().UTC(), string(k.Kind), k.Service, k.Username)
		return err
	})
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
	var col sql.NullString
	e := vault.Entry{Key: k}
	err := s.db.QueryRow(`SELECT settings, created_at, updated_at FROM entries WHERE kind = ? AND service = ? AND username = ?`,
		string(k.Kind), k.Service, k.Username).Scan(&col, &e.CreatedAt, &e.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return vault.Entry{}, notFound(k)
	}
	if err != nil {
		return vault.Entry{}, fmt.Errorf("look up %s: %w", k, err)
	}
	if e.Settings, err = decodeSettings(k, col); err != nil {
		return vault.Entry{}, err
	}
	return e, nil
}

// List implements vault.Store.
func (s *Store) List(f vault.Filter) (_ []vault.Entry, err error) {
	q := `SELECT kind, service, username, settings, created_at, updated_at FROM entries WHERE 1 = 1`
	var args []any
	if f.Kind != "" {
		q += ` AND kind = ?`
		args = append(args, string(f.Kind))
	}
	if f.Service != "" {
		q += ` AND service = ?`
		args = append(args, f.Service)
	}
	rows, err := s.db.Query(q+` ORDER BY kind, service, username`, args...)
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
		var e vault.Entry
		var kind string
		var col sql.NullString
		if err := rows.Scan(&kind, &e.Service, &e.Username, &col, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, fmt.Errorf("list entries: %w", err)
		}
		e.Kind = vault.Kind(kind)
		if e.Settings, err = decodeSettings(e.Key, col); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// DeleteMany implements vault.Store: the entries go in one transaction.
func (s *Store) DeleteMany(keys []vault.Key) error {
	err := s.inTx(func(tx *sql.Tx) error {
		for _, k := range keys {
			res, err := tx.Exec(`DELETE FROM entries WHERE kind = ? AND service = ? AND username = ?`, string(k.Kind), k.Service, k.Username)
			if err != nil {
				return fmt.Errorf("delete %s: %w", k, err)
			}
			if n, err := res.RowsAffected(); err != nil {
				return fmt.Errorf("delete %s: %w", k, err)
			} else if n == 0 {
				return notFound(k)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, k := range keys {
		s.audit("delete", k.String(), "Delete")
	}
	return nil
}

// Delete implements vault.Store.
func (s *Store) Delete(k vault.Key) error {
	var res sql.Result
	err := s.inTx(func(tx *sql.Tx) (err error) {
		res, err = tx.Exec(`DELETE FROM entries WHERE kind = ? AND service = ? AND username = ?`, string(k.Kind), k.Service, k.Username)
		return err
	})
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
