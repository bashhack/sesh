package database

import (
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
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
	return keyAAD("sesh-entry-v1", k)
}

// keyAAD is tag, then k's kind, service, and username, each as a 4-byte
// big-endian length and its bytes.
func keyAAD(tag string, k vault.Key) []byte {
	aad := []byte(tag)
	for _, f := range []string{string(k.Kind), k.Service, k.Username} {
		aad = binary.BigEndian.AppendUint32(aad, uint32(len(f))) //nolint:gosec // field lengths are far below 4 GiB
		aad = append(aad, f...)
	}
	return aad
}

// tagsColumn selects an entries row's tags, joined by ",", which a tag
// can't contain; NULL for none.
const tagsColumn = `(SELECT group_concat(tag, ',') FROM entry_tags WHERE entry_id = entries.id)`

// splitTags reads tagsColumn.
func splitTags(col sql.NullString) []string {
	if !col.Valid || col.String == "" {
		return nil
	}
	return vault.NormalizeTags(strings.Split(col.String, ","))
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

// write stores e's secret. whole also replaces its settings, folder, tags,
// and times; otherwise an existing entry keeps them, except its update
// time.
func (s *Store) write(e *vault.Entry, secret []byte, whole bool) error {
	if err := e.Key.Validate(); err != nil {
		return err
	}
	if err := vault.CheckFolder(e.Folder); err != nil {
		return err
	}
	tags := vault.NormalizeTags(e.Tags)
	for _, t := range tags {
		if err := vault.CheckTag(t); err != nil {
			return err
		}
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
		onConflict += `, settings = excluded.settings, folder = excluded.folder, created_at = excluded.created_at`
	}
	err = s.inTx(func(tx *sql.Tx) error {
		var id int64
		err := tx.QueryRow(`
			INSERT INTO entries (kind, service, username, encrypted_data, salt, settings, folder, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (kind, service, username) DO UPDATE SET `+onConflict+`
			RETURNING id`,
			string(e.Kind), e.Service, e.Username, encData, salt, settings, e.Folder, created, updated,
		).Scan(&id)
		if err != nil || !whole {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM entry_tags WHERE entry_id = ?`, id); err != nil {
			return err
		}
		for _, t := range tags {
			if _, err := tx.Exec(`INSERT INTO entry_tags (entry_id, tag) VALUES (?, ?)`, id, t); err != nil {
				return err
			}
		}
		return nil
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
	var col, tags sql.NullString
	var url, details string
	e := vault.Entry{Key: k}
	err := s.db.QueryRow(`SELECT settings, folder, `+tagsColumn+`, url, details, created_at, updated_at FROM entries WHERE kind = ? AND service = ? AND username = ?`,
		string(k.Kind), k.Service, k.Username).Scan(&col, &e.Folder, &tags, &url, &details, &e.CreatedAt, &e.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return vault.Entry{}, notFound(k)
	}
	if err != nil {
		return vault.Entry{}, fmt.Errorf("look up %s: %w", k, err)
	}
	if e.Settings, err = decodeSettings(k, col); err != nil {
		return vault.Entry{}, err
	}
	e.Tags = splitTags(tags)
	if err := vault.DecodeEntryDetails(&e, url, details); err != nil {
		return vault.Entry{}, err
	}
	return e, nil
}

// Exists implements vault.Store.
func (s *Store) Exists(k vault.Key) error {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM entries WHERE kind = ? AND service = ? AND username = ?`,
		string(k.Kind), k.Service, k.Username).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return notFound(k)
	}
	if err != nil {
		return fmt.Errorf("look up %s: %w", k, err)
	}
	return nil
}

// List implements vault.Store.
func (s *Store) List(f *vault.Filter) (_ []vault.Entry, err error) {
	var q strings.Builder
	q.WriteString(`SELECT kind, service, username, settings, folder, ` + tagsColumn + `, url, details, created_at, updated_at FROM entries WHERE 1 = 1`)
	var args []any
	if f.Kind != "" {
		q.WriteString(` AND kind = ?`)
		args = append(args, string(f.Kind))
	}
	if f.Service != "" {
		q.WriteString(` AND service = ?`)
		args = append(args, f.Service)
	}
	// Compared exactly, as text: LIKE would ignore case and read "_" as
	// any character.
	switch {
	case f.FolderSet && f.Folder == "":
		q.WriteString(` AND folder = ''`)
	case f.FolderSet:
		q.WriteString(` AND (folder = ? OR substr(folder, 1, length(?) + 1) = ? || '/')`)
		args = append(args, f.Folder, f.Folder, f.Folder)
	}
	for _, t := range f.Tags {
		q.WriteString(` AND EXISTS (SELECT 1 FROM entry_tags WHERE entry_id = entries.id AND tag = ?)`)
		args = append(args, t)
	}
	q.WriteString(` ORDER BY kind, service, username`)
	rows, err := s.db.Query(q.String(), args...)
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
		var col, tags sql.NullString
		var url, details string
		if err := rows.Scan(&kind, &e.Service, &e.Username, &col, &e.Folder, &tags, &url, &details, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, fmt.Errorf("list entries: %w", err)
		}
		e.Kind = vault.Kind(kind)
		if e.Settings, err = decodeSettings(e.Key, col); err != nil {
			return nil, err
		}
		e.Tags = splitTags(tags)
		if err := vault.DecodeEntryDetails(&e, url, details); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// DeleteMany implements vault.Store: the entries go in one transaction.
func (s *Store) DeleteMany(keys []vault.Key) error {
	keys = slices.Clone(keys)
	slices.SortFunc(keys, func(a, b vault.Key) int {
		switch {
		case a.Less(b):
			return -1
		case b.Less(a):
			return 1
		}
		return 0
	})
	keys = slices.Compact(keys)
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
