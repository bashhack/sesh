package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bashhack/sesh/internal/vault"
)

// TrashedEntry is an entry in the trash.
type TrashedEntry struct {
	DeletedAt time.Time
	vault.Entry
	ID int64 // its trash id, which sesh trash names it by
}

// ErrNotInTrash is a trash id with no entry.
var ErrNotInTrash = errors.New("no entry in the trash has that id")

// SetTrashDays sets how many days a deleted entry stays in the trash; 0
// means none do, and deleting is for good. A new Store keeps none.
func (s *Store) SetTrashDays(days int) { s.trashDays = days }

// TrashDays is how many days a deleted entry stays in the trash.
func (s *Store) TrashDays() int { return s.trashDays }

// trash moves the entry in row id into the trash, in tx, its tags with it.
func trash(tx *sql.Tx, id int64, at time.Time) error {
	if _, err := tx.Exec(`
		INSERT INTO trash (kind, service, username, encrypted_data, salt, settings, folder, url, details, sealed_details, details_salt, tags, created_at, updated_at, deleted_at)
		SELECT kind, service, username, encrypted_data, salt, settings, folder, url, details, sealed_details, details_salt,
			(SELECT COALESCE(json_group_array(tag), '[]') FROM (SELECT tag FROM entry_tags WHERE entry_id = e.id ORDER BY tag)),
			created_at, updated_at, ?
		FROM entries e WHERE id = ?`, at, id); err != nil {
		return err
	}
	_, err := tx.Exec(`DELETE FROM entries WHERE id = ?`, id)
	return err
}

// PurgeMany deletes the entries for good, not into the trash, in one
// transaction.
func (s *Store) PurgeMany(keys []vault.Key) error {
	return s.deleteMany(keys, true)
}

// Trash lists the trash, the most recently deleted first.
func (s *Store) Trash() (_ []TrashedEntry, err error) {
	rows, err := s.db.Query(`SELECT id, kind, service, username, folder, tags, created_at, updated_at, deleted_at FROM trash ORDER BY deleted_at DESC, id DESC`)
	if err != nil {
		return nil, fmt.Errorf("read the trash: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("read the trash: %w", cerr)
		}
	}()
	var out []TrashedEntry
	for rows.Next() {
		var t TrashedEntry
		var kind, tags string
		if err := rows.Scan(&t.ID, &kind, &t.Service, &t.Username, &t.Folder, &tags, &t.CreatedAt, &t.UpdatedAt, &t.DeletedAt); err != nil {
			return nil, fmt.Errorf("read the trash: %w", err)
		}
		t.Kind = vault.Kind(kind)
		if err := json.Unmarshal([]byte(tags), &t.Tags); err != nil {
			return nil, fmt.Errorf("read the tags of %s in the trash: %w", t.Key, err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RestoreFromTrash puts the trash's entry id back, under as when it isn't
// the zero Key (its secret and details sealed again for that name), and
// returns the name it has. A name another entry has is refused with
// ErrNameTaken; as must keep the entry's kind.
func (s *Store) RestoreFromTrash(id int64, as vault.Key) (vault.Key, error) {
	var to vault.Key
	err := s.inTx(func(tx *sql.Tx) error {
		var kind, tags string
		var settings sql.NullString
		var e vault.Entry
		var data, salt, sealed, detailsSalt []byte
		var url, details string
		var deletedAt time.Time
		err := tx.QueryRow(`SELECT kind, service, username, encrypted_data, salt, settings, folder, url, details, sealed_details, details_salt, tags, created_at, updated_at, deleted_at FROM trash WHERE id = ?`, id).
			Scan(&kind, &e.Service, &e.Username, &data, &salt, &settings, &e.Folder, &url, &details, &sealed, &detailsSalt, &tags, &e.CreatedAt, &e.UpdatedAt, &deletedAt)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: %d", ErrNotInTrash, id)
		}
		if err != nil {
			return fmt.Errorf("read the trash: %w", err)
		}
		e.Kind = vault.Kind(kind)
		to = e.Key
		if as != (vault.Key{}) {
			if as.Kind != e.Kind {
				return fmt.Errorf("%s is a %s entry; restore it under another %s name", e.Key, e.Kind, e.Kind)
			}
			if err := as.Validate(); err != nil {
				return err
			}
			to = as
		}
		if err := s.nameFree(tx, to, 0); err != nil {
			if errors.Is(err, ErrNameTaken) {
				return fmt.Errorf("%w: %s already exists: rename or delete it first, or restore with --as <new name>", ErrNameTaken, to)
			}
			return err
		}
		if err := s.keyUnchanged(tx); err != nil {
			return err
		}
		if to != e.Key {
			if data, salt, err = s.resealSecret(e.Key, to, data, salt, nil); err != nil {
				return err
			}
			if sealed != nil {
				if sealed, detailsSalt, err = s.resealDetails(e.Key, to, sealed, detailsSalt); err != nil {
					return err
				}
			}
		}
		var newID int64
		if err := tx.QueryRow(`
			INSERT INTO entries (kind, service, username, encrypted_data, salt, settings, folder, url, details, sealed_details, details_salt, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
			string(to.Kind), to.Service, to.Username, data, salt, settings, e.Folder, url, details, sealed, detailsSalt, e.CreatedAt, e.UpdatedAt).Scan(&newID); err != nil {
			return fmt.Errorf("restore %s: %w", to, err)
		}
		var tagList []string
		if err := json.Unmarshal([]byte(tags), &tagList); err != nil {
			return fmt.Errorf("read the tags of %s in the trash: %w", e.Key, err)
		}
		for _, t := range tagList {
			if _, err := tx.Exec(`INSERT INTO entry_tags (entry_id, tag) VALUES (?, ?)`, newID, t); err != nil {
				return fmt.Errorf("restore the tags of %s: %w", to, err)
			}
		}
		_, err = tx.Exec(`DELETE FROM trash WHERE id = ?`, id)
		return err
	})
	if err != nil {
		return vault.Key{}, err
	}
	s.audit("restore", to.String(), "Restored from the trash")
	return to, nil
}

// RemoveFromTrash deletes the trash's entry id for good, and returns its
// name.
func (s *Store) RemoveFromTrash(id int64) (vault.Key, error) {
	var k vault.Key
	err := s.inTx(func(tx *sql.Tx) error {
		var kind string
		err := tx.QueryRow(`DELETE FROM trash WHERE id = ? RETURNING kind, service, username`, id).Scan(&kind, &k.Service, &k.Username)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: %d", ErrNotInTrash, id)
		}
		k.Kind = vault.Kind(kind)
		return err
	})
	if err != nil {
		return vault.Key{}, err
	}
	s.audit("purge", k.String(), "Removed from the trash")
	return k, nil
}

// EmptyTrash deletes every entry in the trash for good, and returns how
// many there were.
func (s *Store) EmptyTrash() (int, error) {
	return s.purgeTrash(`DELETE FROM trash RETURNING kind, service, username`, "Trash emptied")
}

// ExpireTrash deletes for good the entries deleted before cutoff, and
// returns how many.
func (s *Store) ExpireTrash(cutoff time.Time) (int, error) {
	return s.purgeTrash(`DELETE FROM trash WHERE deleted_at < ? RETURNING kind, service, username`, "Kept its days in the trash", cutoff.UTC())
}

// purgeTrash runs query, a DELETE FROM trash returning the names deleted,
// and logs each with detail.
func (s *Store) purgeTrash(query, detail string, args ...any) (int, error) {
	var gone []vault.Key
	err := s.inTx(func(tx *sql.Tx) (err error) {
		rows, err := tx.Query(query, args...)
		if err != nil {
			return err
		}
		defer func() {
			if cerr := rows.Close(); err == nil {
				err = cerr
			}
		}()
		for rows.Next() {
			var k vault.Key
			var kind string
			if err := rows.Scan(&kind, &k.Service, &k.Username); err != nil {
				return err
			}
			k.Kind = vault.Kind(kind)
			gone = append(gone, k)
		}
		return rows.Err()
	})
	if err != nil {
		return 0, fmt.Errorf("empty the trash: %w", err)
	}
	for _, k := range gone {
		s.audit("purge", k.String(), detail)
	}
	return len(gone), nil
}
