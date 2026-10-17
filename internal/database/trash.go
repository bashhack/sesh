package database

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/bashhack/sesh/internal/vault"
)

// TrashedEntry is an entry in the trash.
type TrashedEntry struct {
	DeletedAt time.Time
	vault.Entry
	ID int64 // its trash id, which sesh trash names it by
}

// nameTaken is ErrNameTaken said as msg.
type nameTaken string

func (e nameTaken) Error() string        { return string(e) }
func (e nameTaken) Is(target error) bool { return target == ErrNameTaken }

// ErrNotInTrash is a trash id with no entry.
var ErrNotInTrash = errors.New("no entry in the trash has that id")

// SetTrashDays sets how many days a deleted entry stays in the trash; 0
// means none do, and deleting is for good. A new Store keeps none.
func (s *Store) SetTrashDays(days int) { s.trashDays = days }

// TrashDays is how many days a deleted entry stays in the trash.
func (s *Store) TrashDays() int { return s.trashDays }

// trash moves the entry k, in row id, into the trash, in tx: its tags and
// history with it.
func trash(tx *sql.Tx, id int64, k vault.Key, at time.Time) error {
	var trashID int64
	if err := tx.QueryRow(`
		INSERT INTO trash (uid, rev, kind, service, username, encrypted_data, salt, settings, folder, url, details, sealed_details, details_salt, tags, created_at, updated_at, deleted_at)
		SELECT uid, rev + 1, kind, service, username, encrypted_data, salt, settings, folder, url, details, sealed_details, details_salt,
			(SELECT COALESCE(json_group_array(tag), '[]') FROM (SELECT tag FROM entry_tags WHERE entry_id = e.id ORDER BY tag)),
			created_at, updated_at, ?
		FROM entries e WHERE id = ? RETURNING id`, at, id).Scan(&trashID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE history SET trash_id = ? WHERE kind = ? AND service = ? AND username = ? AND trash_id IS NULL`,
		trashID, string(k.Kind), k.Service, k.Username); err != nil {
		return err
	}
	_, err := tx.Exec(`DELETE FROM entries WHERE id = ?`, id)
	return err
}

// forget deletes the entry k, in row id, for good, in tx: its history with
// it.
func forget(tx *sql.Tx, id int64, k vault.Key) error {
	if _, err := tx.Exec(`DELETE FROM history WHERE kind = ? AND service = ? AND username = ? AND trash_id IS NULL`,
		string(k.Kind), k.Service, k.Username); err != nil {
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

// Trash lists the trash, the most recently deleted first. A row whose
// times or tags don't read is still listed, without them, so it can be
// removed; sesh doctor names what's wrong with it.
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
		var created, updated, deleted any
		if err := rows.Scan(&t.ID, &kind, &t.Service, &t.Username, &t.Folder, &tags, &created, &updated, &deleted); err != nil {
			return nil, fmt.Errorf("read the trash: %w", err)
		}
		t.Kind = vault.Kind(kind)
		t.CreatedAt, _ = created.(time.Time)
		t.UpdatedAt, _ = updated.(time.Time)
		t.DeletedAt, _ = deleted.(time.Time)
		if json.Unmarshal([]byte(tags), &t.Tags) != nil {
			t.Tags = nil
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Restored is an entry put back from the trash: its name, and whether its
// tags were damaged, so it came back without them.
type Restored struct {
	Key      vault.Key
	TagsLost bool
}

// RestoreFromTrash puts the trash's entry id back, under as when it isn't
// the zero Key (its secret and details sealed again for that name), and
// returns the name it has. A name another entry has is refused with
// ErrNameTaken; as must keep the entry's kind. Sealing again happens
// before the write, as Edit's does, and the write checks the entry in the
// trash is as it was read (ErrEntryChanged, if a new master password
// sealed it again meanwhile).
func (s *Store) RestoreFromTrash(id int64, as vault.Key) (Restored, error) {
	type sealedRow struct{ data, salt, sealed, detailsSalt []byte }
	read := func(q querier) (e vault.Entry, r sealedRow, settings sql.NullString, url, details, tags string, err error) {
		var kind string
		var deletedAt time.Time
		err = q.QueryRow(`SELECT kind, service, username, encrypted_data, salt, settings, folder, url, details, sealed_details, details_salt, tags, created_at, updated_at, deleted_at FROM trash WHERE id = ?`, id).
			Scan(&kind, &e.Service, &e.Username, &r.data, &r.salt, &settings, &e.Folder, &url, &details, &r.sealed, &r.detailsSalt, &tags, &e.CreatedAt, &e.UpdatedAt, &deletedAt)
		if errors.Is(err, sql.ErrNoRows) {
			err = fmt.Errorf("%w: %d", ErrNotInTrash, id)
		} else if err != nil {
			err = fmt.Errorf("read the trash: %w", err)
		}
		e.Kind = vault.Kind(kind)
		return e, r, settings, url, details, tags, err
	}
	e, was, _, _, _, _, err := read(s.db)
	if err != nil {
		return Restored{}, err
	}
	to := e.Key
	if as != (vault.Key{}) {
		if as.Kind != e.Kind {
			return Restored{}, fmt.Errorf("%s can be restored only under an ID that starts %s/", e.Key, e.Kind)
		}
		if err := as.Validate(); err != nil {
			return Restored{}, err
		}
		to = as
	}
	now := was
	tagsLost := false
	var history []resealedHistory
	if to != e.Key {
		if history, err = s.resealHistory(e.Key, to, id); err != nil {
			return Restored{}, err
		}
		if now.data, now.salt, err = s.resealSecret(e.Key, to, was.data, was.salt, nil); err != nil {
			return Restored{}, err
		}
		if was.sealed != nil {
			if now.sealed, now.detailsSalt, err = s.resealDetails(e.Key, to, was.sealed, was.detailsSalt); err != nil {
				return Restored{}, err
			}
		}
	}
	err = s.inTx(func(tx *sql.Tx) error {
		e, again, settings, url, details, tags, err := read(tx)
		if err != nil {
			return err
		}
		if !bytes.Equal(again.data, was.data) || !bytes.Equal(again.salt, was.salt) || !bytes.Equal(again.sealed, was.sealed) || !bytes.Equal(again.detailsSalt, was.detailsSalt) {
			return fmt.Errorf("%w (%s, in the trash)", ErrEntryChanged, e.Key)
		}
		if err := s.nameFree(tx, to, 0); err != nil {
			if !errors.Is(err, ErrNameTaken) {
				return err
			}
			if as != (vault.Key{}) {
				return nameTaken(fmt.Sprintf("%s already exists: rename or delete it first, or restore under another name", to))
			}
			return nameTaken(fmt.Sprintf("%s already exists: rename or delete it first, or restore with --as <new name>", to))
		}
		if err := s.keyUnchanged(tx); err != nil {
			return err
		}
		var newID int64
		if err := tx.QueryRow(`
			INSERT INTO entries (uid, rev, kind, service, username, encrypted_data, salt, settings, folder, url, details, sealed_details, details_salt, created_at, updated_at)
			SELECT uid, rev + 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? FROM trash WHERE id = ? RETURNING id`,
			string(to.Kind), to.Service, to.Username, now.data, now.salt, settings, e.Folder, url, details, now.sealed, now.detailsSalt, e.CreatedAt, e.UpdatedAt, id).Scan(&newID); err != nil {
			return fmt.Errorf("restore %s: %w", to, err)
		}
		var tagList []string
		if json.Unmarshal([]byte(tags), &tagList) != nil {
			tagList, tagsLost = nil, true // damaged; it comes back without them
		}
		for _, t := range tagList {
			if _, err := tx.Exec(`INSERT INTO entry_tags (entry_id, tag) VALUES (?, ?)`, newID, t); err != nil {
				return fmt.Errorf("restore the tags of %s: %w", to, err)
			}
		}
		// Its history comes back with it, sealed for its new name if it
		// has one.
		if to != e.Key {
			if err := moveHistory(tx, history, to); err != nil {
				return err
			}
		} else if _, err := tx.Exec(`UPDATE history SET trash_id = NULL WHERE trash_id = ?`, id); err != nil {
			return fmt.Errorf("restore the history of %s: %w", to, err)
		}
		_, err = tx.Exec(`DELETE FROM trash WHERE id = ?`, id)
		return err
	})
	if err != nil {
		return Restored{}, err
	}
	s.audit("restore", to.String(), "Restored from the trash")
	return Restored{Key: to, TagsLost: tagsLost}, nil
}

// RemoveFromTrash deletes the trash's entries ids for good, all or none:
// an id not in the trash deletes nothing. An id named twice counts once.
// It returns their names.
func (s *Store) RemoveFromTrash(ids ...int64) ([]vault.Key, error) {
	ids = slices.Clone(ids)
	slices.Sort(ids)
	ids = slices.Compact(ids)
	var gone []vault.Key
	err := s.inTx(func(tx *sql.Tx) error {
		for _, id := range ids {
			var k vault.Key
			var kind string
			err := tx.QueryRow(`DELETE FROM trash WHERE id = ? RETURNING kind, service, username`, id).Scan(&kind, &k.Service, &k.Username)
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("%w: %d; nothing was removed", ErrNotInTrash, id)
			}
			if err != nil {
				return fmt.Errorf("remove %d from the trash: %w", id, err)
			}
			k.Kind = vault.Kind(kind)
			gone = append(gone, k)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, k := range gone {
		s.audit("purge", k.String(), "Removed from the trash")
	}
	return gone, nil
}

// EmptyTrash deletes every entry in the trash for good, and returns how
// many there were.
func (s *Store) EmptyTrash() (int, error) {
	return s.purgeTrash("empty the trash", `DELETE FROM trash RETURNING kind, service, username`, "Trash emptied")
}

// ExpireTrash deletes for good the entries deleted before cutoff, and
// returns how many.
func (s *Store) ExpireTrash(cutoff time.Time) (int, error) {
	return s.purgeTrash("remove what has been in the trash its days", `DELETE FROM trash WHERE deleted_at < ? RETURNING kind, service, username`, "Kept its days in the trash", cutoff.UTC())
}

// purgeTrash runs query, a DELETE FROM trash returning the names deleted,
// and logs each with detail; what is what it does, in errors.
func (s *Store) purgeTrash(what, query, detail string, args ...any) (int, error) {
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
		return 0, fmt.Errorf("%s: %w", what, err)
	}
	for _, k := range gone {
		s.audit("purge", k.String(), detail)
	}
	return len(gone), nil
}
