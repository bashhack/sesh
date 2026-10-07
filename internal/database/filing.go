package database

import (
	"database/sql"
	"fmt"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/bashhack/sesh/internal/vault"
)

// Changing where entries are filed: their folder and tags. These don't
// touch secrets, and an entry's update time stays, since its content
// doesn't change. Each change is one transaction, all or none, and one
// "modify" audit event per entry it changes.

// noSuch is a folder or tag no entry has. It wraps vault.ErrNotFound.
type noSuch struct{ what, name string }

func (e noSuch) Error() string { return fmt.Sprintf("there's no %s %q", e.what, e.name) }
func (e noSuch) Unwrap() error { return vault.ErrNotFound }

// entryIDs returns the row ids of keys, each once, or an error wrapping
// vault.ErrNotFound for the first missing one.
func entryIDs(tx *sql.Tx, keys []vault.Key) (map[vault.Key]int64, error) {
	ids := make(map[vault.Key]int64, len(keys))
	for _, k := range keys {
		if _, ok := ids[k]; ok {
			continue
		}
		var id int64
		err := tx.QueryRow(`SELECT id FROM entries WHERE kind = ? AND service = ? AND username = ?`,
			string(k.Kind), k.Service, k.Username).Scan(&id)
		if err == sql.ErrNoRows {
			return nil, notFound(k)
		}
		if err != nil {
			return nil, fmt.Errorf("look up %s: %w", k, err)
		}
		ids[k] = id
	}
	return ids, nil
}

// changeEach runs change on each of keys' rows in one transaction, all or
// none, and audits the entries it reports changing, with detail. It
// returns how many changed.
func (s *Store) changeEach(keys []vault.Key, detail string, change func(tx *sql.Tx, id int64) (bool, error)) (int, error) {
	var changed []vault.Key
	err := s.inTx(func(tx *sql.Tx) error {
		ids, err := entryIDs(tx, keys)
		if err != nil {
			return err
		}
		changed = changed[:0]
		for _, k := range keys {
			id, ok := ids[k]
			if !ok {
				continue // named twice
			}
			delete(ids, k)
			did, err := change(tx, id)
			if err != nil {
				return fmt.Errorf("change %s: %w", k, err)
			}
			if did {
				changed = append(changed, k)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	for _, k := range changed {
		s.audit("modify", k.String(), detail)
	}
	return len(changed), nil
}

// rowsChanged reports whether res changed a row.
func rowsChanged(res sql.Result, err error) (bool, error) {
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// MoveToFolder files the entries keys name in folder ("" for none),
// returning how many moved; those already there don't count.
func (s *Store) MoveToFolder(keys []vault.Key, folder string) (int, error) {
	if err := vault.CheckFolder(folder); err != nil {
		return 0, err
	}
	return s.changeEach(keys, "Folder", func(tx *sql.Tx, id int64) (bool, error) {
		return rowsChanged(tx.Exec(`UPDATE entries SET folder = ? WHERE id = ? AND folder <> ?`, folder, id, folder))
	})
}

// AddTag tags the entries keys name, returning how many didn't have it.
func (s *Store) AddTag(keys []vault.Key, tag string) (int, error) {
	if err := vault.CheckTag(tag); err != nil {
		return 0, err
	}
	return s.changeEach(keys, "Tag", func(tx *sql.Tx, id int64) (bool, error) {
		return rowsChanged(tx.Exec(`INSERT OR IGNORE INTO entry_tags (entry_id, tag) VALUES (?, ?)`, id, tag))
	})
}

// RemoveTag takes tag off the entries keys name, returning how many had it.
func (s *Store) RemoveTag(keys []vault.Key, tag string) (int, error) {
	if err := vault.CheckTag(tag); err != nil {
		return 0, err
	}
	return s.changeEach(keys, "Untag", func(tx *sql.Tx, id int64) (bool, error) {
		return rowsChanged(tx.Exec(`DELETE FROM entry_tags WHERE entry_id = ? AND tag = ?`, id, tag))
	})
}

// RenameFolder renames folder from, and the folders under it, to to,
// returning how many entries moved. When to was already in use, the two
// merge, and merged says so. A folder can't move under itself.
func (s *Store) RenameFolder(from, to string) (n int, merged bool, err error) {
	switch {
	case from == "":
		return 0, false, fmt.Errorf("name the folder to rename")
	case to == "":
		return 0, false, fmt.Errorf("name the folder's new name; to take entries out of a folder: sesh folder move \"\" <id>…")
	case from == to:
		return 0, false, fmt.Errorf("the folder is already called %q", to)
	case vault.InFolder(to, from):
		return 0, false, fmt.Errorf("can't move folder %q into a folder under itself (%q)", from, to)
	}
	if err := vault.CheckFolder(from); err != nil {
		return 0, false, err
	}
	if err := vault.CheckFolder(to); err != nil {
		return 0, false, err
	}
	var moved []vault.Key
	err = s.inTx(func(tx *sql.Tx) error {
		inFrom, err := keysInFolder(tx, from)
		if err != nil {
			return err
		}
		if len(inFrom) == 0 {
			return noSuch{"folder", from}
		}
		inTo, err := keysInFolder(tx, to)
		if err != nil {
			return err
		}
		merged = len(inTo) > 0
		// from's own entries go to to; one in from/x goes to to/x.
		if _, err := tx.Exec(`UPDATE entries SET folder = ? || substr(folder, length(?) + 1)
			WHERE folder = ? OR substr(folder, 1, length(?) + 1) = ? || '/'`, to, from, from, from, from); err != nil {
			return err
		}
		moved = inFrom
		return nil
	})
	if err != nil {
		return 0, false, err
	}
	for _, k := range moved {
		s.audit("modify", k.String(), "Folder")
	}
	return len(moved), merged, nil
}

// keysInFolder returns the entries in folder or one under it.
func keysInFolder(tx *sql.Tx, folder string) ([]vault.Key, error) {
	return queryKeys(tx, `SELECT kind, service, username FROM entries
		WHERE folder = ? OR substr(folder, 1, length(?) + 1) = ? || '/'`, folder, folder, folder)
}

// RenameTag renames tag from to to on every entry, returning how many
// entries had it. When to was already in use, the two merge, and merged
// says so; an entry with both keeps one.
func (s *Store) RenameTag(from, to string) (n int, merged bool, err error) {
	if from == to {
		return 0, false, fmt.Errorf("the tag is already called %q", to)
	}
	if err := vault.CheckTag(from); err != nil {
		return 0, false, err
	}
	if err := vault.CheckTag(to); err != nil {
		return 0, false, err
	}
	var tagged []vault.Key
	err = s.inTx(func(tx *sql.Tx) error {
		var err error
		tagged, err = queryKeys(tx, `SELECT e.kind, e.service, e.username FROM entries e JOIN entry_tags t ON t.entry_id = e.id WHERE t.tag = ?`, from)
		if err != nil {
			return err
		}
		if len(tagged) == 0 {
			return noSuch{"tag", from}
		}
		if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM entry_tags WHERE tag = ?)`, to).Scan(&merged); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO entry_tags (entry_id, tag) SELECT entry_id, ? FROM entry_tags WHERE tag = ?`, to, from); err != nil {
			return err
		}
		_, err = tx.Exec(`DELETE FROM entry_tags WHERE tag = ?`, from)
		return err
	})
	if err != nil {
		return 0, false, err
	}
	for _, k := range tagged {
		s.audit("modify", k.String(), "Tag")
	}
	return len(tagged), merged, nil
}

// queryKeys returns the keys q's rows (kind, service, username) name.
func queryKeys(tx *sql.Tx, q string, args ...any) (_ []vault.Key, err error) {
	rows, err := tx.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := rows.Close(); err == nil {
			err = cerr
		}
	}()
	var keys []vault.Key
	for rows.Next() {
		var k vault.Key
		var kind string
		if err := rows.Scan(&kind, &k.Service, &k.Username); err != nil {
			return nil, err
		}
		k.Kind = vault.Kind(kind)
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// FolderCount is a folder and how many entries it holds: Entries in it
// alone, Total with its subfolders'. Name "" counts the entries in no
// folder.
type FolderCount struct {
	Name           string
	Entries, Total int
}

// Folders returns every folder, with the folders above them that hold no
// entries of their own, ordered part by part so subfolders follow their
// folder. The entries in no folder come first, when there are any.
func (s *Store) Folders() ([]FolderCount, error) {
	rows, err := s.db.Query(`SELECT folder, count(*) FROM entries GROUP BY folder`)
	if err != nil {
		return nil, fmt.Errorf("list folders: %w", err)
	}
	own := map[string]int{}
	for rows.Next() {
		var folder string
		var n int
		if err := rows.Scan(&folder, &n); err != nil {
			_ = rows.Close() //nolint:errcheck // already failing
			return nil, fmt.Errorf("list folders: %w", err)
		}
		own[folder] = n
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("list folders: %w", err)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list folders: %w", err)
	}
	total := map[string]int{}
	for folder, n := range own {
		if folder == "" {
			total[""] += n
			continue
		}
		for p := folder; p != "."; p = path.Dir(p) {
			total[p] += n
		}
	}
	out := make([]FolderCount, 0, len(total))
	for name, t := range total {
		out = append(out, FolderCount{Name: name, Entries: own[name], Total: t})
	}
	slices.SortFunc(out, func(a, b FolderCount) int {
		if a.Name == "" || b.Name == "" {
			return strings.Compare(a.Name, b.Name)
		}
		return slices.Compare(strings.Split(a.Name, "/"), strings.Split(b.Name, "/"))
	})
	return out, nil
}

// TagCount is a tag and how many entries have it.
type TagCount struct {
	Name    string
	Entries int
}

// Tags returns every tag in name order, and how many entries have none.
func (s *Store) Tags() (tags []TagCount, untagged int, err error) {
	rows, err := s.db.Query(`SELECT tag, count(*) FROM entry_tags GROUP BY tag`)
	if err != nil {
		return nil, 0, fmt.Errorf("list tags: %w", err)
	}
	for rows.Next() {
		var t TagCount
		if err := rows.Scan(&t.Name, &t.Entries); err != nil {
			_ = rows.Close() //nolint:errcheck // already failing
			return nil, 0, fmt.Errorf("list tags: %w", err)
		}
		tags = append(tags, t)
	}
	if err := rows.Close(); err != nil {
		return nil, 0, fmt.Errorf("list tags: %w", err)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("list tags: %w", err)
	}
	sort.Slice(tags, func(i, j int) bool { return tags[i].Name < tags[j].Name })
	if err := s.db.QueryRow(`SELECT count(*) FROM entries WHERE NOT EXISTS (SELECT 1 FROM entry_tags WHERE entry_id = entries.id)`).Scan(&untagged); err != nil {
		return nil, 0, fmt.Errorf("list tags: %w", err)
	}
	return tags, untagged, nil
}
