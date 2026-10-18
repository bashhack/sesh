package database

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/secure"
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

func encodeSettings(s *vault.Settings) (sql.NullString, error) {
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
	return s.get(k, "Get")
}

// GetFor is Get, recording in the audit log what the secret was read
// for: reading, such as "secret, to run".
func (s *Store) GetFor(k vault.Key, reading string) ([]byte, error) {
	return s.get(k, "Read: "+reading)
}

// CodeKey is the TOTP entry k's key, for drawing its codes on screen,
// which the audit log doesn't record, as it does reading a secret: a code
// shown isn't one copied or revealed. Only a TOTP entry's key is read so.
func (s *Store) CodeKey(k vault.Key) ([]byte, error) {
	if k.Kind != vault.KindTOTP {
		return nil, fmt.Errorf("%s isn't a TOTP entry: only a TOTP key is read for drawing codes", k)
	}
	return s.get(k, "")
}

// get is Get, with detail as the audit event's; "" records none.
func (s *Store) get(k vault.Key, detail string) ([]byte, error) {
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
	if detail != "" {
		s.audit("access", k.String(), detail)
	}
	return secret, nil
}

// Put implements vault.Store.
func (s *Store) Put(k vault.Key, secret []byte) error {
	return s.write(&vault.Entry{Key: k}, secret, false, nil, nil, nil)
}

// Save implements vault.Store.
func (s *Store) Save(e *vault.Entry, secret []byte) error {
	return s.write(e, secret, true, nil, nil, nil)
}

// SaveWithDetails implements vault.Store.
func (s *Store) SaveWithDetails(e *vault.Entry, secret []byte, d *vault.Details) error {
	if err := d.Check(e.Kind); err != nil {
		return err
	}
	return s.write(e, secret, true, d, nil, nil)
}

// write stores e's secret. whole also replaces its settings, folder, tags,
// and times (a zero creation time keeps the one it has); otherwise an
// existing entry keeps them, except its update time. Details, when not nil, replace the entry's in the same write.
// earlier, the newest first, go into the entry's history below what it
// has (see SaveImported), and got, when not nil, says what became of them.
func (s *Store) write(e *vault.Entry, secret []byte, whole bool, d *vault.Details, earlier []vault.Earlier, got *ImportedHistory) error {
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
	if err := vault.CheckFileName(e.Settings.FileName); err != nil {
		return err
	}
	settings, err := encodeSettings(&e.Settings)
	if err != nil {
		return err
	}
	// With history kept, a secret it replaces is kept there, sealed here,
	// outside the transaction, as Edit's sealing is, and the write checks
	// the entry is as read: absent, or with that secret, so another
	// command's store in between isn't replaced without being kept.
	// An entry stored over with the secret it has keeps its times, which
	// say when its secret last changed; the write keeps them only while
	// its secret is still the one compared.
	var old *oldSecret
	var data, oldSalt []byte
	var oldSettings sql.NullString
	var was sealedDetails
	keeping, existed, same := s.historyKeep > 0, false, false
	switch err := s.db.QueryRow(`SELECT encrypted_data, salt, settings, url, details, sealed_details, details_salt FROM entries WHERE kind = ? AND service = ? AND username = ?`,
		string(e.Kind), e.Service, e.Username).Scan(&data, &oldSalt, &oldSettings, &was.url, &was.plain, &was.sealed, &was.salt); {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return fmt.Errorf("read %s: %w", e.Key, err)
	case keeping:
		existed = true
		if old, err = s.replacing(e.Key, e.Key, data, oldSalt, secret); err != nil {
			return err
		}
		if old == nil {
			old = &oldSecret{from: data}
		}
		same = old.same
		// A file's name goes into the history with it.
		if had, err := decodeSettings(e.Key, oldSettings); err == nil {
			old.fileName = had.FileName
		}
	default:
		existed = true
		if same, err = s.sameSecret(e.Key, data, oldSalt, secret); err != nil {
			return err
		}
	}
	mend := false
	if existed {
		// Times that don't read (damage) aren't kept: this write mends
		// both, whatever the secret.
		var created, updated time.Time
		if err := s.db.QueryRow(`SELECT created_at, updated_at FROM entries WHERE kind = ? AND service = ? AND username = ?`, string(e.Kind), e.Service, e.Username).Scan(&created, &updated); err != nil {
			same, mend = false, true
		} else if old != nil {
			old.set = updated
		}
	}
	var imported *importedHistory
	if keeping && len(earlier) > 0 {
		if imported, err = s.sealEarlier(e.Key, secret, data, oldSalt, old, earlier); err != nil {
			return err
		}
	}
	// The secret it has is kept as it's sealed: sealing it again would
	// change nothing but cost a key derivation.
	encData, salt := data, oldSalt
	if !same {
		if encData, salt, err = s.oracle.EncryptEntry(secret, entryAAD(e.Key)); err != nil {
			return fmt.Errorf("encrypt %s: %w", e.Key, err)
		}
	}
	var sd sealedDetails
	if d != nil {
		var had *sealedDetails
		if existed {
			had = &was
		}
		if sd, err = s.sealDetails(e.Key, d, had); err != nil {
			return err
		}
	}
	now := time.Now().UTC()
	created, updated := e.CreatedAt, e.UpdatedAt
	if created.IsZero() {
		created = now
	}
	if updated.IsZero() {
		updated = now
	}
	// With the same secret and no times given, the entry keeps its own,
	// so long as its secret is still the one compared: another command's
	// write in between (unchecked without history) makes these new times.
	onConflict := `encrypted_data = excluded.encrypted_data, salt = excluded.salt`
	var keepTimes []any
	keepTime := func(col string) string {
		keepTimes = append(keepTimes, data)
		return `, ` + col + ` = CASE WHEN entries.encrypted_data = ? THEN entries.` + col + ` ELSE excluded.` + col + ` END`
	}
	if same && e.UpdatedAt.IsZero() {
		onConflict += keepTime("updated_at")
	} else {
		onConflict += `, updated_at = excluded.updated_at`
	}
	switch {
	case whole && same && e.CreatedAt.IsZero():
		onConflict += `, settings = excluded.settings, folder = excluded.folder` + keepTime("created_at")
	case whole && e.CreatedAt.IsZero() && !mend:
		// A new secret doesn't make it a new entry: it keeps when it was
		// made.
		onConflict += `, settings = excluded.settings, folder = excluded.folder`
	case whole:
		onConflict += `, settings = excluded.settings, folder = excluded.folder, created_at = excluded.created_at`
	case mend:
		onConflict += `, created_at = excluded.created_at`
	}
	if !whole && e.Kind == vault.KindFile && e.Settings.FileName != "" {
		// A file entry's settings are its file's name alone.
		onConflict += `, settings = excluded.settings`
	}
	if d != nil {
		onConflict += `, url = excluded.url, details = excluded.details, sealed_details = excluded.sealed_details, details_salt = excluded.details_salt`
	}
	err = s.inTx(func(tx *sql.Tx) error {
		if keeping {
			var dataNow []byte
			err := tx.QueryRow(`SELECT encrypted_data FROM entries WHERE kind = ? AND service = ? AND username = ?`, string(e.Kind), e.Service, e.Username).Scan(&dataNow)
			switch {
			case !existed && errors.Is(err, sql.ErrNoRows):
			case !existed, err != nil, !bytes.Equal(dataNow, old.from):
				return ErrEntryChanged
			}
			if err := s.keepImported(tx, e.Key, imported); err != nil {
				return err
			}
			if existed {
				if err := s.keepOld(tx, e.Key, old, now); err != nil {
					return err
				}
			}
		}
		var id int64
		err := tx.QueryRow(`
			INSERT INTO entries (kind, service, username, encrypted_data, salt, settings, folder, url, details, sealed_details, details_salt, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (kind, service, username) DO UPDATE SET `+onConflict+`
			RETURNING id`,
			append([]any{string(e.Kind), e.Service, e.Username, encData, salt, settings, e.Folder, sd.url, sd.plain, sd.sealed, sd.salt, created, updated}, keepTimes...)...,
		).Scan(&id)
		if err != nil || !whole {
			return err
		}
		// Tags it has already aren't written again, so the entry doesn't
		// count as changed.
		var had []string
		rows, err := tx.Query(`SELECT tag FROM entry_tags WHERE entry_id = ? ORDER BY tag`, id)
		if err != nil {
			return err
		}
		for rows.Next() {
			var t string
			if err := rows.Scan(&t); err != nil {
				_ = rows.Close() //nolint:errcheck // already failing
				return err
			}
			had = append(had, t)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return err
		}
		if slices.Equal(had, tags) {
			return nil
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
	if n := imported.count(); n > 0 {
		detail += fmt.Sprintf(", with %d earlier secrets imported", n)
		if n == 1 {
			detail = strings.TrimSuffix(detail, "s imported") + " imported"
		}
	}
	s.audit("modify", e.Key.String(), detail)
	if got != nil {
		*got = imported.result()
	}
	return nil
}

// SetSettings implements vault.Store.
func (s *Store) SetSettings(k vault.Key, settings *vault.Settings) error {
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
	var sealedSize int64
	err := s.db.QueryRow(`SELECT settings, folder, `+tagsColumn+`, url, details, created_at, updated_at, length(encrypted_data) FROM entries WHERE kind = ? AND service = ? AND username = ?`,
		string(k.Kind), k.Service, k.Username).Scan(&col, &e.Folder, &tags, &url, &details, &e.CreatedAt, &e.UpdatedAt, &sealedSize)
	if errors.Is(err, sql.ErrNoRows) {
		return vault.Entry{}, notFound(k)
	}
	if err != nil {
		return vault.Entry{}, fmt.Errorf("look up %s: %w", k, err)
	}
	if e.Settings, err = decodeSettings(k, col); err != nil {
		return vault.Entry{}, err
	}
	e.Size = plainSize(sealedSize)
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
	q.WriteString(`SELECT kind, service, username, settings, folder, ` + tagsColumn + `, url, details, created_at, updated_at, length(encrypted_data) FROM entries WHERE 1 = 1`)
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
		var sealedSize int64
		if err := rows.Scan(&kind, &e.Service, &e.Username, &col, &e.Folder, &tags, &url, &details, &e.CreatedAt, &e.UpdatedAt, &sealedSize); err != nil {
			return nil, fmt.Errorf("list entries: %w", err)
		}
		e.Kind = vault.Kind(kind)
		e.Size = plainSize(sealedSize)
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

// DeleteMany implements vault.Store: the entries go, in one transaction,
// into the trash, or for good when it keeps none (see SetTrashDays).
func (s *Store) DeleteMany(keys []vault.Key) error {
	return s.deleteMany(keys, false)
}

// Delete implements vault.Store, as DeleteMany does one entry.
func (s *Store) Delete(k vault.Key) error {
	return s.deleteMany([]vault.Key{k}, false)
}

// deleteMany deletes the entries in one transaction: into the trash,
// unless purge or the store keeps none.
func (s *Store) deleteMany(keys []vault.Key, purge bool) error {
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
	toTrash := !purge && s.trashDays > 0
	now := time.Now().UTC()
	err := s.inTx(func(tx *sql.Tx) error {
		for _, k := range keys {
			var id int64
			err := tx.QueryRow(`SELECT id FROM entries WHERE kind = ? AND service = ? AND username = ?`, string(k.Kind), k.Service, k.Username).Scan(&id)
			if errors.Is(err, sql.ErrNoRows) {
				return notFound(k)
			}
			if err == nil && toTrash {
				err = trash(tx, id, k, now)
			} else if err == nil {
				err = forget(tx, id, k)
			}
			if err != nil {
				return fmt.Errorf("delete %s: %w", k, err)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, k := range keys {
		if toTrash {
			s.audit("trash", k.String(), "Moved to the trash")
		} else {
			s.audit("delete", k.String(), "Delete")
		}
	}
	return nil
}

// EachSecret calls each with every entry of kinds and its secret,
// decrypted, which it zeroes after each call, and records the reads as one
// audit event: "<reading>: read N secrets". Other kinds' secrets aren't
// read. An entry whose secret doesn't decrypt (ErrDecrypt) is handed to
// each with that error and no secret; one deleted meanwhile is passed
// over. Any other error, or one from each, stops it.
func (s *Store) EachSecret(reading string, kinds []vault.Kind, each func(e *vault.Entry, secret []byte, err error) error) (n int, err error) {
	entries, err := s.List(&vault.Filter{})
	if err != nil {
		return 0, err
	}
	defer func() {
		if n > 0 {
			word := "secrets"
			if n == 1 {
				word = "secret"
			}
			s.audit("access", "", fmt.Sprintf("%s: read %d %s", reading, n, word))
		}
	}()
	for i := range entries {
		if !slices.Contains(kinds, entries[i].Kind) {
			continue
		}
		secret, err := s.get(entries[i].Key, "")
		switch {
		case errors.Is(err, vault.ErrNotFound):
			continue
		case errors.Is(err, ErrDecrypt):
			if err := each(&entries[i], nil, err); err != nil {
				return n, err
			}
			continue
		case err != nil:
			return n, err
		}
		n++
		err = each(&entries[i], secret, nil)
		secure.SecureZeroBytes(secret)
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
