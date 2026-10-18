package database

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/syncfolder"
	"github.com/bashhack/sesh/internal/vault"
)

// What syncing the vault with a sync folder (internal/vaultsync) reads of
// it and writes to it. An entry is known by its uid; its rev says whether
// it changed here since it and the folder last agreed (sync_state).

// SyncPlace is where an entry is.
type SyncPlace int

const (
	// SyncLive is an entry in the vault.
	SyncLive SyncPlace = iota + 1
	// SyncTrashed is an entry in the trash.
	SyncTrashed
	// SyncGone is an entry deleted for good (or never here): only what
	// was last agreed of it is left.
	SyncGone
)

// SyncAgreed is what this computer and the folder last agreed on for an
// entry: its rev here then, and the hash of the folder's file (SyncBase is
// the version itself).
type SyncAgreed struct {
	Hash syncfolder.Hash
	Rev  int64
	// Intact says the version agreed is kept as it was sealed (its hash),
	// for this entry, with the vault's key now: it opens without being
	// opened to find out.
	Intact bool
}

// SyncItem is an entry as sync sees it.
type SyncItem struct {
	// Agreed is nil for an entry never synced.
	Agreed *SyncAgreed
	UID    string
	// Key is its name; the zero Key when gone.
	Key   vault.Key
	Place SyncPlace
	// Rev is 0 when gone.
	Rev int64
	// Restored says it was restored from a backup and hasn't synced since;
	// RestoredRev is its rev then (another now: changed since);
	// RestoredChanged, that the backup had it changed and not synced.
	RestoredRev     int64
	Restored        bool
	RestoredChanged bool
	// Left says it was agreed under a key this computer left behind,
	// taking a master password change made elsewhere: until it's made
	// again from the folder's version under the new key (SyncLeftDone),
	// nothing is sent for it.
	Left bool
}

// Changed says whether the entry changed here since it was last agreed:
// made, edited, moved to or from the trash, or deleted for good.
func (i *SyncItem) Changed() bool {
	if i.Agreed == nil {
		return i.Place != SyncGone
	}
	return i.Rev != i.Agreed.Rev
}

// SyncItems is every entry, live, in the trash, or gone since it was
// synced, by uid.
func (s *Store) SyncItems() (_ []SyncItem, err error) {
	rows, err := s.db.Query(`SELECT uid, kind, service, username, rev, 1 FROM entries
		UNION ALL SELECT uid, kind, service, username, rev, 2 FROM trash`)
	if err != nil {
		return nil, fmt.Errorf("read the entries to sync: %w", err)
	}
	byUID := map[string]*SyncItem{}
	for rows.Next() {
		var it SyncItem
		var kind string
		var place int
		if err := rows.Scan(&it.UID, &kind, &it.Key.Service, &it.Key.Username, &it.Rev, &place); err != nil {
			_ = rows.Close() //nolint:errcheck // already failing
			return nil, fmt.Errorf("read the entries to sync: %w", err)
		}
		it.Key.Kind, it.Place = vault.Kind(kind), SyncPlace(place)
		byUID[it.UID] = &it
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("read the entries to sync: %w", err)
	}
	keyID := ""
	if m, err := readKeyRecord(s.db, s.path); err == nil {
		keyID = UnlockID(m.Verify)
	}
	rows, err = s.db.Query(`SELECT uid, rev, file_hash, base, base_hash, left_key FROM sync_state`)
	if err != nil {
		return nil, fmt.Errorf("read what was synced: %w", err)
	}
	for rows.Next() {
		var uid string
		var a SyncAgreed
		var hash, base, baseHash []byte
		var left bool
		if err := rows.Scan(&uid, &a.Rev, &hash, &base, &baseHash, &left); err != nil {
			_ = rows.Close() //nolint:errcheck // already failing
			return nil, fmt.Errorf("read what was synced: %w", err)
		}
		copy(a.Hash[:], hash)
		a.Intact = baseIntact(uid, keyID, base, baseHash)
		it, ok := byUID[uid]
		if !ok {
			it = &SyncItem{UID: uid, Place: SyncGone}
			byUID[uid] = it
		}
		it.Agreed, it.Left = &a, left
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("read what was synced: %w", err)
	}
	rows, err = s.db.Query(`SELECT uid, rev, changed FROM sync_restored`)
	if err != nil {
		return nil, fmt.Errorf("read what was restored: %w", err)
	}
	for rows.Next() {
		var uid string
		var rev int64
		var changed bool
		if err := rows.Scan(&uid, &rev, &changed); err != nil {
			_ = rows.Close() //nolint:errcheck // already failing
			return nil, err
		}
		if it, ok := byUID[uid]; ok && it.Place != SyncGone {
			it.Restored, it.RestoredRev, it.RestoredChanged = true, rev, changed
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("read what was restored: %w", err)
	}
	out := make([]SyncItem, 0, len(byUID))
	for _, it := range byUID {
		out = append(out, *it)
	}
	slices.SortFunc(out, func(a, b SyncItem) int { return compareStrings(a.UID, b.UID) })
	return out, nil
}

func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// SyncKeyID is the ID of the vault's key record (UnlockID), which every
// sync file sealed with its key names.
func (s *Store) SyncKeyID() (string, error) {
	m, err := readKeyRecord(s.db, s.path)
	if err != nil {
		return "", err
	}
	return UnlockID(m.Verify), nil
}

// syncRow is an entry's row, live or in the trash, as sync reads it.
type syncRow struct {
	created, updated, changed, deleted time.Time
	set                                sql.NullTime
	settings                           sql.NullString
	key                                vault.Key
	folder, url, details, tags         string
	data, salt, sealed, detailsSalt    []byte
	id, rev                            int64
	place                              SyncPlace
}

// readSyncRow reads uid's row from q; Place SyncGone when it has none.
func readSyncRow(q querier, uid string) (syncRow, error) {
	var r syncRow
	var kind string
	err := q.QueryRow(`SELECT id, rev, kind, service, username, encrypted_data, salt, settings, folder, url, details, sealed_details, details_salt, created_at, updated_at, set_at, changed_at
		FROM entries WHERE uid = ?`, uid).Scan(&r.id, &r.rev, &kind, &r.key.Service, &r.key.Username, &r.data, &r.salt, &r.settings, &r.folder, &r.url, &r.details, &r.sealed, &r.detailsSalt, &r.created, &r.updated, &r.set, &r.changed)
	if err == nil {
		r.key.Kind, r.place = vault.Kind(kind), SyncLive
		return r, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return r, err
	}
	err = q.QueryRow(`SELECT id, rev, kind, service, username, encrypted_data, salt, settings, folder, url, details, sealed_details, details_salt, created_at, updated_at, set_at, changed_at, deleted_at, tags
		FROM trash WHERE uid = ?`, uid).Scan(&r.id, &r.rev, &kind, &r.key.Service, &r.key.Username, &r.data, &r.salt, &r.settings, &r.folder, &r.url, &r.details, &r.sealed, &r.detailsSalt, &r.created, &r.updated, &r.set, &r.changed, &r.deleted, &r.tags)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		r.place = SyncGone
		return r, nil
	case err != nil:
		return r, err
	}
	r.key.Kind, r.place = vault.Kind(kind), SyncTrashed
	return r, nil
}

// SyncRecord is the entry uid as it is here, as a record made on
// computer: everything it holds, its secrets opened, with its rev as read.
// For one gone, it's a record of its deletion for good, now. The caller
// wipes it.
func (s *Store) SyncRecord(uid, computer string) (_ *syncfolder.Record, rev int64, err error) {
	row, err := readSyncRow(s.db, uid)
	if err != nil {
		return nil, 0, fmt.Errorf("read %s to sync: %w", uid, err)
	}
	if row.place == SyncGone {
		now := time.Now().UTC()
		return &syncfolder.Record{Purged: now, Changed: now, Computer: computer}, 0, nil
	}
	k := row.key
	r := &syncfolder.Record{
		Kind: k.Kind, Service: k.Service, Username: k.Username, Computer: computer,
		Folder: row.folder, Created: row.created, Updated: row.updated, SetAt: row.set.Time, Changed: row.changed, Deleted: row.deleted,
	}
	defer func() {
		if err != nil {
			r.Wipe()
		}
	}()
	if r.Settings, err = decodeSettings(k, row.settings); err != nil {
		return nil, 0, err
	}
	if r.Secret, err = s.oracle.DecryptEntry(row.data, row.salt, entryAAD(k)); err != nil {
		return nil, 0, fmt.Errorf("decrypt %s: %w", k, err)
	}
	e := vault.Entry{Key: k}
	if err := vault.DecodeEntryDetails(&e, row.url, row.details); err != nil {
		return nil, 0, err
	}
	var plain []byte
	if row.sealed != nil {
		if plain, err = s.oracle.DecryptEntry(row.sealed, row.detailsSalt, detailsAAD(k)); err != nil {
			return nil, 0, fmt.Errorf("decrypt the details of %s: %w", k, err)
		}
		defer secure.SecureZeroBytes(plain)
	}
	d, err := vault.DecodeDetails(&e, plain)
	if err != nil {
		return nil, 0, err
	}
	r.URL, r.Notes = d.URL, d.Notes
	for _, f := range d.Fields {
		r.Fields = append(r.Fields, syncfolder.Field{Name: f.Name, Value: f.Value, Secret: f.Secret})
	}
	var damaged bool
	if r.Tags, damaged, err = s.syncTags(&row); err != nil {
		return nil, 0, err
	}
	// Tags that don't read (damage) are as last agreed, not taken for
	// removed.
	if damaged {
		if base, err := s.SyncBase(uid); err == nil && base != nil {
			r.Tags = slices.Clone(base.Tags)
			base.Wipe()
		}
	}
	if r.History, err = s.syncHistory(&row, computer); err != nil {
		return nil, 0, err
	}
	if r.Forgotten, err = forgotten(s.db, uid); err != nil {
		return nil, 0, err
	}
	return r, row.rev, nil
}

// forgotten are the marks of the entry uid's earlier secrets forgotten on
// purpose, in order.
func forgotten(db *sql.DB, uid string) (marks []syncfolder.Forgotten, err error) {
	rows, err := db.Query(`SELECT hash, at FROM history_forgotten WHERE uid = ? ORDER BY hash`, uid)
	if err != nil {
		return nil, fmt.Errorf("read what %s forgot: %w", uid, err)
	}
	for rows.Next() {
		var m syncfolder.Forgotten
		if err := rows.Scan(&m.Hash, &m.At); err != nil {
			_ = rows.Close() //nolint:errcheck // already failing
			return nil, err
		}
		marks = append(marks, m)
	}
	return marks, errors.Join(rows.Err(), rows.Close())
}

// syncTags are row's tags; damaged says those of an entry in the trash
// don't read.
func (s *Store) syncTags(row *syncRow) (tags []string, damaged bool, err error) {
	if row.place == SyncTrashed {
		if json.Unmarshal([]byte(row.tags), &tags) != nil {
			return nil, true, nil
		}
		return vault.NormalizeTags(tags), false, nil
	}
	rows, err := s.db.Query(`SELECT tag FROM entry_tags WHERE entry_id = ? ORDER BY tag`, row.id)
	if err != nil {
		return nil, false, fmt.Errorf("read the tags of %s: %w", row.key, err)
	}
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			_ = rows.Close() //nolint:errcheck // already failing
			return nil, false, err
		}
		tags = append(tags, t)
	}
	return tags, false, errors.Join(rows.Err(), rows.Close())
}

// syncHistory is row's earlier secrets, opened, the newest first; one
// replaced on this computer is said to be computer's.
func (s *Store) syncHistory(row *syncRow, computer string) (_ []syncfolder.Earlier, err error) {
	q, args := `SELECT encrypted_data, salt, replaced_at, set_at, file_name, computer FROM history WHERE kind = ? AND service = ? AND username = ? AND trash_id IS NULL ORDER BY id DESC`,
		[]any{string(row.key.Kind), row.key.Service, row.key.Username}
	if row.place == SyncTrashed {
		q, args = `SELECT encrypted_data, salt, replaced_at, set_at, file_name, computer FROM history WHERE trash_id = ? ORDER BY id DESC`, []any{row.id}
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("read the history of %s: %w", row.key, err)
	}
	var out []syncfolder.Earlier
	defer func() {
		if err != nil {
			for i := range out {
				secure.SecureZeroBytes(out[i].Secret)
			}
		}
	}()
	type sealed struct {
		at, set    time.Time
		file, comp string
		data, salt []byte
	}
	var all []sealed
	for rows.Next() {
		var h sealed
		if err := rows.Scan(&h.data, &h.salt, &h.at, &h.set, &h.file, &h.comp); err != nil {
			_ = rows.Close() //nolint:errcheck // already failing
			return nil, fmt.Errorf("read the history of %s: %w", row.key, err)
		}
		all = append(all, h)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("read the history of %s: %w", row.key, err)
	}
	for i := range all {
		h := &all[i]
		secret, err := s.oracle.DecryptEntry(h.data, h.salt, historyAAD(row.key))
		if err != nil {
			if kerr := s.keyUnchanged(s.db); kerr != nil {
				return nil, kerr
			}
			// Damaged: it isn't synced, and a sound copy elsewhere comes
			// back with the sync.
			continue
		}
		if h.comp == "" {
			h.comp = computer
		}
		out = append(out, syncfolder.Earlier{ReplacedAt: h.at, SetAt: h.set, Computer: h.comp, FileName: h.file, Secret: secret})
	}
	return out, nil
}

// SyncBase is the version uid was last agreed at, nil when it never was.
// The caller wipes it.
func (s *Store) SyncBase(uid string) (*syncfolder.Record, error) {
	var b []byte
	err := s.db.QueryRow(`SELECT base FROM sync_state WHERE uid = ?`, uid).Scan(&b)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("read what %s was synced at: %w", uid, err)
	}
	h, r, err := syncfolder.Open(s.oracle, b)
	if err != nil {
		return nil, fmt.Errorf("read what %s was synced at: %w", uid, err)
	}
	if h.UIDString() != uid {
		r.Wipe()
		return nil, fmt.Errorf("read what %s was synced at: it's another entry's", uid)
	}
	return r, nil
}

// syncRev is uid's rev in q: 0 when it's gone.
func syncRev(q querier, uid string) (int64, error) {
	var rev int64
	err := q.QueryRow(`SELECT rev FROM entries WHERE uid = ? UNION ALL SELECT rev FROM trash WHERE uid = ?`, uid, uid).Scan(&rev)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return rev, err
}

// baseHash is what sync_state keeps of an agreed version sealed as base,
// so damage to it is seen without opening it.
func baseHash(base []byte) []byte {
	h := sha256.Sum256(base)
	return h[:]
}

// baseIntact says whether base, uid's agreed version as sync_state keeps it
// with its hash, is as it was sealed, for uid, with the key of the key
// record keyID.
func baseIntact(uid, keyID string, base, hash []byte) bool {
	if keyID == "" || !bytes.Equal(baseHash(base), hash) {
		return false
	}
	h, err := syncfolder.ParseHeader(base)
	return err == nil && h.UIDString() == uid && h.KeyIDString() == keyID
}

// agree records, in tx, that uid at rev here and the folder's file of hash
// agree on the version sealed as base.
func agree(tx *sql.Tx, uid string, rev int64, hash syncfolder.Hash, base []byte) error {
	if _, err := tx.Exec(`INSERT INTO sync_state (uid, rev, file_hash, base, base_hash) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (uid) DO UPDATE SET rev = excluded.rev, file_hash = excluded.file_hash, base = excluded.base, base_hash = excluded.base_hash`,
		uid, rev, hash[:], base, baseHash(base)); err != nil {
		return err
	}
	_, err := tx.Exec(`DELETE FROM sync_restored WHERE uid = ?`, uid)
	return err
}

// SyncComputerID is this computer's sync ID, made the first time it's
// asked for: random, kept in the vault, and not taken from a backup, so
// each computer's changes are counted as its own (syncfolder.Versions).
func (s *Store) SyncComputerID() (string, error) {
	var id string
	err := s.db.QueryRow(`SELECT computer_id FROM sync_info WHERE id = 1`).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	err = s.inTx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO sync_info (id, computer_id) VALUES (1, lower(hex(randomblob(8))))`); err != nil {
			return err
		}
		return tx.QueryRow(`SELECT computer_id FROM sync_info WHERE id = 1`).Scan(&id)
	})
	return id, err
}

// SyncNextChange is the count of this computer's next change written to
// the sync folder: one more than any it gave before, and than seen (any
// of its counts in what it's writing over), counted in the vault before
// the change is written, so no two changes it writes, even one written
// and then lost to a crash, share a count.
func (s *Store) SyncNextChange(seen uint64) (uint64, error) {
	if _, err := s.SyncComputerID(); err != nil {
		return 0, err
	}
	var n uint64
	err := s.inTx(func(tx *sql.Tx) error {
		if err := tx.QueryRow(`SELECT MAX(changes, ?) + 1 FROM sync_info WHERE id = 1`, seen).Scan(&n); err != nil {
			return err
		}
		// Past it, no computer would read the change (syncfolder.Open).
		if n >= syncfolder.MaxCount {
			return errors.New("a change count too high to be one")
		}
		_, err := tx.Exec(`UPDATE sync_info SET changes = ? WHERE id = 1`, n)
		return err
	})
	return n, err
}

// typedAAD binds a sealed Typed to its entry.
func typedAAD(uid string) []byte { return []byte("sesh sync typed " + uid) }

// SyncAddTyped keeps t, typed in the entry uid and sent with the count
// t.N, folded in with what it kept before (syncfolder.Fold).
func (s *Store) SyncAddTyped(uid string, t *syncfolder.Typed) error {
	if t.Empty() {
		return nil
	}
	olds, err := s.SyncTyped(uid)
	if err != nil {
		return err
	}
	return s.putTyped(uid, syncfolder.Fold(olds, t))
}

// putTyped keeps all as what was typed in the entry uid, in place of
// what was kept.
func (s *Store) putTyped(uid string, all []*syncfolder.Typed) error {
	type sealed struct {
		data, salt []byte
		n          uint64
	}
	var rows []sealed
	for _, o := range all {
		b, err := json.Marshal(o)
		if err != nil {
			return err
		}
		data, salt, err := s.oracle.EncryptEntry(b, typedAAD(uid))
		secure.SecureZeroBytes(b)
		if err != nil {
			return fmt.Errorf("keep what was typed in %s: %w", uid, err)
		}
		rows = append(rows, sealed{data, salt, o.N})
	}
	return s.inTx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM sync_typed WHERE uid = ?`, uid); err != nil {
			return err
		}
		for _, r := range rows {
			if _, err := tx.Exec(`INSERT INTO sync_typed (uid, n, data, salt) VALUES (?, ?, ?, ?)`, uid, r.n, r.data, r.salt); err != nil {
				return err
			}
		}
		return nil
	})
}

// SyncTyped is what was typed in the entry uid and kept (SyncAddTyped),
// in the order it was sent. One that doesn't open is left out.
func (s *Store) SyncTyped(uid string) ([]*syncfolder.Typed, error) {
	rows, err := s.db.Query(`SELECT data, salt FROM sync_typed WHERE uid = ? ORDER BY n`, uid)
	if err != nil {
		return nil, fmt.Errorf("read what was typed in %s: %w", uid, err)
	}
	defer rows.Close() //nolint:errcheck // read only
	var out []*syncfolder.Typed
	for rows.Next() {
		var data, salt []byte
		if err := rows.Scan(&data, &salt); err != nil {
			return nil, err
		}
		b, err := s.oracle.DecryptEntry(data, salt, typedAAD(uid))
		if err != nil {
			continue
		}
		var t syncfolder.Typed
		err = json.Unmarshal(b, &t)
		secure.SecureZeroBytes(b)
		if err != nil {
			continue
		}
		out = append(out, &t)
	}
	return out, rows.Err()
}

// SyncLeftDone records that the entry uid, agreed under a key left
// behind (SyncItem.Left), was made again from the folder's version under
// the new key, with what was typed here: that's no longer kept.
func (s *Store) SyncLeftDone(uid string) error {
	return s.inTx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`UPDATE sync_state SET left_key = 0 WHERE uid = ?`, uid); err != nil {
			return err
		}
		_, err := tx.Exec(`DELETE FROM sync_typed WHERE uid = ?`, uid)
		return err
	})
}

// SyncDropEntry forgets the entry uid, deleted for good here, as synced:
// nothing is sent for it.
func (s *Store) SyncDropEntry(uid string) error {
	return s.inTx(func(tx *sql.Tx) error {
		for _, q := range []string{`DELETE FROM sync_state WHERE uid = ?`, `DELETE FROM sync_typed WHERE uid = ?`, `DELETE FROM sync_restored WHERE uid = ?`} {
			if _, err := tx.Exec(q, uid); err != nil {
				return err
			}
		}
		return nil
	})
}

// SyncSetForgotten makes the earlier secrets forgotten on purpose in the
// entry uid exactly marks, in place of what it had.
func (s *Store) SyncSetForgotten(uid string, marks []syncfolder.Forgotten) error {
	return s.inTx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM history_forgotten WHERE uid = ?`, uid); err != nil {
			return err
		}
		for _, m := range marks {
			if _, err := tx.Exec(`INSERT INTO history_forgotten (uid, hash, at) VALUES (?, ?, ?)`, uid, m.Hash, m.At); err != nil {
				return err
			}
		}
		return nil
	})
}

// SyncCheck says what's wrong with rec as an entry sesh would keep, if
// anything: a merged one may not fit (too many fields, notes too long).
func (s *Store) SyncCheck(rec *syncfolder.Record) error {
	if !rec.Purged.IsZero() {
		return nil
	}
	_, err := checkRecord(rec)
	return err
}

// SyncSealer seals and opens sync files with the vault's key.
func (s *Store) SyncSealer() syncfolder.Sealer { return s.oracle }

// SyncAgree records that the entry uid, at rev here, and the folder's file
// of hash agree on rec: once this computer has written its version there,
// or found it the same. If uid's rev isn't rev any more (another command
// changed it meanwhile), nothing is recorded: ErrEntryChanged, for the
// next sync.
func (s *Store) SyncAgree(uid string, rev int64, rec *syncfolder.Record, hash syncfolder.Hash) error {
	base, err := s.sealBase(uid, rec)
	if err != nil {
		return err
	}
	return s.inTx(func(tx *sql.Tx) error {
		now, err := syncRev(tx, uid)
		if err != nil {
			return err
		}
		if now != rev {
			return ErrEntryChanged
		}
		return agree(tx, uid, rev, hash, base)
	})
}

// SyncMendBase keeps rec again as the version the entry uid was last
// agreed at, in place of one that doesn't open (damaged).
func (s *Store) SyncMendBase(uid string, rec *syncfolder.Record) error {
	base, err := s.sealBase(uid, rec)
	if err != nil {
		return err
	}
	return s.inTx(func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE sync_state SET base = ?, base_hash = ? WHERE uid = ?`, base, baseHash(base), uid)
		return err
	})
}

// sealBase is rec sealed as uid's agreed version is kept: without its
// earlier secrets, which merging doesn't take from it, so it's small
// however long the history.
func (s *Store) sealBase(uid string, rec *syncfolder.Record) ([]byte, error) {
	r := *rec
	r.History = nil
	rec = &r
	keyID, err := s.SyncKeyID()
	if err != nil {
		return nil, err
	}
	h, err := syncfolder.NewHeader(uid, keyID)
	if err != nil {
		return nil, err
	}
	return syncfolder.Seal(s.oracle, h, rec)
}

// sealedRecord is a record sealed to be written as an entry's row.
type sealedRecord struct {
	settings   sql.NullString
	key        vault.Key
	details    sealedDetails
	tags       []string
	history    []resealedHistory
	historyAt  []syncfolder.Earlier
	data, salt []byte
}

// checkRecord checks rec is an entry sesh would keep: its name, folder,
// tags, secret, file name and details; it returns its details.
func checkRecord(rec *syncfolder.Record) (vault.Details, error) {
	k := vault.Key{Kind: rec.Kind, Service: rec.Service, Username: rec.Username}
	if err := k.Validate(); err != nil {
		return vault.Details{}, err
	}
	if err := vault.CheckFolder(rec.Folder); err != nil {
		return vault.Details{}, err
	}
	for _, t := range vault.NormalizeTags(rec.Tags) {
		if err := vault.CheckTag(t); err != nil {
			return vault.Details{}, err
		}
	}
	if len(rec.Secret) > MaxSecretSize {
		return vault.Details{}, fmt.Errorf("%w: %d bytes (max %d)", ErrSecretTooLarge, len(rec.Secret), MaxSecretSize)
	}
	if err := vault.CheckFileName(rec.Settings.FileName); err != nil {
		return vault.Details{}, err
	}
	d := vault.Details{URL: rec.URL, Notes: rec.Notes}
	for _, f := range rec.Fields {
		d.Fields = append(d.Fields, vault.Field{Name: f.Name, Value: f.Value, Secret: f.Secret})
	}
	if err := d.Check(k.Kind); err != nil {
		return vault.Details{}, err
	}
	if _, _, sealed, err := vault.EncodeDetails(&d); err != nil {
		return vault.Details{}, err
	} else {
		secure.SecureZeroBytes(sealed)
	}
	return d, nil
}

// sealRecord checks rec is an entry sesh would keep, and seals it for its
// name.
func (s *Store) sealRecord(rec *syncfolder.Record) (sealedRecord, error) {
	d, err := checkRecord(rec)
	if err != nil {
		return sealedRecord{}, err
	}
	k := vault.Key{Kind: rec.Kind, Service: rec.Service, Username: rec.Username}
	out := sealedRecord{key: k, tags: vault.NormalizeTags(rec.Tags), historyAt: rec.History}
	if out.settings, err = encodeSettings(&rec.Settings); err != nil {
		return sealedRecord{}, err
	}
	if out.data, out.salt, err = s.oracle.EncryptEntry(rec.Secret, entryAAD(k)); err != nil {
		return sealedRecord{}, fmt.Errorf("encrypt %s: %w", k, err)
	}
	if out.details, err = s.sealDetails(k, &d, nil); err != nil {
		return sealedRecord{}, err
	}
	for _, h := range rec.History {
		data, salt, err := s.oracle.EncryptEntry(h.Secret, historyAAD(k))
		if err != nil {
			return sealedRecord{}, fmt.Errorf("encrypt an earlier secret of %s: %w", k, err)
		}
		out.history = append(out.history, resealedHistory{data: data, salt: salt})
	}
	return out, nil
}

// SyncApply makes the entry uid here as rec has it, in one transaction, if
// its rev is still rev (ErrEntryChanged, for the next sync, if another
// command changed it meanwhile), and records it agreed with the folder's
// file of hash. A name another entry has is ErrNameTaken. It returns the
// entry's rev after; 0 for one deleted for good. The writes are quiet: the
// rev is set, not raised by them.
func (s *Store) SyncApply(uid string, rev int64, rec *syncfolder.Record, hash syncfolder.Hash) (int64, error) {
	var sr sealedRecord
	if rec.Purged.IsZero() {
		var err error
		if sr, err = s.sealRecord(rec); err != nil {
			return 0, fmt.Errorf("sync %s: %w", uid, err)
		}
	}
	base, err := s.sealBase(uid, rec)
	if err != nil {
		return 0, err
	}
	var newRev int64
	err = s.inTx(func(tx *sql.Tx) error {
		return quietly(tx, func() error {
			row, err := readSyncRow(tx, uid)
			if err != nil {
				return err
			}
			if row.rev != rev {
				return ErrEntryChanged
			}
			if err := s.keyUnchanged(tx); err != nil {
				return err
			}
			switch row.place {
			case SyncLive:
				if err := forget(tx, row.id, row.key); err != nil {
					return err
				}
			case SyncTrashed:
				if _, err := tx.Exec(`DELETE FROM trash WHERE id = ?`, row.id); err != nil {
					return err
				}
			}
			if !rec.Purged.IsZero() {
				return agree(tx, uid, 0, hash, base)
			}
			newRev = rev + 1
			if err := s.insertRecord(tx, uid, newRev, rec, &sr); err != nil {
				return err
			}
			return agree(tx, uid, newRev, hash, base)
		})
	})
	if err != nil {
		return 0, fmt.Errorf("sync %s: %w", uid, err)
	}
	switch {
	case !rec.Purged.IsZero():
		s.audit("purge", uid, "Sync: deleted for good on "+rec.Computer)
	default:
		s.audit("modify", sr.key.String(), "Sync: as "+rec.Computer+" has it")
	}
	return newRev, nil
}

// insertRecord writes rec, sealed as sr, as the entry uid at rev, in the
// vault or its trash, with its tags and history.
func (s *Store) insertRecord(tx *sql.Tx, uid string, rev int64, rec *syncfolder.Record, sr *sealedRecord) error {
	k := sr.key
	changed := rec.Changed
	if changed.IsZero() {
		changed = time.Now().UTC()
	}
	// When its secret's use began, kept only where it isn't Updated.
	var set any
	if !rec.SetAt.IsZero() {
		set = rec.SetAt
	}
	var trashID any
	if rec.Deleted.IsZero() {
		if err := s.nameFree(tx, k, 0); err != nil {
			return err
		}
		var id int64
		if err := tx.QueryRow(`INSERT INTO entries (uid, rev, kind, service, username, encrypted_data, salt, settings, folder, url, details, sealed_details, details_salt, created_at, updated_at, set_at, changed_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
			uid, rev, string(k.Kind), k.Service, k.Username, sr.data, sr.salt, sr.settings, rec.Folder, sr.details.url, sr.details.plain, sr.details.sealed, sr.details.salt,
			rec.Created, rec.Updated, set, changed).Scan(&id); err != nil {
			return err
		}
		for _, t := range sr.tags {
			if _, err := tx.Exec(`INSERT INTO entry_tags (entry_id, tag) VALUES (?, ?)`, id, t); err != nil {
				return err
			}
		}
	} else {
		tags, err := json.Marshal(sr.tags)
		if err != nil {
			return err
		}
		if sr.tags == nil {
			tags = []byte("[]")
		}
		var id int64
		if err := tx.QueryRow(`INSERT INTO trash (uid, rev, kind, service, username, encrypted_data, salt, settings, folder, url, details, sealed_details, details_salt, tags, created_at, updated_at, set_at, deleted_at, changed_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
			uid, rev, string(k.Kind), k.Service, k.Username, sr.data, sr.salt, sr.settings, rec.Folder, sr.details.url, sr.details.plain, sr.details.sealed, sr.details.salt,
			string(tags), rec.Created, rec.Updated, set, rec.Deleted, changed).Scan(&id); err != nil {
			return err
		}
		trashID = id
	}
	for _, m := range rec.Forgotten {
		var at time.Time
		err := tx.QueryRow(`SELECT at FROM history_forgotten WHERE uid = ? AND hash = ?`, uid, m.Hash).Scan(&at)
		switch {
		case err == nil && !m.At.After(at):
			continue
		case err != nil && !errors.Is(err, sql.ErrNoRows):
			return err
		}
		if _, err := tx.Exec(`INSERT INTO history_forgotten (uid, hash, at) VALUES (?, ?, ?)
			ON CONFLICT (uid, hash) DO UPDATE SET at = excluded.at`, uid, m.Hash, m.At); err != nil {
			return err
		}
	}
	// Oldest first, so the newest has the highest row, as history lists
	// them.
	for i, h := range slices.Backward(sr.history) {
		at := sr.historyAt[i]
		if _, err := tx.Exec(`INSERT INTO history (kind, service, username, trash_id, encrypted_data, salt, replaced_at, set_at, file_name, computer) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			string(k.Kind), k.Service, k.Username, trashID, h.data, h.salt, at.ReplacedAt, at.SetAt, at.FileName, at.Computer); err != nil {
			return err
		}
	}
	// Trimmed to this computer's history.keep: with 0, none is kept.
	if trashID == nil {
		return s.trimHistory(tx, k)
	}
	return nil
}

// LogSync records a sync with the sync folder in the audit log: detail
// says what it did.
func (s *Store) LogSync(detail string) {
	s.audit("sync", "", detail)
}

// ErrVaultNotEmpty is a vault that can't join a sync folder: it has
// entries, sealed with its own key (its own salt, even with the same
// master password).
var ErrVaultNotEmpty = errors.New("this vault already has entries of its own, never synced with this folder")

// CanJoin says whether the vault at dbPath may join the sync folder
// folderID, whose vaults' key record is m: none there yet, an empty one, or
// one joining again the folder it synced with before, under its key
// (rejoin); ErrRejoinOtherKey for one that synced with it under another;
// ErrVaultNotEmpty for any other with entries, in the trash or in history. It changes nothing, so a command can check before asking
// for the master password.
func CanJoin(dbPath string, m UnlockMaterial, folderID string) (rejoin bool, err error) {
	db, err := openExisting(dbPath)
	if errors.Is(err, ErrNoVault) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { err = closeVault(db, err) }()
	have, err := readKeyRecord(db, dbPath)
	if errors.Is(err, ErrNoVault) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return joinable(db, have, m, folderID)
}

// VaultSyncFolder is the ID of the sync folder the vault at dbPath syncs
// with, or did before it left; "" when none, or there's no vault. It
// changes nothing.
func VaultSyncFolder(dbPath string) (id string, err error) {
	db, err := openExisting(dbPath)
	if errors.Is(err, ErrNoVault) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer func() { err = closeVault(db, err) }()
	err = db.QueryRow(`SELECT folder_id FROM sync_info WHERE id = 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// VaultKeyChange is the vault at dbPath's SyncKeyChange, read without
// unlocking it: "" when there's no change to send, or no vault.
func VaultKeyChange(dbPath string) (id string, err error) {
	db, err := openExisting(dbPath)
	if errors.Is(err, ErrNoVault) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer func() { err = closeVault(db, err) }()
	err = db.QueryRow(`SELECT prev_key_id FROM sync_info WHERE id = 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// ErrRejoinOtherKey is a vault joining again the sync folder it synced
// with, but under another master password than the folder's now: one of
// them changed it since.
var ErrRejoinOtherKey = errors.New("this vault synced with this folder before, but its master password, or the folder's, has changed since")

// joinable is CanJoin for the open vault db, whose key record is have. A
// vault that synced with folderID under its key rejoins, even with nothing
// left in it: what it agreed holds its deletions. So does one restored
// from a backup made before it synced, every entry marked restored (the
// marks keep the folder's deletions).
func joinable(db *sql.DB, have, m UnlockMaterial, folderID string) (rejoin bool, err error) {
	var synced, prev string
	if err := db.QueryRow(`SELECT folder_id, prev_key_id FROM sync_info WHERE id = 1`).Scan(&synced, &prev); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	sameKey := UnlockID(have.Verify) == UnlockID(m.Verify)
	// The folder's, or the one it had before a change made here that it
	// left with, not sent: that's sent once it has joined again.
	if synced == folderID && (sameKey || prev == UnlockID(m.Verify)) {
		return true, nil
	}
	var used, restoredOnly bool
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM entries) OR EXISTS (SELECT 1 FROM trash) OR EXISTS (SELECT 1 FROM history),
		NOT EXISTS (SELECT 1 FROM entries WHERE uid NOT IN (SELECT uid FROM sync_restored))
		AND NOT EXISTS (SELECT 1 FROM trash WHERE uid NOT IN (SELECT uid FROM sync_restored))`).Scan(&used, &restoredOnly); err != nil {
		return false, err
	}
	switch {
	case synced == folderID:
		// Even with nothing left: what it agreed holds its deletions.
		return false, ErrRejoinOtherKey
	case !used:
		return false, nil
	case synced == "" && sameKey && restoredOnly:
		return true, nil
	}
	return false, ErrVaultNotEmpty
}

// JoinVault readies the vault at dbPath to join the sync folder folderID,
// whose vaults' key record is m, the master password already checked
// against it (CheckMasterPassword). A vault joining again the folder it
// synced with, under its key, is left as it is (rejoin): what it agreed
// with the folder before it left is kept, so what changed on both sides
// since merges as any change does. Any other with entries is refused
// (ErrVaultNotEmpty): with nothing agreed, it would bring back, as edits,
// entries deleted elsewhere. A new or empty vault gets m as its key
// record, so the same master password gives the same key; one that had
// another loses its recovery record, made for that key. Whatever it kept
// of an earlier sync (what it agreed, its sync ID, restored and forgotten
// marks) goes: it starts afresh.
//
// links are the folder's key links, which a new or emptied vault takes.
func JoinVault(dbPath string, m UnlockMaterial, folderID string, links []syncfolder.KeyLink) (rejoin bool, err error) {
	if err := ValidateUnlockMaterial(m.Salt, m.Verify, m.Params); err != nil {
		return false, fmt.Errorf("the sync folder's key record: %w", err)
	}
	db, err := openDB(dbPath)
	if err != nil {
		return false, err
	}
	defer func() { err = closeVault(db, err) }()
	if err := applyMigrations(db); err != nil {
		return false, err
	}
	have, err := readKeyRecord(db, dbPath)
	switch {
	case errors.Is(err, ErrNoVault):
		if _, err := writeKeyRecord(db, m); err != nil {
			return false, err
		}
		have = m
	case err != nil:
		return false, err
	default:
		if rejoin, err := joinable(db, have, m, folderID); err != nil || rejoin {
			return rejoin, err
		}
	}
	tx, err := db.Begin()
	if err != nil {
		return false, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback() //nolint:errcheck // already failing
		}
	}()
	stmts := []string{`DELETE FROM sync_state`, `DELETE FROM sync_info`, `DELETE FROM sync_typed`, `DELETE FROM sync_restored`, `DELETE FROM history_forgotten`}
	if UnlockID(have.Verify) != UnlockID(m.Verify) {
		stmts = append(stmts, `DELETE FROM recovery`)
		if _, err := tx.Exec(`UPDATE vault_key SET salt = ?, kdf = ?, kdf_params = ?, verify = ?, created_at = ? WHERE id = 1`,
			m.Salt, kdfArgon2id, m.Params.MarshalParams(), m.Verify, time.Now().UTC()); err != nil {
			return false, err
		}
	}
	for _, q := range stmts {
		if _, err := tx.Exec(q); err != nil {
			return false, err
		}
	}
	if _, err := tx.Exec(`INSERT INTO sync_info (id, computer_id, folder_id) VALUES (1, lower(hex(randomblob(8))), ?)`, folderID); err != nil {
		return false, err
	}
	if _, err := tx.Exec(`DELETE FROM key_links`); err != nil {
		return false, err
	}
	for i := range links {
		if err := putKeyLink(tx, &links[i]); err != nil {
			return false, err
		}
	}
	return false, tx.Commit()
}

// CheckMasterPassword says whether pw is the master password of the key
// record m, without a vault: an error when it isn't.
func CheckMasterPassword(pw []byte, m UnlockMaterial) error {
	key := DeriveKey(pw, m.Salt, m.Params)
	defer secure.SecureZeroBytes(key)
	if _, err := Decrypt(key, m.Verify); err != nil {
		return errors.New("that isn't the master password of the vaults that sync through this folder")
	}
	return nil
}

// SyncStartFolder makes folderID the sync folder the vault syncs with. A
// vault that synced with another forgets what it agreed with that one, so
// every entry goes to the new folder as a change (entries restored from a
// backup stay marked so), and so does its recovery key record; one syncing
// with folderID already keeps it.
func (s *Store) SyncStartFolder(folderID string) error {
	return s.inTx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO sync_info (id, computer_id) VALUES (1, lower(hex(randomblob(8))))`); err != nil {
			return err
		}
		var have string
		if err := tx.QueryRow(`SELECT folder_id FROM sync_info WHERE id = 1`).Scan(&have); err != nil {
			return err
		}
		if have == folderID {
			return nil
		}
		if _, err := tx.Exec(`DELETE FROM sync_state`); err != nil {
			return err
		}
		_, err := tx.Exec(`UPDATE sync_info SET folder_id = ?, `+noRecoverySeen+` WHERE id = 1`, folderID)
		return err
	})
}

// SyncKeyChange is the ID of the key record the vault had before a master
// password change made here that the sync folder hasn't taken yet (the
// folder's), or "" when there's none to send.
func (s *Store) SyncKeyChange() (string, error) {
	var id string
	err := s.db.QueryRow(`SELECT prev_key_id FROM sync_info WHERE id = 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// SyncKeyChangeSent records that the sync folder has the vault's key
// record: there's no change to send.
func (s *Store) SyncKeyChangeSent() error {
	return s.inTx(func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE sync_info SET prev_key_id = ''`)
		return err
	})
}

// SyncFolderID is the ID of the sync folder the vault syncs with, or did
// before it left; "" when none.
func (s *Store) SyncFolderID() (string, error) {
	var id string
	err := s.db.QueryRow(`SELECT folder_id FROM sync_info WHERE id = 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}
