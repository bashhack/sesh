package database

import (
	"bytes"
	"cmp"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/shell"
	"github.com/bashhack/sesh/internal/syncfolder"
	"github.com/bashhack/sesh/internal/vault"
)

// historyAAD is what binds an entry's earlier secret to the entry, as
// entryAAD does its secret, apart from it: an old secret can't be read as
// the current one.
func historyAAD(k vault.Key) []byte {
	return keyAAD("sesh-history-v1", k)
}

// Version is one of an entry's earlier secrets: its row, and when it
// stopped being the secret.
type Version struct {
	ReplacedAt time.Time
	ID         int64
}

// ErrNoVersion is a version number an entry's history doesn't have.
var ErrNoVersion = errors.New("no such version")

// ErrVersionGone is a version, named by its row, that's no longer in the
// entry's history: another command forgot it, or dropped it to
// history.keep.
var ErrVersionGone = errors.New("that earlier secret isn't in the history any more")

// SetHistoryKeep sets how many earlier secrets each entry keeps; 0 keeps
// none. A new Store keeps none.
func (s *Store) SetHistoryKeep(n int) { s.historyKeep = n }

// HistoryKeep is how many earlier secrets each entry keeps.
func (s *Store) HistoryKeep() int { return s.historyKeep }

// oldSecret is an entry's secret about to be replaced, sealed for its
// history (nil data when there's nothing to keep): from is the row it was
// read from, so the write can check it hasn't changed since.
type oldSecret struct {
	at         time.Time // replaced, for an imported one
	set        time.Time // its use began: the entry's set_at, or else updated_at, as read; zero when that doesn't read
	fileName   string    // a file entry's file's name with it
	data, salt []byte    // sealed for history
	from       []byte    // the entry's encrypted_data it was read from
	same       bool      // next is the secret it has: nothing changes
}

// sameSecret says whether the entry k's secret, sealed (data, salt), is
// next. One that doesn't decrypt isn't.
func (s *Store) sameSecret(k vault.Key, data, salt, next []byte) (bool, error) {
	if next == nil {
		return false, nil
	}
	plain, err := s.oracle.DecryptEntry(data, salt, entryAAD(k))
	switch {
	case err == nil:
		defer secure.SecureZeroBytes(plain)
		return bytes.Equal(plain, next), nil
	case errors.Is(err, ErrDecrypt):
		if kerr := s.keyUnchanged(s.db); errors.Is(kerr, ErrVaultKeyChanged) {
			return false, fmt.Errorf("decrypt %s: %w", k, kerr)
		}
		return false, nil
	}
	return false, fmt.Errorf("decrypt %s: %w", k, err)
}

// replacing is the entry k's secret, sealed (data, salt), kept for its
// history as to's when it's being replaced by next (nil when the secret
// isn't changing) and differs from it; nil when there's nothing to keep
// or check. A secret that doesn't decrypt (damage) isn't kept, but the
// write still checks the entry is as it was read.
func (s *Store) replacing(k, to vault.Key, data, salt, next []byte) (*oldSecret, error) {
	if s.historyKeep == 0 || next == nil {
		return nil, nil
	}
	plain, err := s.oracle.DecryptEntry(data, salt, entryAAD(k))
	if err != nil {
		if kerr := s.keyUnchanged(s.db); errors.Is(kerr, ErrVaultKeyChanged) {
			return nil, fmt.Errorf("decrypt %s: %w", k, kerr)
		}
		if errors.Is(err, ErrDecrypt) {
			return &oldSecret{from: data}, nil
		}
		return nil, fmt.Errorf("decrypt %s: %w", k, err)
	}
	defer secure.SecureZeroBytes(plain)
	if bytes.Equal(plain, next) {
		return &oldSecret{from: data, same: true}, nil
	}
	hd, hs, err := s.oracle.EncryptEntry(plain, historyAAD(to))
	if err != nil {
		return nil, fmt.Errorf("encrypt %s's earlier secret: %w", to, err)
	}
	return &oldSecret{data: hd, salt: hs, from: data}, nil
}

// keepOld records old as k's latest earlier secret, replaced at, in tx,
// and drops the oldest past the store's history.keep; an old with no data
// keeps nothing. Its use began when its entry says (set_at, or else
// updated_at), as it is (another computer's clock may be ahead), or, when
// that doesn't read, at.
func (s *Store) keepOld(tx *sql.Tx, k vault.Key, old *oldSecret, at time.Time) error {
	if old.data == nil {
		return nil
	}
	set := old.set
	if set.IsZero() {
		set = at
	}
	if _, err := tx.Exec(`INSERT INTO history (kind, service, username, encrypted_data, salt, replaced_at, set_at, file_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		string(k.Kind), k.Service, k.Username, old.data, old.salt, at, set.UTC(), old.fileName); err != nil {
		return fmt.Errorf("keep %s's earlier secret: %w", k, err)
	}
	return s.trimHistory(tx, k)
}

// trimHistory drops, in tx, k's earlier secrets past the newest
// history.keep.
func (s *Store) trimHistory(tx *sql.Tx, k vault.Key) error {
	_, err := tx.Exec(`DELETE FROM history WHERE trash_id IS NULL AND kind = ? AND service = ? AND username = ? AND id NOT IN (
		SELECT id FROM history WHERE trash_id IS NULL AND kind = ? AND service = ? AND username = ? ORDER BY id DESC LIMIT ?)`,
		string(k.Kind), k.Service, k.Username, string(k.Kind), k.Service, k.Username, s.historyKeep)
	return err
}

// SaveImported is SaveWithDetails, or Save when d is nil, for an import
// that also brings the entry's earlier secrets, the newest first. They go
// into its history below what it has, and below the secret this replaces;
// one the entry already has, as its secret or an earlier one, isn't kept
// again, so importing twice adds nothing twice. Only as many as
// history.keep has room for are kept, the newest, and none over
// MaxSecretSize; the result says how many.
func (s *Store) SaveImported(e *vault.Entry, secret []byte, d *vault.Details, earlier []vault.Earlier) (ImportedHistory, error) {
	if d != nil {
		if err := d.Check(e.Kind); err != nil {
			return ImportedHistory{}, err
		}
	}
	var got ImportedHistory
	err := s.write(e, secret, true, d, earlier, &got)
	return got, err
}

// ImportedHistory is what SaveImported did with an entry's earlier
// secrets, leaving out those the entry already had: how many it kept, and
// how many it didn't, for lack of room under history.keep or for being
// over MaxSecretSize.
type ImportedHistory struct {
	Kept, NoRoom, TooLarge int
}

// importedHistory is what an import adds to an entry's history: sealed,
// the newest first, and the ids of the history the entry had when read,
// the newest first, which go above them.
type importedHistory struct {
	sealed           []oldSecret
	had              []int64
	noRoom, tooLarge int
}

func (h *importedHistory) count() int {
	if h == nil {
		return 0
	}
	return len(h.sealed)
}

func (h *importedHistory) result() ImportedHistory {
	if h == nil {
		return ImportedHistory{}
	}
	return ImportedHistory{Kept: len(h.sealed), NoRoom: h.noRoom, TooLarge: h.tooLarge}
}

// sealEarlier seals, for k's history, those of earlier that k doesn't
// have yet: not secret, the one it's about to replace (data and salt, nil
// when k is new), or one in its history; only as many as history.keep has
// room for below those, of which old, the replaced secret, will be one
// when it's kept, and none over MaxSecretSize: those are counted. A
// secret already kept that doesn't decrypt (damage) can't be compared,
// and is passed over.
func (s *Store) sealEarlier(k vault.Key, secret, data, salt []byte, old *oldSecret, earlier []vault.Earlier) (_ *importedHistory, err error) {
	have := [][]byte{secret}
	defer func() {
		for _, p := range have[1:] {
			secure.SecureZeroBytes(p)
		}
	}()
	open := func(data, salt, aad []byte) error {
		plain, err := s.oracle.DecryptEntry(data, salt, aad)
		switch {
		case errors.Is(err, ErrDecrypt):
			if kerr := s.keyUnchanged(s.db); errors.Is(kerr, ErrVaultKeyChanged) {
				return fmt.Errorf("decrypt %s: %w", k, kerr)
			}
			return nil
		case err != nil:
			return fmt.Errorf("decrypt %s: %w", k, err)
		}
		have = append(have, plain)
		return nil
	}
	h := &importedHistory{}
	if data != nil {
		if err := open(data, salt, entryAAD(k)); err != nil {
			return nil, err
		}
		rows, err := s.historyRows(s.db, k, 0)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			h.had = append(h.had, r.id)
			if err := open(r.data, r.salt, historyAAD(k)); err != nil {
				return nil, err
			}
		}
	}
	room := s.historyKeep - len(h.had)
	if old != nil && old.data != nil {
		room--
	}
	for _, e := range earlier {
		if len(e.Secret) == 0 || slices.ContainsFunc(have, func(p []byte) bool { return bytes.Equal(p, e.Secret) }) {
			continue
		}
		have = append(have, slices.Clone(e.Secret))
		switch {
		case len(e.Secret) > MaxSecretSize:
			h.tooLarge++
			continue
		case len(h.sealed) >= room:
			h.noRoom++
			continue
		}
		data, salt, err := s.oracle.EncryptEntry(e.Secret, historyAAD(k))
		if err != nil {
			return nil, fmt.Errorf("encrypt an earlier secret of %s: %w", k, err)
		}
		h.sealed = append(h.sealed, oldSecret{data: data, salt: salt, at: e.ReplacedAt})
	}
	return h, nil
}

// keepImported adds h to k's history, in tx: the imported secrets, the
// oldest first, then the history k had moved above them, so it stays the
// newer; history changed since it was read is refused with
// ErrEntryChanged.
func (s *Store) keepImported(tx *sql.Tx, k vault.Key, h *importedHistory) error {
	if h.count() == 0 {
		return nil
	}
	rows, err := s.historyRows(tx, k, 0)
	if err != nil {
		return err
	}
	if !slices.EqualFunc(rows, h.had, func(r resealedHistory, id int64) bool { return r.id == id }) {
		return ErrEntryChanged
	}
	// When an imported one was set isn't known: no later than replaced.
	for i := range slices.Backward(h.sealed) {
		o := &h.sealed[i]
		if _, err := tx.Exec(`INSERT INTO history (kind, service, username, encrypted_data, salt, replaced_at, set_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			string(k.Kind), k.Service, k.Username, o.data, o.salt, o.at.UTC(), o.at.UTC()); err != nil {
			return fmt.Errorf("keep %s's imported earlier secrets: %w", k, err)
		}
	}
	for _, id := range slices.Backward(h.had) {
		if _, err := tx.Exec(`INSERT INTO history (kind, service, username, encrypted_data, salt, replaced_at, set_at, file_name)
			SELECT kind, service, username, encrypted_data, salt, replaced_at, set_at, file_name FROM history WHERE id = ?`, id); err != nil {
			return fmt.Errorf("keep %s's history above what's imported: %w", k, err)
		}
		if _, err := tx.Exec(`DELETE FROM history WHERE id = ?`, id); err != nil {
			return fmt.Errorf("keep %s's history above what's imported: %w", k, err)
		}
	}
	return s.trimHistory(tx, k)
}

// resealedHistory is an entry's history sealed again for another name:
// each row's id, what it was, and what it is now.
type resealedHistory struct {
	from       []byte
	data, salt []byte
	id         int64
}

// resealHistory reads the history of k (in the trash with trashID, or
// live when 0) and seals it again for to, outside any transaction.
func (s *Store) resealHistory(k, to vault.Key, trashID int64) ([]resealedHistory, error) {
	rows, err := s.historyRows(s.db, k, trashID)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		r := &rows[i]
		r.from = r.data
		plain, err := s.oracle.DecryptEntry(r.data, r.salt, historyAAD(k))
		if err != nil {
			if kerr := s.keyUnchanged(s.db); errors.Is(kerr, ErrVaultKeyChanged) {
				return nil, fmt.Errorf("decrypt an earlier secret of %s: %w", k, kerr)
			}
			// Name the version, and how to forget it, as sesh history does.
			if trashID != 0 {
				return nil, fmt.Errorf("decrypt %s's version %d, in the trash: %w; restore it under its own name, then forget that version with: sesh history %s --forget %d",
					k, i+2, err, shell.Quote(k.String()), i+2)
			}
			return nil, fmt.Errorf("decrypt %s's version %d: %w; forget it with: sesh history %s --forget %d", k, i+2, err, shell.Quote(k.String()), i+2)
		}
		r.data, r.salt, err = s.oracle.EncryptEntry(plain, historyAAD(to))
		secure.SecureZeroBytes(plain)
		if err != nil {
			return nil, fmt.Errorf("encrypt an earlier secret of %s: %w", to, err)
		}
	}
	return rows, nil
}

// moveHistory writes rows, sealed again by resealHistory, as to's live
// history in tx, refusing with ErrEntryChanged a row changed since.
func moveHistory(tx *sql.Tx, rows []resealedHistory, to vault.Key) error {
	for _, r := range rows {
		res, err := tx.Exec(`UPDATE history SET kind = ?, service = ?, username = ?, trash_id = NULL, encrypted_data = ?, salt = ? WHERE id = ? AND encrypted_data = ?`,
			string(to.Kind), to.Service, to.Username, r.data, r.salt, r.id, r.from)
		if err != nil {
			return fmt.Errorf("move the history to %s: %w", to, err)
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return ErrEntryChanged
		}
	}
	return nil
}

// historyRows reads the history of k, live (trashID 0) or of the trash's
// entry trashID, the newest first.
func (s *Store) historyRows(q interface {
	Query(query string, args ...any) (*sql.Rows, error)
}, k vault.Key, trashID int64) (_ []resealedHistory, err error) {
	query := `SELECT id, encrypted_data, salt FROM history WHERE kind = ? AND service = ? AND username = ? AND trash_id IS NULL ORDER BY id DESC`
	args := []any{string(k.Kind), k.Service, k.Username}
	if trashID != 0 {
		query = `SELECT id, encrypted_data, salt FROM history WHERE trash_id = ? ORDER BY id DESC`
		args = []any{trashID}
	}
	rows, err := q.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("read the history of %s: %w", k, err)
	}
	defer func() {
		if cerr := rows.Close(); err == nil && cerr != nil {
			err = cerr
		}
	}()
	var out []resealedHistory
	for rows.Next() {
		var r resealedHistory
		if err := rows.Scan(&r.id, &r.data, &r.salt); err != nil {
			return nil, fmt.Errorf("read the history of %s: %w", k, err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// History is the entry k's earlier secrets, the newest first: version 2 is
// the first, as version 1 is the current secret.
func (s *Store) History(k vault.Key) (_ []Version, err error) {
	if err := s.Exists(k); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT id, replaced_at FROM history WHERE kind = ? AND service = ? AND username = ? AND trash_id IS NULL ORDER BY id DESC`,
		string(k.Kind), k.Service, k.Username)
	if err != nil {
		return nil, fmt.Errorf("read the history of %s: %w", k, err)
	}
	defer func() {
		if cerr := rows.Close(); err == nil && cerr != nil {
			err = cerr
		}
	}()
	var out []Version
	for rows.Next() {
		var v Version
		var at any
		if err := rows.Scan(&v.ID, &at); err != nil {
			return nil, fmt.Errorf("read the history of %s: %w", k, err)
		}
		v.ReplacedAt, _ = at.(time.Time)
		out = append(out, v)
	}
	return out, rows.Err()
}

// version is the row of k's version n (2 and up).
func (s *Store) version(k vault.Key, n int) (Version, error) {
	versions, err := s.History(k)
	if err != nil {
		return Version{}, err
	}
	if n < 2 || n-2 >= len(versions) {
		return Version{}, fmt.Errorf("%w: %s has versions 1 (the current secret) to %d", ErrNoVersion, k, len(versions)+1)
	}
	return versions[n-2], nil
}

// numbered is k's version want, by its row and when it was replaced, and
// its number now (2 and up); ErrVersionGone when the history no longer
// has it. Both are matched: a vault made before its ids stopped being
// reused can give a forgotten one's id to a secret replaced later.
func (s *Store) numbered(k vault.Key, want Version) (Version, int, error) {
	versions, err := s.History(k)
	if err != nil {
		return Version{}, 0, err
	}
	i := slices.IndexFunc(versions, func(v Version) bool { return v.ID == want.ID && v.ReplacedAt.Equal(want.ReplacedAt) })
	if i < 0 {
		return Version{}, 0, ErrVersionGone
	}
	return versions[i], i + 2, nil
}

// ReadVersionOf is the secret of k's version v, as History listed it,
// for reading, which the audit log records: ErrVersionGone when it's no
// longer in the history.
func (s *Store) ReadVersionOf(k vault.Key, v Version, reading string) ([]byte, error) {
	v, n, err := s.numbered(k, v)
	if err != nil {
		return nil, err
	}
	return s.readVersion(k, v, n, reading)
}

// ReadVersion is the secret of k's version n (2 and up), for reading,
// which the audit log records.
func (s *Store) ReadVersion(k vault.Key, n int, reading string) ([]byte, error) {
	v, err := s.version(k, n)
	if err != nil {
		return nil, err
	}
	return s.readVersion(k, v, n, reading)
}

// readVersion is the secret of k's version v, numbered n, for reading.
func (s *Store) readVersion(k vault.Key, v Version, n int, reading string) ([]byte, error) {
	var data, salt []byte
	err := s.db.QueryRow(`SELECT encrypted_data, salt FROM history WHERE id = ? AND kind = ? AND service = ? AND username = ? AND trash_id IS NULL`,
		v.ID, string(k.Kind), k.Service, k.Username).Scan(&data, &salt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrVersionGone // forgotten meanwhile
	}
	if err != nil {
		return nil, fmt.Errorf("read %s's version %d: %w", k, n, err)
	}
	secret, err := s.oracle.DecryptEntry(data, salt, historyAAD(k))
	if err != nil {
		if kerr := s.keyUnchanged(s.db); errors.Is(kerr, ErrVaultKeyChanged) {
			err = kerr
		}
		return nil, fmt.Errorf("decrypt %s's version %d: %w", k, n, err)
	}
	s.audit("access", k.String(), fmt.Sprintf("History: version %d, %s", n, reading))
	return secret, nil
}

// RestoreVersion makes k's version n (2 and up) its secret again; the
// secret it replaces goes into the history, as any replaced secret does.
// It reports whether that one was kept: not when none are, or when it's
// the same secret.
func (s *Store) RestoreVersion(k vault.Key, n int) (kept bool, err error) {
	v, err := s.version(k, n)
	if err != nil {
		return false, err
	}
	return s.restoreVersion(k, v, n)
}

// RestoreVersionOf is RestoreVersion of the version v, as History listed
// it, wherever it's numbered now: ErrVersionGone when it's no longer in
// the history.
func (s *Store) RestoreVersionOf(k vault.Key, v Version) (kept bool, err error) {
	v, n, err := s.numbered(k, v)
	if err != nil {
		return false, err
	}
	return s.restoreVersion(k, v, n)
}

func (s *Store) restoreVersion(k vault.Key, v Version, n int) (kept bool, err error) {
	secret, err := s.readVersion(k, v, n, "to restore it")
	if err != nil {
		return false, err
	}
	defer secure.SecureZeroBytes(secret)
	before, err := s.History(k)
	if err != nil {
		return false, err
	}
	// A file entry gets the file's name back with its content.
	restored := vault.Entry{Key: k}
	if k.Kind == vault.KindFile {
		if err := s.db.QueryRow(`SELECT file_name FROM history WHERE id = ?`, v.ID).Scan(&restored.Settings.FileName); err != nil {
			return false, fmt.Errorf("read version %d of %s: %w", n, k, err)
		}
	}
	if err := s.write(&restored, secret, false, nil, nil, nil); err != nil {
		return false, err
	}
	after, err := s.History(k)
	if err != nil {
		return false, err
	}
	s.audit("modify", k.String(), fmt.Sprintf("History: restored version %d", n))
	return len(after) > 0 && (len(before) == 0 || after[0].ID != before[0].ID), nil
}

// ForgetVersions deletes k's versions ns (2 and up) for good, all or
// none: each is resolved before any is deleted, so the numbers mean what
// they meant when they were listed.
func (s *Store) ForgetVersions(k vault.Key, ns ...int) error {
	ns = slices.Clone(ns)
	slices.Sort(ns)
	ns = slices.Compact(ns)
	versions, err := s.History(k)
	if err != nil {
		return err
	}
	var ids []int64
	for _, n := range ns {
		if n < 2 || n-2 >= len(versions) {
			return fmt.Errorf("%w: %s has versions 1 (the current secret) to %d; nothing was forgotten", ErrNoVersion, k, len(versions)+1)
		}
		ids = append(ids, versions[n-2].ID)
	}
	marks, err := s.forgetMarks(k, ids)
	if err != nil {
		return fmt.Errorf("forget %s's versions: %w", k, err)
	}
	err = s.inTx(func(tx *sql.Tx) error {
		for _, id := range ids {
			if _, err := tx.Exec(`DELETE FROM history WHERE id = ?`, id); err != nil {
				return err
			}
		}
		return markForgotten(tx, k, marks)
	})
	if err != nil {
		return fmt.Errorf("forget %s's versions: %w", k, err)
	}
	for _, n := range ns {
		s.audit("purge", k.String(), fmt.Sprintf("History: forgot version %d", n))
	}
	// Nor is it kept as typed for syncing.
	return s.typedKeptAll()
}

// ForgetVersionOf deletes k's version v, as History listed it, for good,
// wherever it's numbered now: ErrVersionGone when it's no longer in the
// history, even if another command forgets it meanwhile.
func (s *Store) ForgetVersionOf(k vault.Key, v Version) error {
	v, n, err := s.numbered(k, v)
	if err != nil {
		return err
	}
	id := v.ID
	marks, err := s.forgetMarks(k, []int64{id})
	if err != nil {
		return fmt.Errorf("forget %s's version %d: %w", k, n, err)
	}
	err = s.inTx(func(tx *sql.Tx) error {
		res, err := tx.Exec(`DELETE FROM history WHERE id = ? AND kind = ? AND service = ? AND username = ? AND trash_id IS NULL`,
			id, string(k.Kind), k.Service, k.Username)
		if err != nil {
			return err
		}
		if gone, err := res.RowsAffected(); err != nil || gone == 0 {
			return cmp.Or(err, ErrVersionGone)
		}
		return markForgotten(tx, k, marks)
	})
	if errors.Is(err, ErrVersionGone) {
		return err
	}
	if err != nil {
		return fmt.Errorf("forget %s's version %d: %w", k, n, err)
	}
	s.audit("purge", k.String(), fmt.Sprintf("History: forgot version %d", n))
	return s.typedKeptAll()
}

// forgetMarks are the marks (syncfolder.Forget) of k's earlier secrets in
// the history rows ids, opened to make them. A row gone meanwhile has none,
// nor has one that doesn't open (damaged): it's forgotten here only, and a
// sound copy of it on another computer comes back with a sync.
func (s *Store) forgetMarks(k vault.Key, ids []int64) ([]forgetMark, error) {
	var marks []forgetMark
	for _, id := range ids {
		var data, salt []byte
		var set time.Time
		err := s.db.QueryRow(`SELECT encrypted_data, salt, set_at FROM history WHERE id = ?`, id).Scan(&data, &salt, &set)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		secret, err := s.oracle.DecryptEntry(data, salt, historyAAD(k))
		if err != nil {
			if kerr := s.keyUnchanged(s.db); kerr != nil {
				return nil, kerr
			}
			continue
		}
		marks = append(marks, forgetMark{hash: syncfolder.Forget(secret), set: set})
		secure.SecureZeroBytes(secret)
	}
	return marks, nil
}

// forgetMark is an earlier secret being forgotten: its hash
// (syncfolder.Forget), and when its use was set.
type forgetMark struct {
	set  time.Time
	hash string
}

// markForgotten records, in tx, that k's earlier secrets with marks were
// forgotten on purpose, so a sync forgets them everywhere.
func markForgotten(tx *sql.Tx, k vault.Key, marks []forgetMark) error {
	now := time.Now().UTC()
	for _, m := range marks {
		// When its use was set, by whichever computer's clock, so every
		// copy of that use is forgotten (syncfolder.Forgotten), and a later
		// use of the same secret isn't; but no more than a day ahead of this
		// one's, so a clock set far wrong can't keep the same secret, used
		// again later, forgotten.
		at := m.set.UTC()
		if m.set.IsZero() {
			at = now
		}
		if limit := now.Add(24 * time.Hour); at.After(limit) {
			at = limit
		}
		if _, err := tx.Exec(`INSERT INTO history_forgotten (uid, hash, at) SELECT uid, ?, ? FROM entries WHERE kind = ? AND service = ? AND username = ?
			ON CONFLICT (uid, hash) DO UPDATE SET at = MAX(at, excluded.at)`,
			m.hash, at, string(k.Kind), k.Service, k.Username); err != nil {
			return err
		}
	}
	return nil
}

// PruneHistory drops, from every entry's history, live or in the trash,
// what's past the newest keep (all, for 0), and returns how many.
func (s *Store) PruneHistory(keep int) (int, error) {
	// Most of the time there's nothing past keep: look before taking the
	// write lock.
	var over bool
	if err := s.db.QueryRow(`SELECT EXISTS (SELECT 1 FROM (SELECT ROW_NUMBER() OVER (PARTITION BY kind, service, username, trash_id ORDER BY id DESC) AS n FROM history) WHERE n > ?)`, keep).Scan(&over); err != nil {
		return 0, fmt.Errorf("check the history against history.keep: %w", err)
	}
	if !over {
		return 0, nil
	}
	var n int64
	// Keeping fewer is this computer's setting, not a change to the
	// entries: it's done quietly.
	err := s.inTx(func(tx *sql.Tx) error {
		return quietly(tx, func() error {
			res, err := tx.Exec(`DELETE FROM history WHERE id IN (
				SELECT id FROM (SELECT id, ROW_NUMBER() OVER (PARTITION BY kind, service, username, trash_id ORDER BY id DESC) AS n FROM history)
				WHERE n > ?)`, keep)
			if err != nil {
				return err
			}
			n, err = res.RowsAffected()
			return err
		})
	})
	if err != nil {
		return 0, fmt.Errorf("drop earlier secrets past history.keep: %w", err)
	}
	if n > 0 {
		what := fmt.Sprintf("%d earlier secrets", n)
		if n == 1 {
			what = "1 earlier secret"
		}
		s.audit("purge", "", fmt.Sprintf("History: %s past history.keep (%d) dropped", what, keep))
		// Nor are they kept as typed for syncing.
		if err := s.typedKeptAll(); err != nil {
			return int(n), err
		}
	}
	return int(n), nil
}
