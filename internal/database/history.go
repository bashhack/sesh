package database

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/bashhack/sesh/internal/secure"
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

// SetHistoryKeep sets how many earlier secrets each entry keeps; 0 keeps
// none. A new Store keeps none.
func (s *Store) SetHistoryKeep(n int) { s.historyKeep = n }

// HistoryKeep is how many earlier secrets each entry keeps.
func (s *Store) HistoryKeep() int { return s.historyKeep }

// oldSecret is an entry's secret about to be replaced, sealed for its
// history: from is the row it was read from, so the write can check it
// hasn't changed since.
type oldSecret struct {
	data, salt []byte // sealed for history
	from       []byte // the entry's encrypted_data it was read from
}

// replacing is the entry k's secret, sealed (data, salt), kept for its
// history as to's when it's being replaced by next (nil when the secret
// isn't changing) and differs from it; nil when there's nothing to keep.
func (s *Store) replacing(k, to vault.Key, data, salt, next []byte) (*oldSecret, error) {
	if s.historyKeep == 0 || next == nil {
		return nil, nil
	}
	plain, err := s.oracle.DecryptEntry(data, salt, entryAAD(k))
	if err != nil {
		if kerr := s.keyUnchanged(s.db); errors.Is(kerr, ErrVaultKeyChanged) {
			err = kerr
		}
		return nil, fmt.Errorf("decrypt %s: %w", k, err)
	}
	defer secure.SecureZeroBytes(plain)
	if bytes.Equal(plain, next) {
		return nil, nil
	}
	hd, hs, err := s.oracle.EncryptEntry(plain, historyAAD(to))
	if err != nil {
		return nil, fmt.Errorf("encrypt %s's earlier secret: %w", to, err)
	}
	return &oldSecret{data: hd, salt: hs, from: data}, nil
}

// keepOld records old as k's latest earlier secret, in tx, and drops the
// oldest past the store's history.keep.
func (s *Store) keepOld(tx *sql.Tx, k vault.Key, old *oldSecret, at time.Time) error {
	if _, err := tx.Exec(`INSERT INTO history (kind, service, username, encrypted_data, salt, replaced_at) VALUES (?, ?, ?, ?, ?, ?)`,
		string(k.Kind), k.Service, k.Username, old.data, old.salt, at); err != nil {
		return fmt.Errorf("keep %s's earlier secret: %w", k, err)
	}
	_, err := tx.Exec(`DELETE FROM history WHERE trash_id IS NULL AND kind = ? AND service = ? AND username = ? AND id NOT IN (
		SELECT id FROM history WHERE trash_id IS NULL AND kind = ? AND service = ? AND username = ? ORDER BY replaced_at DESC, id DESC LIMIT ?)`,
		string(k.Kind), k.Service, k.Username, string(k.Kind), k.Service, k.Username, s.historyKeep)
	return err
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
				err = kerr
			}
			return nil, fmt.Errorf("decrypt an earlier secret of %s: %w", k, err)
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
	query := `SELECT id, encrypted_data, salt FROM history WHERE kind = ? AND service = ? AND username = ? AND trash_id IS NULL ORDER BY replaced_at DESC, id DESC`
	args := []any{string(k.Kind), k.Service, k.Username}
	if trashID != 0 {
		query = `SELECT id, encrypted_data, salt FROM history WHERE trash_id = ? ORDER BY replaced_at DESC, id DESC`
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
	rows, err := s.db.Query(`SELECT id, replaced_at FROM history WHERE kind = ? AND service = ? AND username = ? AND trash_id IS NULL ORDER BY replaced_at DESC, id DESC`,
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

// ReadVersion is the secret of k's version n (2 and up), for reading,
// which the audit log records.
func (s *Store) ReadVersion(k vault.Key, n int, reading string) ([]byte, error) {
	v, err := s.version(k, n)
	if err != nil {
		return nil, err
	}
	var data, salt []byte
	if err := s.db.QueryRow(`SELECT encrypted_data, salt FROM history WHERE id = ?`, v.ID).Scan(&data, &salt); err != nil {
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
func (s *Store) RestoreVersion(k vault.Key, n int) error {
	secret, err := s.ReadVersion(k, n, "to restore it")
	if err != nil {
		return err
	}
	defer secure.SecureZeroBytes(secret)
	if err := s.write(&vault.Entry{Key: k}, secret, false, nil); err != nil {
		return err
	}
	s.audit("modify", k.String(), fmt.Sprintf("History: restored version %d", n))
	return nil
}

// ForgetVersion deletes k's version n (2 and up) for good.
func (s *Store) ForgetVersion(k vault.Key, n int) error {
	v, err := s.version(k, n)
	if err != nil {
		return err
	}
	err = s.inTx(func(tx *sql.Tx) error {
		_, err := tx.Exec(`DELETE FROM history WHERE id = ?`, v.ID)
		return err
	})
	if err != nil {
		return fmt.Errorf("forget %s's version %d: %w", k, n, err)
	}
	s.audit("purge", k.String(), fmt.Sprintf("History: forgot version %d", n))
	return nil
}
