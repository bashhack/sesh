package database

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

// ErrNameTaken is an edit's new name being another entry's.
var ErrNameTaken = errors.New("another entry has that name")

// ErrEntryChanged is an entry changed by another sesh command while an edit
// was re-sealing its secret.
var ErrEntryChanged = errors.New("the entry was changed by another sesh command meanwhile; run this again")

// EntryEdit is a change to an entry: To, its new key (nil keeps it), and
// Secret, its new secret (nil keeps it; the caller zeroes it).
type EntryEdit struct {
	To     *vault.Key
	Secret []byte
}

// Edit changes the entry at k as e says, in one transaction. Its secret is
// sealed to its key (entryAAD), so a new key re-seals it: decrypted,
// encrypted for the new key, and written with it. The row stays, so its
// folder, tags, settings, and creation time come along; its update time
// moves only with a new secret. A new key another entry has is ErrNameTaken;
// the entry changed meanwhile is ErrEntryChanged. It returns the change, in
// words, as the audit event records it.
func (s *Store) Edit(k vault.Key, e EntryEdit) (string, error) {
	if e.To == nil && e.Secret == nil {
		return "", errors.New("nothing to change")
	}
	to := k
	if e.To != nil {
		if err := e.To.Validate(); err != nil {
			return "", err
		}
		to = *e.To
	}
	if len(e.Secret) > MaxSecretSize {
		return "", fmt.Errorf("%w: %d bytes (max %d)", ErrSecretTooLarge, len(e.Secret), MaxSecretSize)
	}

	var id int64
	var data, salt []byte
	err := s.db.QueryRow(`SELECT id, encrypted_data, salt FROM entries WHERE kind = ? AND service = ? AND username = ?`,
		string(k.Kind), k.Service, k.Username).Scan(&id, &data, &salt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", notFound(k)
	}
	if err != nil {
		return "", fmt.Errorf("read %s: %w", k, err)
	}
	if to != k {
		if err := s.nameFree(s.db, to, id); err != nil {
			return "", err
		}
	}

	// Seal outside the transaction, as a password change does: the agent
	// may take a moment, and the write lock shouldn't wait on it.
	plain := e.Secret
	if plain == nil {
		plain, err = s.oracle.DecryptEntry(data, salt, entryAAD(k))
		if err != nil {
			return "", fmt.Errorf("decrypt %s: %w", k, err)
		}
		defer secure.SecureZeroBytes(plain)
	}
	newData, newSalt, err := s.oracle.EncryptEntry(plain, entryAAD(to))
	if err != nil {
		return "", fmt.Errorf("encrypt %s: %w", to, err)
	}

	var what []string
	if to != k {
		what = append(what, "renamed from "+k.String())
	}
	if e.Secret != nil {
		what = append(what, "secret changed")
	}
	detail := strings.Join(what, " and ")
	err = s.inTx(func(tx *sql.Tx) error {
		var now []byte
		err := tx.QueryRow(`SELECT encrypted_data FROM entries WHERE id = ? AND kind = ? AND service = ? AND username = ?`,
			id, string(k.Kind), k.Service, k.Username).Scan(&now)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && !bytes.Equal(now, data)) {
			return ErrEntryChanged
		}
		if err != nil {
			return err
		}
		if to != k {
			if err := s.nameFree(tx, to, id); err != nil {
				return err
			}
		}
		q := `UPDATE entries SET kind = ?, service = ?, username = ?, encrypted_data = ?, salt = ? WHERE id = ?`
		args := []any{string(to.Kind), to.Service, to.Username, newData, newSalt, id}
		if e.Secret != nil {
			q = `UPDATE entries SET kind = ?, service = ?, username = ?, encrypted_data = ?, salt = ?, updated_at = ? WHERE id = ?`
			args = []any{string(to.Kind), to.Service, to.Username, newData, newSalt, time.Now().UTC(), id}
		}
		_, err = tx.Exec(q, args...)
		return err
	})
	if err != nil {
		return "", err
	}
	s.audit("modify", to.String(), "Edit: "+detail)
	return detail, nil
}

// nameFree refuses to when an entry other than row id has it.
func (s *Store) nameFree(q querier, to vault.Key, id int64) error {
	var other int64
	err := q.QueryRow(`SELECT id FROM entries WHERE kind = ? AND service = ? AND username = ?`,
		string(to.Kind), to.Service, to.Username).Scan(&other)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return fmt.Errorf("check %s: %w", to, err)
	case other != id:
		return fmt.Errorf("%w: %s; delete or rename that one first", ErrNameTaken, to)
	}
	return nil
}
