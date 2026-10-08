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

// ErrNothingToChange is an edit that would leave the entry as it is.
var ErrNothingToChange = errors.New("nothing to change")

// EntryEdit is a change to an entry: To, its new key (nil keeps it);
// Secret, its new secret (nil keeps it; the caller zeroes it); and
// Details, a change to its details (nil keeps them).
type EntryEdit struct {
	To      *vault.Key
	Details *vault.DetailsChange
	Secret  []byte
}

// Edit changes the entry at k as e says, in one transaction. Its secret and
// details are sealed to its key (entryAAD, detailsAAD), so a new key
// re-seals them: decrypted, encrypted for the new key, and written with
// it. The details after the change must pass Details.Check for the new
// kind, so an entry keeping notes can't become a secure note. The row
// stays, so its folder, tags, settings, and creation time come along; its
// update time moves only with a new secret. A new key another entry has is
// ErrNameTaken; the entry changed meanwhile is ErrEntryChanged. It returns
// the change, in words, as the audit event records it.
func (s *Store) Edit(k vault.Key, e EntryEdit) (string, error) {
	if e.To != nil && *e.To == k {
		e.To = nil
	}
	if e.Details != nil && e.Details.IsZero() {
		e.Details = nil
	}
	if e.To == nil && e.Secret == nil && e.Details == nil {
		return "", ErrNothingToChange
	}
	if e.Secret != nil && len(e.Secret) == 0 {
		return "", errors.New("the new secret is empty")
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
	var data, salt, sealed, sealedSalt []byte
	var url, details string
	err := s.db.QueryRow(`SELECT id, encrypted_data, salt, url, details, sealed_details, details_salt FROM entries WHERE kind = ? AND service = ? AND username = ?`,
		string(k.Kind), k.Service, k.Username).Scan(&id, &data, &salt, &url, &details, &sealed, &sealedSalt)
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
	ent := vault.Entry{Key: k}
	if err := vault.DecodeEntryDetails(&ent, url, details); err != nil {
		return "", err
	}
	if e.Details == nil && to.Kind == vault.KindNote && k.Kind != vault.KindNote && ent.HasNotes {
		return "", fmt.Errorf("%s has notes, and a secure note can't: its secret is the note; remove the notes first", k)
	}

	var what []string
	if to != k {
		what = append(what, "renamed from "+k.String())
	}
	if e.Secret != nil {
		what = append(what, "secret changed")
	}
	// Seal outside the transaction, as a password change does: the agent
	// may take a moment, and the write lock shouldn't wait on it.
	newData, newSalt := data, salt
	if to != k || e.Secret != nil {
		if newData, newSalt, err = s.resealSecret(k, to, data, salt, e.Secret); err != nil {
			return "", err
		}
	}
	// The details are sealed to the name too.
	nd := sealedDetails{url: url, plain: details, sealed: sealed, salt: sealedSalt}
	switch {
	case e.Details != nil:
		changed, err := s.changeDetails(&ent, sealed, sealedSalt, to, e.Details)
		if err != nil {
			return "", err
		}
		if changed.what != "" {
			what = append(what, changed.what)
		}
		nd = changed.sealedDetails
	case to != k && sealed != nil:
		if nd.sealed, nd.salt, err = s.resealDetails(k, to, sealed, sealedSalt); err != nil {
			return "", err
		}
	}
	if len(what) == 0 {
		return "", ErrNothingToChange
	}

	detail := strings.Join(what, " and ")
	err = s.inTx(func(tx *sql.Tx) error {
		var dataNow, sealedNow []byte
		var urlNow, detailsNow string
		err := tx.QueryRow(`SELECT encrypted_data, url, details, sealed_details FROM entries WHERE id = ? AND kind = ? AND service = ? AND username = ?`,
			id, string(k.Kind), k.Service, k.Username).Scan(&dataNow, &urlNow, &detailsNow, &sealedNow)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && (!bytes.Equal(dataNow, data) || !bytes.Equal(sealedNow, sealed) || urlNow != url || detailsNow != details)) {
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
		q := `UPDATE entries SET kind = ?, service = ?, username = ?, encrypted_data = ?, salt = ?, url = ?, details = ?, sealed_details = ?, details_salt = ? WHERE id = ?`
		args := []any{string(to.Kind), to.Service, to.Username, newData, newSalt, nd.url, nd.plain, nd.sealed, nd.salt, id}
		if e.Secret != nil {
			q = `UPDATE entries SET kind = ?, service = ?, username = ?, encrypted_data = ?, salt = ?, url = ?, details = ?, sealed_details = ?, details_salt = ?, updated_at = ? WHERE id = ?`
			args = []any{string(to.Kind), to.Service, to.Username, newData, newSalt, nd.url, nd.plain, nd.sealed, nd.salt, time.Now().UTC(), id}
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

// resealSecret is the secret for to: secret when given, or k's sealed
// secret (data, salt) opened and sealed again for to.
func (s *Store) resealSecret(k, to vault.Key, data, salt, secret []byte) (newData, newSalt []byte, err error) {
	plain := secret
	if plain == nil {
		plain, err = s.oracle.DecryptEntry(data, salt, entryAAD(k))
		if err != nil {
			// A master password changed meanwhile reads as a wrong key; say so.
			if kerr := s.keyUnchanged(s.db); errors.Is(kerr, ErrVaultKeyChanged) {
				err = kerr
			}
			return nil, nil, fmt.Errorf("decrypt %s: %w", k, err)
		}
		defer secure.SecureZeroBytes(plain)
	}
	if newData, newSalt, err = s.oracle.EncryptEntry(plain, entryAAD(to)); err != nil {
		return nil, nil, fmt.Errorf("encrypt %s: %w", to, err)
	}
	return newData, newSalt, nil
}

// changedDetails are details after a change, as stored for the new key,
// and what changed, in words ("" for nothing).
type changedDetails struct {
	what string
	sealedDetails
}

// changeDetails opens ent's details (its sealed part, sealed and salt),
// makes change to them, checks them for to's kind, and seals them for to.
func (s *Store) changeDetails(ent *vault.Entry, sealed, salt []byte, to vault.Key, change *vault.DetailsChange) (changedDetails, error) {
	var plain []byte
	if sealed != nil {
		var err error
		plain, err = s.oracle.DecryptEntry(sealed, salt, detailsAAD(ent.Key))
		if err != nil {
			if kerr := s.keyUnchanged(s.db); errors.Is(kerr, ErrVaultKeyChanged) {
				err = kerr
			}
			return changedDetails{}, fmt.Errorf("decrypt the details of %s: %w", ent.Key, err)
		}
		defer secure.SecureZeroBytes(plain)
	}
	d, err := vault.DecodeDetails(ent, plain)
	if err != nil {
		return changedDetails{}, err
	}
	defer d.Zero()
	what, err := change.Apply(&d)
	if err != nil {
		return changedDetails{}, err
	}
	if err := d.Check(to.Kind); err != nil {
		return changedDetails{}, err
	}
	sd, err := s.sealDetails(to, &d)
	if err != nil {
		return changedDetails{}, err
	}
	return changedDetails{what: what, sealedDetails: sd}, nil
}

// resealDetails opens k's sealed details and seals them for to.
func (s *Store) resealDetails(k, to vault.Key, sealed, salt []byte) (newSealed, newSalt []byte, err error) {
	plain, err := s.oracle.DecryptEntry(sealed, salt, detailsAAD(k))
	if err != nil {
		if kerr := s.keyUnchanged(s.db); errors.Is(kerr, ErrVaultKeyChanged) {
			err = kerr
		}
		return nil, nil, fmt.Errorf("decrypt the details of %s: %w", k, err)
	}
	defer secure.SecureZeroBytes(plain)
	if newSealed, newSalt, err = s.oracle.EncryptEntry(plain, detailsAAD(to)); err != nil {
		return nil, nil, fmt.Errorf("encrypt the details of %s: %w", to, err)
	}
	return newSealed, newSalt, nil
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
