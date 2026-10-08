package database

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

// An entry's details (vault.Details) are stored in three parts on its
// row: the URL as it is; the readable part, as JSON (details), naming the
// fields in order and holding the plain values; and the notes and secret
// values, sealed together (sealed_details, details_salt; NULL for none).

// detailsAAD binds an entry's sealed details to its key, as entryAAD does
// its secret, under its own tag, so the two can't be swapped.
func detailsAAD(k vault.Key) []byte {
	return keyAAD("sesh-details-v1", k)
}

// Details implements vault.Store.
func (s *Store) Details(k vault.Key) (vault.Details, error) {
	var url, details string
	var sealed, salt []byte
	err := s.db.QueryRow(`SELECT url, details, sealed_details, details_salt FROM entries WHERE kind = ? AND service = ? AND username = ?`,
		string(k.Kind), k.Service, k.Username).Scan(&url, &details, &sealed, &salt)
	if errors.Is(err, sql.ErrNoRows) {
		return vault.Details{}, notFound(k)
	}
	if err != nil {
		return vault.Details{}, fmt.Errorf("read %s: %w", k, err)
	}
	e := vault.Entry{Key: k}
	if err := vault.DecodeEntryDetails(&e, url, details); err != nil {
		return vault.Details{}, err
	}
	var plain []byte
	if sealed != nil {
		plain, err = s.oracle.DecryptEntry(sealed, salt, detailsAAD(k))
		if err != nil {
			if kerr := s.keyUnchanged(s.db); errors.Is(kerr, ErrVaultKeyChanged) {
				err = kerr
			}
			return vault.Details{}, fmt.Errorf("decrypt the details of %s: %w", k, err)
		}
		defer secure.SecureZeroBytes(plain)
	}
	d, err := vault.DecodeDetails(&e, plain)
	if err != nil {
		return vault.Details{}, err
	}
	if sealed != nil {
		s.audit("access", k.String(), "Details")
	}
	return d, nil
}

// sealedDetails are an entry's details as stored: the URL, the readable
// part, and the sealed part with its salt (nil for none).
type sealedDetails struct {
	url, plain   string
	sealed, salt []byte
}

// sealDetails encodes d for k's row, sealing its notes and secret values
// to k.
func (s *Store) sealDetails(k vault.Key, d *vault.Details) (sealedDetails, error) {
	url, plain, sealedPlain, err := vault.EncodeDetails(d)
	if err != nil {
		return sealedDetails{}, err
	}
	defer secure.SecureZeroBytes(sealedPlain)
	sd := sealedDetails{url: url, plain: plain}
	if sealedPlain != nil {
		if sd.sealed, sd.salt, err = s.oracle.EncryptEntry(sealedPlain, detailsAAD(k)); err != nil {
			return sealedDetails{}, fmt.Errorf("encrypt the details of %s: %w", k, err)
		}
	}
	return sd, nil
}

// SetDetails implements vault.Store. The update time stays: it follows
// the secret.
func (s *Store) SetDetails(k vault.Key, d *vault.Details) error {
	if err := d.Check(k.Kind); err != nil {
		return err
	}
	sd, err := s.sealDetails(k, d)
	if err != nil {
		return err
	}
	var res sql.Result
	err = s.inTx(func(tx *sql.Tx) (err error) {
		res, err = tx.Exec(`UPDATE entries SET url = ?, details = ?, sealed_details = ?, details_salt = ? WHERE kind = ? AND service = ? AND username = ?`,
			sd.url, sd.plain, sd.sealed, sd.salt, string(k.Kind), k.Service, k.Username)
		return err
	})
	if err != nil {
		return fmt.Errorf("set the details of %s: %w", k, err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("set the details of %s: %w", k, err)
	} else if n == 0 {
		return notFound(k)
	}
	s.audit("modify", k.String(), "SetDetails")
	return nil
}
