package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

// ProblemKind is what Verify couldn't read in an entry.
type ProblemKind int

// The kinds of entry problem.
const (
	// ProblemSecret: the secret doesn't decrypt with the vault's key.
	ProblemSecret ProblemKind = iota + 1
	// ProblemSettings: the settings don't parse.
	ProblemSettings
	// ProblemTimes: the creation or update time doesn't read.
	ProblemTimes
	// ProblemDetails: the notes and custom fields don't decrypt or read.
	ProblemDetails
)

// EntryProblem is an entry Verify couldn't read: its secret or details
// don't decrypt, or its settings, times, or details don't parse.
type EntryProblem struct {
	Err  error
	Key  vault.Key
	Kind ProblemKind
}

// VerifyReport is what Verify found, all from one consistent view of the
// vault.
type VerifyReport struct {
	// Recovery is the recovery key record, nil when there's none or
	// RecoveryErr says it can't be read.
	Recovery    *RecoveryRecord
	RecoveryErr error
	// KeyID is the id of the vault's key record (UnlockID).
	KeyID string
	// Structure is what SQLite's integrity check found wrong with the
	// file, empty when it's sound. When the check itself couldn't run,
	// its error is the one line.
	Structure []string
	// Problems are the entries that can't be read, ordered by key.
	Problems []EntryProblem
	// Entries is how many entries the vault holds.
	Entries int
}

// Verify checks the vault without writing to it, from one read-only view of
// it: SQLite's integrity check of the file, then every entry's secret
// decrypted with the store's key and its settings and times read. It
// reports every problem rather than stopping at the first.
//
// Only a secret that doesn't decrypt with the vault's key (ErrDecrypt)
// counts as a damaged entry. Any other failure, such as an agent that
// locked or went away, or a master password changed by another command
// (ErrVaultKeyChanged), means the check couldn't finish, and is returned as
// an error with a partial report.
func (s *Store) Verify() (VerifyReport, error) {
	var r VerifyReport
	tx, err := s.db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return r, fmt.Errorf("read the vault: %w", err)
	}
	defer func() { _ = tx.Rollback() }() //nolint:errcheck // read-only; nothing to keep

	if err := s.keyUnchanged(tx); err != nil {
		return r, err
	}
	var verify []byte
	if err := tx.QueryRow(`SELECT verify FROM vault_key WHERE id = 1`).Scan(&verify); err != nil {
		return r, fmt.Errorf("read the vault's key record: %w", err)
	}
	r.KeyID = UnlockID(verify)
	r.Recovery, r.RecoveryErr = scanRecovery(tx)
	if errors.Is(r.RecoveryErr, ErrNoRecovery) {
		r.RecoveryErr = nil
	}
	r.Structure, err = integrityCheck(tx)
	if err != nil {
		// SQLite couldn't read enough of the file to check it; the
		// entries may still read, so carry on.
		r.Structure = []string{err.Error()}
	}

	type entry struct {
		timesErr           error
		k                  vault.Key
		data, salt         []byte
		sealed, sealedSalt []byte
		url, details       string
		settings           sql.NullString
	}
	// By row id, not through the name index, so a damaged index can't
	// hide an entry.
	rows, err := tx.Query(`SELECT kind, service, username, encrypted_data, salt, settings, url, details, sealed_details, details_salt, created_at, updated_at FROM entries NOT INDEXED ORDER BY id`)
	if err != nil {
		return r, fmt.Errorf("read entries: %w", err)
	}
	var all []entry
	for rows.Next() {
		var e entry
		var kind string
		var created, updated sql.NullTime
		if err := rows.Scan(&kind, &e.k.Service, &e.k.Username, &e.data, &e.salt, &e.settings, &e.url, &e.details, &e.sealed, &e.sealedSalt, &created, &updated); err != nil {
			// A time that doesn't read is the entry's problem; scan the
			// rest of the row without it.
			var raw1, raw2 any
			if err2 := rows.Scan(&kind, &e.k.Service, &e.k.Username, &e.data, &e.salt, &e.settings, &e.url, &e.details, &e.sealed, &e.sealedSalt, &raw1, &raw2); err2 != nil {
				_ = rows.Close() //nolint:errcheck // already failing
				return r, fmt.Errorf("read entries: %w", err2)
			}
			e.timesErr = fmt.Errorf("its times don't read: %w", err)
		}
		e.k.Kind = vault.Kind(kind)
		all = append(all, e)
	}
	if err := rows.Close(); err != nil {
		return r, fmt.Errorf("read entries: %w", err)
	}
	if err := rows.Err(); err != nil {
		return r, fmt.Errorf("read entries: %w", err)
	}
	r.Entries = len(all)
	for i := range all {
		e := &all[i]
		plain, err := s.oracle.DecryptEntry(e.data, e.salt, entryAAD(e.k))
		secure.SecureZeroBytes(plain)
		switch {
		case errors.Is(err, ErrDecrypt):
			r.Problems = append(r.Problems, EntryProblem{Key: e.k, Kind: ProblemSecret, Err: fmt.Errorf("its secret doesn't decrypt with the vault's key: %w", err)})
			continue
		case err != nil:
			return r, fmt.Errorf("couldn't finish checking %s: %w", e.k, err)
		}
		if _, err := decodeSettings(e.k, e.settings); err != nil {
			r.Problems = append(r.Problems, EntryProblem{Key: e.k, Kind: ProblemSettings, Err: err})
			continue
		}
		if err := s.checkDetails(e.k, e.url, e.details, e.sealed, e.sealedSalt); err != nil {
			if errors.Is(err, errCouldntCheck) {
				return r, fmt.Errorf("couldn't finish checking %s: %w", e.k, err)
			}
			r.Problems = append(r.Problems, EntryProblem{Key: e.k, Kind: ProblemDetails, Err: err})
			continue
		}
		if e.timesErr != nil {
			r.Problems = append(r.Problems, EntryProblem{Key: e.k, Kind: ProblemTimes, Err: e.timesErr})
		}
	}
	sort.Slice(r.Problems, func(i, j int) bool { return r.Problems[i].Key.Less(r.Problems[j].Key) })
	return r, nil
}

// errCouldntCheck marks a details check that failed for a reason other
// than damage, such as an agent that went away.
var errCouldntCheck = errors.New("couldn't check")

// checkDetails opens an entry's details as Details would, returning what
// doesn't read or breaks the rules SetDetails keeps. A failure that isn't
// damage wraps errCouldntCheck.
func (s *Store) checkDetails(k vault.Key, url, details string, sealed, salt []byte) error {
	e := vault.Entry{Key: k}
	if err := vault.DecodeEntryDetails(&e, url, details); err != nil {
		return err
	}
	var plain []byte
	if sealed != nil {
		var err error
		plain, err = s.oracle.DecryptEntry(sealed, salt, detailsAAD(k))
		switch {
		case errors.Is(err, ErrDecrypt):
			return fmt.Errorf("its notes and secret fields don't decrypt with the vault's key: %w", err)
		case err != nil:
			return fmt.Errorf("%w: %w", errCouldntCheck, err)
		}
		defer secure.SecureZeroBytes(plain)
	}
	d, err := vault.DecodeDetails(&e, plain)
	if err != nil {
		return err
	}
	defer d.Zero()
	return d.Check(k.Kind)
}

// rowsQuerier is a *sql.DB or a *sql.Tx, for queries returning rows.
type rowsQuerier interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

// integrityCheck runs SQLite's integrity check, returning what it found
// wrong (nothing when the file is sound).
func integrityCheck(q rowsQuerier) (_ []string, err error) {
	rows, err := q.Query(`PRAGMA integrity_check`)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := rows.Close(); err == nil {
			err = cerr
		}
	}()
	var found []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return nil, err
		}
		if line != "ok" {
			found = append(found, line)
		}
	}
	return found, rows.Err()
}

// LogImport records an import in the audit log, with what it brought in as
// detail.
func (s *Store) LogImport(detail string) {
	s.audit("import", "", detail)
}

// LogDoctor records a sesh doctor check of the vault in the audit log,
// with its result as detail.
func (s *Store) LogDoctor(detail string) {
	s.audit("doctor", "", detail)
}
