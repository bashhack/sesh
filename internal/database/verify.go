package database

import (
	"database/sql"
	"fmt"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

// EntryProblem is an entry Verify couldn't read: its secret doesn't decrypt,
// or its settings don't parse.
type EntryProblem struct {
	Err error
	Key vault.Key
}

// VerifyReport is what Verify found.
type VerifyReport struct {
	// Structure is SQLite's integrity check result: nil when the file is
	// sound, otherwise each problem it names.
	Structure []string
	// Problems are the entries that can't be read.
	Problems []EntryProblem
	// Entries is how many entries the vault holds.
	Entries int
}

// Verify checks the vault without writing to it: SQLite's integrity check
// of the file, then every entry's secret decrypted with the store's key and
// its settings parsed. It reports every problem rather than stopping at the
// first; an error means the checks themselves couldn't run.
func (s *Store) Verify() (VerifyReport, error) {
	var r VerifyReport
	rows, err := s.db.Query(`PRAGMA integrity_check`)
	if err != nil {
		return r, fmt.Errorf("check the vault file: %w", err)
	}
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			_ = rows.Close() //nolint:errcheck // already failing
			return r, fmt.Errorf("check the vault file: %w", err)
		}
		if line != "ok" {
			r.Structure = append(r.Structure, line)
		}
	}
	if err := rows.Close(); err != nil {
		return r, fmt.Errorf("check the vault file: %w", err)
	}
	if err := rows.Err(); err != nil {
		return r, fmt.Errorf("check the vault file: %w", err)
	}

	type entry struct {
		k          vault.Key
		data, salt []byte
		settings   sql.NullString
	}
	erows, err := s.db.Query(`SELECT kind, service, username, encrypted_data, salt, settings FROM entries ORDER BY kind, service, username`)
	if err != nil {
		return r, fmt.Errorf("read entries: %w", err)
	}
	var all []entry
	for erows.Next() {
		var e entry
		var kind string
		if err := erows.Scan(&kind, &e.k.Service, &e.k.Username, &e.data, &e.salt, &e.settings); err != nil {
			_ = erows.Close() //nolint:errcheck // already failing
			return r, fmt.Errorf("read entries: %w", err)
		}
		e.k.Kind = vault.Kind(kind)
		all = append(all, e)
	}
	if err := erows.Close(); err != nil {
		return r, fmt.Errorf("read entries: %w", err)
	}
	if err := erows.Err(); err != nil {
		return r, fmt.Errorf("read entries: %w", err)
	}
	r.Entries = len(all)
	for _, e := range all {
		plain, err := s.oracle.DecryptEntry(e.data, e.salt, entryAAD(e.k))
		secure.SecureZeroBytes(plain)
		if err != nil {
			r.Problems = append(r.Problems, EntryProblem{Key: e.k, Err: fmt.Errorf("its secret doesn't decrypt: %w", err)})
			continue
		}
		if _, err := decodeSettings(e.k, e.settings); err != nil {
			r.Problems = append(r.Problems, EntryProblem{Key: e.k, Err: err})
		}
	}
	return r, nil
}

// LogVerify records a verify in the audit log, with its result as detail.
func (s *Store) LogVerify(detail string) {
	s.audit("verify", "", detail)
}
