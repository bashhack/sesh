// Package migration copies every entry from one vault to another: key
// changes (rekey, master password rotation, recovery) use it to re-encrypt
// a vault under a new key.
package migration

import (
	"errors"
	"fmt"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

// Result reports what a copy did.
type Result struct {
	Errors   []string
	Migrated int
	Skipped  int
}

// Plan returns every entry in source, without secrets: what Migrate copies.
func Plan(source vault.Store) ([]vault.Entry, error) {
	entries, err := source.List(vault.Filter{})
	if err != nil {
		return nil, fmt.Errorf("list entries: %w", err)
	}
	return entries, nil
}

// Migrate copies every entry in source to dest, with its settings and
// times. An entry dest already holds is skipped, not overwritten.
func Migrate(source, dest vault.Store) (Result, error) {
	var result Result
	entries, err := Plan(source)
	if err != nil {
		return result, err
	}
	for i := range entries {
		e := &entries[i]
		// Check dest before reading the secret, so a skipped entry's
		// plaintext is never read. Only a confirmed absence permits
		// writing; any other error isn't taken as absence.
		_, err := dest.Lookup(e.Key)
		switch {
		case err == nil:
			result.Skipped++
			continue
		case errors.Is(err, vault.ErrNotFound):
		default:
			result.Errors = append(result.Errors, fmt.Sprintf("%s: failed to check destination: %v", e.Key, err))
			continue
		}

		secret, err := source.Get(e.Key)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: failed to read: %v", e.Key, err))
			continue
		}
		err = dest.Save(e, secret)
		secure.SecureZeroBytes(secret)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: failed to write: %v", e.Key, err))
			continue
		}
		result.Migrated++
	}
	return result, nil
}
