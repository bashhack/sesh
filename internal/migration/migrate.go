// Package migration provides tools for migrating credential data between storage backends.
package migration

import (
	"errors"
	"fmt"
	"time"

	"github.com/bashhack/sesh/internal/constants"
	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/secure"
)

var migratePrefixes = []string{
	constants.AWSServicePrefix,
	constants.AWSServiceMFAPrefix,
	constants.TOTPServicePrefix,
	constants.PasswordServicePrefix,
}

// entryKey identifies a credential by its (service, account) pair. Used
// to dedupe when overlapping prefixes — e.g. "sesh-aws" is a byte-prefix
// of "sesh-aws-serial", so a SQLite-backed source's prefix-range ListEntries
// would return the same serial entry under both prefixes.
type entryKey struct {
	service string
	account string
}

// Result reports what happened during migration.
type Result struct {
	Errors   []string
	Migrated int
	Skipped  int
}

// PlanEntry describes a single entry that would be migrated. CreatedAt and
// UpdatedAt come from the source's ListEntries; they may be zero for sources
// that don't track timestamps (e.g. macOS Keychain).
type PlanEntry struct {
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Service     string
	Account     string
	Description string
}

// Plan scans the source for all sesh entries and returns what would be migrated.
func Plan(source keychain.Provider) ([]PlanEntry, error) {
	var plan []PlanEntry
	seen := make(map[entryKey]bool)

	for _, prefix := range migratePrefixes {
		entries, err := source.ListEntries(prefix)
		if err != nil {
			return nil, fmt.Errorf("list %s entries: %w", prefix, err)
		}
		for _, e := range entries {
			k := entryKey{service: e.Service, account: e.Account}
			if seen[k] {
				continue
			}
			seen[k] = true
			plan = append(plan, PlanEntry{
				Service:     e.Service,
				Account:     e.Account,
				Description: e.Description,
				CreatedAt:   e.CreatedAt,
				UpdatedAt:   e.UpdatedAt,
			})
		}
	}

	return plan, nil
}

// Migrate copies all sesh entries from source to dest.
// Existing entries in dest are skipped (not overwritten).
//
// If dest implements keychain.TimestampedStore, the source's CreatedAt /
// UpdatedAt are forwarded to SetSecretAt / SetDescriptionAt so audit history
// survives the copy. Sources that don't track timestamps return zero values,
// and the timestamped methods fall back to time.Now in that case — so this
// path is a strict superset of the bare SetSecret behaviour.
func Migrate(source, dest keychain.Provider) (Result, error) {
	var result Result
	seen := make(map[entryKey]bool)
	ts, _ := dest.(keychain.TimestampedStore)

	for _, prefix := range migratePrefixes {
		entries, err := source.ListEntries(prefix)
		if err != nil {
			return result, fmt.Errorf("list %s entries: %w", prefix, err)
		}

		for _, entry := range entries {
			k := entryKey{service: entry.Service, account: entry.Account}
			if seen[k] {
				continue
			}
			seen[k] = true
			// Check destination before reading the source secret so skipped
			// entries never materialize plaintext in memory. Only a confirmed
			// ErrNotFound permits writing; other errors (I/O, decrypt,
			// locked DB) must not be treated as absence.
			existing, getErr := dest.GetSecret(entry.Account, entry.Service)
			switch {
			case getErr == nil:
				secure.SecureZeroBytes(existing)
				result.Skipped++
				continue
			case errors.Is(getErr, keychain.ErrNotFound):
				// Not present — proceed to read source and write.
			default:
				result.Errors = append(result.Errors, fmt.Sprintf("%s: failed to check destination: %v", entry.Service, getErr))
				continue
			}

			secret, err := source.GetSecret(entry.Account, entry.Service)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: failed to read: %v", entry.Service, err))
				continue
			}

			if writeErr := writeEntry(dest, ts, &entry, secret); writeErr != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: failed to write: %v", entry.Service, writeErr))
				secure.SecureZeroBytes(secret)
				continue
			}
			secure.SecureZeroBytes(secret)

			if entry.Description != "" {
				if descErr := writeDescription(dest, ts, &entry); descErr != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("%s: migrated but description failed: %v", entry.Service, descErr))
				}
			}

			result.Migrated++
		}
	}

	return result, nil
}

func writeEntry(dest keychain.Provider, ts keychain.TimestampedStore, entry *keychain.KeychainEntry, secret []byte) error {
	if ts != nil {
		return ts.SetSecretAt(entry.Account, entry.Service, secret, entry.CreatedAt, entry.UpdatedAt)
	}
	return dest.SetSecret(entry.Account, entry.Service, secret)
}

func writeDescription(dest keychain.Provider, ts keychain.TimestampedStore, entry *keychain.KeychainEntry) error {
	if ts != nil {
		return ts.SetDescriptionAt(entry.Service, entry.Account, entry.Description, entry.UpdatedAt)
	}
	return dest.SetDescription(entry.Service, entry.Account, entry.Description)
}
