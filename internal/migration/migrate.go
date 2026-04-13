// Package migration provides tools for migrating credential data between storage backends.
package migration

import (
	"fmt"

	"github.com/bashhack/sesh/internal/constants"
	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/secure"
)

var migratePrefixes = []string{
	constants.AWSServicePrefix,
	constants.AWSServiceMFAPrefix,
	constants.TOTPServicePrefix,
}

// Result reports what happened during migration.
type Result struct {
	Errors   []string
	Migrated int
	Skipped  int
}

// PlanEntry describes a single entry that would be migrated.
type PlanEntry struct {
	Service     string
	Account     string
	Description string
}

// Plan scans the source for all sesh entries and returns what would be migrated.
func Plan(source keychain.Provider) ([]PlanEntry, error) {
	var plan []PlanEntry

	for _, prefix := range migratePrefixes {
		entries, err := source.ListEntries(prefix)
		if err != nil {
			return nil, fmt.Errorf("list %s entries: %w", prefix, err)
		}
		for _, e := range entries {
			plan = append(plan, PlanEntry{
				Service:     e.Service,
				Account:     e.Account,
				Description: e.Description,
			})
		}
	}

	return plan, nil
}

// Migrate copies all sesh entries from source to dest.
// Existing entries in dest are skipped (not overwritten).
func Migrate(source, dest keychain.Provider) (Result, error) {
	var result Result

	for _, prefix := range migratePrefixes {
		entries, err := source.ListEntries(prefix)
		if err != nil {
			return result, fmt.Errorf("list %s entries: %w", prefix, err)
		}

		for _, entry := range entries {
			secret, err := source.GetSecret(entry.Account, entry.Service)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: failed to read: %v", entry.Service, err))
				continue
			}

			// Check if entry already exists in dest
			existing, getErr := dest.GetSecret(entry.Account, entry.Service)
			if getErr == nil {
				secure.SecureZeroBytes(existing)
				result.Skipped++
				secure.SecureZeroBytes(secret)
				continue
			}

			if err := dest.SetSecret(entry.Account, entry.Service, secret); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: failed to write: %v", entry.Service, err))
				secure.SecureZeroBytes(secret)
				continue
			}
			secure.SecureZeroBytes(secret)

			if entry.Description != "" {
				if descErr := dest.SetDescription(entry.Service, entry.Account, entry.Description); descErr != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("%s: migrated but description failed: %v", entry.Service, descErr))
				}
			}

			result.Migrated++
		}
	}

	return result, nil
}
