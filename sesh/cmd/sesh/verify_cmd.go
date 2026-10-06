package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/recovery"
	"github.com/bashhack/sesh/internal/touchid"
)

// runVerify is `sesh verify`: it unlocks the vault and checks that it can
// all be read. SQLite checks the file; every entry's secret is decrypted
// and its settings read; the recovery key's record must be able to open the
// vault, and Touch ID unlock must be this vault's. Nothing is written while
// it checks; one audit event records the result, if the file is sound.
// A problem with the file, an entry, or the recovery key is an error; one
// with Touch ID is a warning.
func runVerify(app *App, args []string) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-help" || args[0] == "-h") {
		_, err := fmt.Fprintln(app.Stdout, "Usage: sesh verify\n  Unlock the vault and check every entry can be read, and that its recovery key and Touch ID unlock still work.")
		return err
	}
	if len(args) > 0 {
		return fmt.Errorf("sesh verify takes no arguments, got %q", strings.Join(args, " "))
	}
	cfg, err := settings()
	if err != nil {
		return err
	}
	dbPath := cfg.DBPath.Value
	if err := requireVault(dbPath, "there's no vault yet: create it first, by running any sesh command or sesh init"); err != nil {
		return err
	}
	ks, err := buildKeySource(cfg)
	if err != nil {
		return err
	}
	// Opened without pruning the audit log: a check writes nothing until
	// it knows the file is sound.
	store, err := openStoreWith(dbPath, ks)
	if err != nil {
		return err
	}
	defer closeAuditStore(store)

	report, err := store.Verify()
	if err != nil {
		// SQLite couldn't read enough of the file to check it.
		return fmt.Errorf("the vault file at %s is damaged (%v); restore it from a backup, such as an encrypted export", tildePath(dbPath), err)
	}
	var b strings.Builder
	problems := 0
	fmt.Fprintf(&b, "Vault: %s\n", tildePath(dbPath))
	if len(report.Structure) == 0 {
		b.WriteString("  File: ok\n")
	} else {
		problems += len(report.Structure)
		fmt.Fprintf(&b, "  File: SQLite reports %s:\n", countOf(int64(len(report.Structure)), "problem"))
		for _, p := range report.Structure {
			fmt.Fprintf(&b, "    %s\n", p)
		}
	}
	if len(report.Problems) == 0 {
		fmt.Fprintf(&b, "  Entries: %s, all readable\n", entryCount(report.Entries))
	} else {
		problems += len(report.Problems)
		fmt.Fprintf(&b, "  Entries: %d of %s can't be read:\n", len(report.Problems), entryCount(report.Entries))
		for _, p := range report.Problems {
			fmt.Fprintf(&b, "    %s: %v\n", p.Key, p.Err)
		}
	}
	mat, err := database.ReadUnlockMaterial(dbPath)
	if err != nil {
		return err
	}
	id := database.UnlockID(mat.Verify)
	if line, ok := verifyRecovery(dbPath, id); ok {
		fmt.Fprintf(&b, "  Recovery key: %s\n", line)
	} else {
		problems++
		fmt.Fprintf(&b, "  Recovery key: %s\n", line)
	}
	fmt.Fprintf(&b, "  Touch ID: %s\n", verifyTouchID(filepath.Dir(dbPath), id))

	result := "ok"
	if problems > 0 {
		result = countOf(int64(problems), "problem")
	}
	if len(report.Structure) == 0 {
		store.LogVerify(fmt.Sprintf("%s, %s", result, entryCount(report.Entries)))
	}
	if problems == 0 {
		b.WriteString("Vault OK.\n")
	}
	if _, err := fmt.Fprint(app.Stdout, b.String()); err != nil {
		return err
	}
	if problems > 0 {
		return fmt.Errorf("the vault has %s (see above)", countOf(int64(problems), "problem"))
	}
	return nil
}

// verifyRecovery reports on the vault's recovery key: a line, and whether
// it's fine (none counts as fine). id is the vault's key record id.
func verifyRecovery(dbPath, id string) (string, bool) {
	r, err := database.ReadRecovery(dbPath)
	switch {
	case errors.Is(err, database.ErrNoRecovery):
		return "none", true
	case err != nil:
		return fmt.Sprintf("its record can't be read (%v); make a new one with: sesh recovery new", err), false
	case r.UnlockID != id:
		return "its record is for another vault or key, so it can't open this one; make a new one with: sesh recovery new", false
	}
	if err := recovery.CheckPublicKey(r.PublicKey); err != nil {
		return fmt.Sprintf("its record is damaged (%v); make a new one with: sesh recovery new", err), false
	}
	return "set, and made for this vault's key", true
}

// verifyTouchID reports on Touch ID unlock for the vault whose key record
// id is id, from its file in dataDir. A stale setup only costs typing the
// password, so it's a warning, never a failure.
func verifyTouchID(dataDir, id string) string {
	f, err := touchid.ReadFile(dataDir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "off"
	case err != nil:
		return fmt.Sprintf("warning: its file can't be read (%v); turn it back on with: sesh touchid enable", err)
	case f.UnlockID != id:
		return "warning: it was set up for another vault or an earlier master password, so it won't unlock this one; turn it back on with: sesh touchid enable"
	case fingerprintsChanged(f):
		return "warning: your fingerprints changed since it was set up, so it won't unlock; turn it back on with: sesh touchid enable"
	}
	return "on, for this vault"
}
