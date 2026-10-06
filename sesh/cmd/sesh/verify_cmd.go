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

// structureLinesShown is how many of SQLite's findings verify prints.
const structureLinesShown = 10

// runVerify is `sesh verify`: it unlocks the vault and checks that it can
// all be read. SQLite checks the file; every entry's secret is decrypted
// and its settings and times read; the recovery key's record must be shaped
// to open the vault, and Touch ID unlock must be this vault's. Nothing is
// written while it checks; one audit event records the result, if the file
// is sound. A problem with the file, an entry, or the recovery key is an
// error; one with Touch ID is a warning.
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
	damagedFile := func(err error) error {
		if database.IsDamaged(err) {
			return fmt.Errorf("the vault file at %s is damaged (%v); restore it from a backup, such as an encrypted export", tildePath(dbPath), err)
		}
		return err
	}
	if err := requireVault(dbPath, "there's no vault yet: create it first, by running any sesh command or sesh init"); err != nil {
		return damagedFile(err)
	}
	// Touch ID is checked as found: unlocking removes a stale setup.
	mat, err := database.ReadUnlockMaterial(dbPath)
	if err != nil {
		return damagedFile(err)
	}
	touchLine := verifyTouchID(filepath.Dir(dbPath), database.UnlockID(mat.Verify))
	ks, err := buildKeySource(cfg)
	if err != nil {
		return damagedFile(err)
	}
	// Opened without pruning the audit log: a check writes nothing until
	// it knows the file is sound.
	store, err := openStoreWith(dbPath, ks)
	if err != nil {
		return damagedFile(err)
	}
	defer closeAuditStore(store)

	report, err := store.Verify()
	switch {
	case errors.Is(err, database.ErrVaultKeyChanged):
		return errors.New("the master password was changed by another sesh command while this one was checking; run sesh verify again")
	case database.IsDamaged(err):
		return damagedFile(err)
	case err != nil:
		return fmt.Errorf("%w; nothing was concluded, so run sesh verify again", err)
	}

	var b strings.Builder
	var next []string
	problems := 0
	fmt.Fprintf(&b, "Vault: %s\n", tildePath(dbPath))
	if len(report.Structure) == 0 {
		b.WriteString("  File: ok\n")
	} else {
		problems++
		b.WriteString("  File: damaged; SQLite reports:\n")
		for i, line := range report.Structure {
			if i == structureLinesShown {
				fmt.Fprintf(&b, "    … and %d more\n", len(report.Structure)-structureLinesShown)
				break
			}
			fmt.Fprintf(&b, "    %s\n", line)
		}
	}
	if len(report.Problems) == 0 {
		fmt.Fprintf(&b, "  Entries: %s, all readable\n", entryCount(report.Entries))
		if problems > 0 {
			next = append(next, "Your entries all read, so save them now, then start a new vault and import them:\n    sesh --service password --action export --format encrypted --file backup.enc")
		}
	} else {
		problems += len(report.Problems)
		fmt.Fprintf(&b, "  Entries: %d of %s can't be read:\n", len(report.Problems), entryCount(report.Entries))
		for _, p := range report.Problems {
			fmt.Fprintf(&b, "    %s: %v\n", p.Key, p.Err)
		}
		next = append(next, "Restore the entries that can't be read from a backup, such as an encrypted export, or delete them with --delete.")
	}
	line, ok := verifyRecovery(&report)
	fmt.Fprintf(&b, "  Recovery key: %s\n", line)
	if !ok {
		problems++
	}
	fmt.Fprintf(&b, "  Touch ID: %s\n", touchLine)

	result := "ok"
	if problems > 0 {
		result = countOf(int64(problems), "problem")
	}
	if len(report.Structure) == 0 {
		store.LogVerify(fmt.Sprintf("%s, %s", result, entryCount(report.Entries)))
	}
	if problems == 0 {
		b.WriteString("Vault OK.\n")
	} else {
		for _, n := range next {
			fmt.Fprintf(&b, "%s\n", n)
		}
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
// it's fine (none counts as fine).
func verifyRecovery(r *database.VerifyReport) (string, bool) {
	switch {
	case r.RecoveryErr != nil:
		return fmt.Sprintf("its record can't be read (%v); make a new one with: sesh recovery new", r.RecoveryErr), false
	case r.Recovery == nil:
		return "none", true
	case r.Recovery.UnlockID != r.KeyID:
		return "its record is for another vault or key, so it can't open this one; make a new one with: sesh recovery new", false
	}
	if err := recovery.CheckRecord(r.Recovery); err != nil {
		return fmt.Sprintf("its record is damaged (%v); make a new one with: sesh recovery new", err), false
	}
	return "set, complete, and made for this vault's key", true
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
