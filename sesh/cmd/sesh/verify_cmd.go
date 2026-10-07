package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/recovery"
	"github.com/bashhack/sesh/internal/shell"
	"github.com/bashhack/sesh/internal/touchid"
)

// structureLinesShown is how many of SQLite's findings verify prints.
const structureLinesShown = 10

// runVerify is `sesh verify`: it unlocks the vault and checks that it can
// all be read. SQLite checks the file; every entry's secret is decrypted
// and its settings and times read; the recovery key's record must be shaped
// to open the vault, and Touch ID unlock must be this vault's. Nothing is
// written while it checks; one audit event records the result, if the file
// is sound. A problem with the file, an entry, or the recovery key fails the
// check; one with Touch ID is a warning. The report ends with what to do
// about each.
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
	touchFile, touchErr := touchid.ReadFile(filepath.Dir(dbPath))
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

	var c verifyChecks
	if len(report.Structure) == 0 {
		c.row(markOK, "File", "ok")
	} else {
		lines := report.Structure
		if len(lines) > structureLinesShown {
			lines = append(lines[:structureLinesShown:structureLinesShown], fmt.Sprintf("… and %d more", len(report.Structure)-structureLinesShown))
		}
		c.row(markFail, "File", "damaged; SQLite reports:", lines...)
		if len(report.Problems) == 0 {
			c.todo("Your entries all read, so save them now, then start a new vault and import them:", "sesh --service password --action export --format encrypted --file backup.enc")
		} else {
			c.todo("Restore the vault from a backup, such as an encrypted export.")
		}
	}
	if len(report.Problems) == 0 {
		c.row(markOK, "Entries", entryCount(report.Entries)+", all readable")
	} else {
		var details, ids []string
		for _, p := range report.Problems {
			details = append(details, fmt.Sprintf("%s: %s", p.Key, problemText(p.Kind)))
			ids = append(ids, shell.Quote(p.Key.String()))
		}
		// Why a secret doesn't decrypt goes under the last one that doesn't.
		for i, p := range slices.Backward(report.Problems) {
			if p.Kind == database.ProblemSecret {
				details = slices.Insert(details, i+1, "(damaged, or encrypted with another key)")
				break
			}
		}
		c.fails += len(report.Problems) - 1
		c.row(markFail, "Entries", fmt.Sprintf("%d of %s can't be read", len(report.Problems), entryCount(report.Entries)), details...)
		if len(report.Structure) == 0 {
			what := "Restore these entries from a backup (an encrypted export), or delete them:"
			if len(ids) == 1 {
				what = fmt.Sprintf("Restore %s from a backup (an encrypted export), or delete it:", report.Problems[0].Key)
			}
			c.todo(what, "sesh --service password --delete "+strings.Join(ids, " "))
		}
	}
	verifyRecovery(&c, &report)
	verifyTouchID(&c, touchFile, touchErr, database.UnlockID(mat.Verify))

	if len(report.Structure) == 0 {
		result := "ok"
		if c.fails > 0 {
			result = countOf(int64(c.fails), "problem")
		}
		store.LogVerify(fmt.Sprintf("%s, %s", result, entryCount(report.Entries)))
	}
	if _, err := fmt.Fprint(app.Stdout, c.render(tildePath(dbPath))); err != nil {
		return err
	}
	if c.fails > 0 {
		return errReported
	}
	return nil
}

// The marks at the start of each row of the report.
const (
	markOK   = "ok"
	markFail = "FAIL"
	markWarn = "warn"
	markNone = "-"
)

// verifyChecks collects the report's rows, what to do, and the tally.
type verifyChecks struct {
	rows         strings.Builder
	todos        [][]string
	fails, warns int
}

// row adds a check's result, with any details under it.
func (c *verifyChecks) row(mark, label, value string, details ...string) {
	switch mark {
	case markFail:
		c.fails++
	case markWarn:
		c.warns++
	}
	fmt.Fprintf(&c.rows, "  %-6s%-14s%s\n", mark, label, value)
	for _, d := range details {
		fmt.Fprintf(&c.rows, "%24s%s\n", "", d)
	}
}

// todo adds a step to what to do: what to do, then any commands to run.
func (c *verifyChecks) todo(text string, commands ...string) {
	c.todos = append(c.todos, append([]string{text}, commands...))
}

func (c *verifyChecks) render(vault string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "sesh verify: %s\n\n%s", vault, c.rows.String())
	if len(c.todos) > 0 {
		b.WriteString("\nWhat to do\n")
		for i, t := range c.todos {
			fmt.Fprintf(&b, "  %d. %s\n", i+1, t[0])
			for _, cmd := range t[1:] {
				fmt.Fprintf(&b, "       %s\n", cmd)
			}
		}
	}
	b.WriteString("\n")
	var tally []string
	if c.fails > 0 {
		tally = append(tally, countOf(int64(c.fails), "problem"))
	}
	if c.warns > 0 {
		tally = append(tally, countOf(int64(c.warns), "warning"))
	}
	switch {
	case c.fails > 0:
		fmt.Fprintf(&b, "FAIL: %s\n", strings.Join(tally, ", "))
	case c.warns > 0:
		fmt.Fprintf(&b, "OK, with %s\n", tally[0])
	default:
		b.WriteString("OK: no problems\n")
	}
	return b.String()
}

// problemText says in plain words what's wrong with an entry.
func problemText(k database.ProblemKind) string {
	switch k {
	case database.ProblemSettings:
		return "settings don't read"
	case database.ProblemTimes:
		return "times don't read"
	}
	return "secret doesn't decrypt"
}

// verifyRecovery checks the vault's recovery key record. None is fine.
func verifyRecovery(c *verifyChecks, r *database.VerifyReport) {
	switch {
	case r.RecoveryErr != nil:
		c.row(markFail, "Recovery key", "its record can't be read", r.RecoveryErr.Error())
	case r.Recovery == nil:
		c.row(markNone, "Recovery key", "none")
		return
	case r.Recovery.UnlockID != r.KeyID:
		c.row(markFail, "Recovery key", "made for another vault or key")
	default:
		if err := recovery.CheckRecord(r.Recovery); err != nil {
			c.row(markFail, "Recovery key", "its record is damaged", err.Error())
		} else {
			c.row(markOK, "Recovery key", "set, for this vault's key")
			return
		}
	}
	c.todo("Make a new recovery key:", "sesh recovery new")
}

// verifyTouchID checks Touch ID unlock for the vault whose key record id is
// id, from its file as read before unlocking (f, err). A stale setup only
// costs typing the password, so it's a warning, never a failure.
func verifyTouchID(c *verifyChecks, f *touchid.File, err error, id string) {
	switch {
	case errors.Is(err, os.ErrNotExist):
		c.row(markNone, "Touch ID", "off")
		return
	case err != nil:
		c.row(markWarn, "Touch ID", "its file can't be read", err.Error())
	case f.UnlockID != id:
		c.row(markWarn, "Touch ID", "set up for another vault or an earlier master password")
	case fingerprintsChanged(f):
		c.row(markWarn, "Touch ID", "your fingerprints changed since it was set up")
	default:
		c.row(markOK, "Touch ID", "on, for this vault")
		return
	}
	c.todo("Optional: turn Touch ID back on:", "sesh touchid enable")
}
