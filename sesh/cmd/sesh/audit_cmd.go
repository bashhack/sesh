package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/constants"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/keyformat"
)

// auditCommands are the commands of `sesh audit`.
var auditCommands = []candidate{
	{"prune", "Remove events older than a number of days"},
}

// addAuditFlags registers the flags of `sesh audit` and returns its --limit.
func addAuditFlags(fs *flag.FlagSet) *int {
	return fs.Int("limit", 50, "Show at most this many of the newest events; 0 shows them all")
}

// addAuditPruneFlags registers the flags of `sesh audit prune` and returns
// its --older-than.
func addAuditPruneFlags(fs *flag.FlagSet) *int {
	return fs.Int("older-than", -1, "Remove events older than this many days; 0 removes them all")
}

// runAudit is `sesh audit [--limit N]`, which shows the vault's audit log,
// and `sesh audit prune --older-than DAYS`. Both open the vault, so they
// ask for the master password the way --list does.
func runAudit(app *App, args []string) error {
	if len(args) > 0 && args[0] == "prune" {
		return runAuditPrune(app, args[1:])
	}
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	limit := addAuditFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("sesh audit takes no arguments, got %q (to remove old events: sesh audit prune --older-than <days>)", strings.Join(fs.Args(), " "))
	}
	if *limit < 0 {
		return fmt.Errorf("--limit wants 0 (all events) or more, got %d", *limit)
	}
	cfg, store, err := openAuditStore()
	if err != nil {
		return err
	}
	defer closeAuditStore(store)

	count, oldest, err := store.AuditSummary()
	if err != nil {
		return err
	}
	var b strings.Builder
	if count == 0 {
		b.WriteString("Audit log: no events.\n")
		_, err := fmt.Fprint(app.Stdout, b.String())
		return err
	}
	fmt.Fprintf(&b, "Audit log: %s since %s. ", plural(count, "event"), oldest.Local().Format("2006-01-02 15:04"))
	if days := cfg.AuditRetentionDays.Value; days > 0 {
		fmt.Fprintf(&b, "Events older than %s are removed automatically (audit.retention_days).\n\n", plural(int64(days), "day"))
	} else {
		b.WriteString("Nothing is removed automatically (audit.retention_days = 0); remove old events with: sesh audit prune --older-than <days>\n\n")
	}
	events, err := store.AuditEvents(*limit)
	if err != nil {
		return err
	}
	for _, e := range events {
		kind, name := auditEntryName(e.EntryID)
		fmt.Fprintf(&b, "%s  %-6s  %-11s  %s\n", e.CreatedAt.Local().Format("2006-01-02 15:04:05"), e.EventType, kind, name)
	}
	if *limit > 0 && count > int64(*limit) {
		fmt.Fprintf(&b, "\nShowing the newest %d of %d; --limit 0 shows them all.\n", *limit, count)
	}
	_, err = fmt.Fprint(app.Stdout, b.String())
	return err
}

func runAuditPrune(app *App, args []string) error {
	fs := flag.NewFlagSet("audit prune", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	olderThan := addAuditPruneFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("sesh audit prune takes no arguments, got %q", strings.Join(fs.Args(), " "))
	}
	if !flagSet(fs, "older-than") {
		return fmt.Errorf("sesh audit prune needs --older-than <days> (0 removes every event)")
	}
	if *olderThan < 0 || *olderThan > config.MaxAuditRetentionDays {
		return fmt.Errorf("--older-than wants a whole number of days from 0 (everything) to %d, got %d", config.MaxAuditRetentionDays, *olderThan)
	}
	_, store, err := openAuditStore()
	if err != nil {
		return err
	}
	defer closeAuditStore(store)

	// 0 means every event, including any stamped by a clock that was ahead.
	var n int64
	if *olderThan == 0 {
		n, err = store.ClearAudit()
	} else {
		n, err = store.PruneAudit(time.Now().AddDate(0, 0, -*olderThan))
	}
	if err != nil {
		return err
	}
	if n == 0 {
		_, err = fmt.Fprintf(app.Stdout, "No events older than %s.\n", plural(int64(*olderThan), "day"))
		return err
	}
	removed := fmt.Sprintf("Removed %s older than %s", plural(n, "event"), plural(int64(*olderThan), "day"))
	if *olderThan == 0 {
		removed = fmt.Sprintf("Removed all %s", plural(n, "event"))
	}
	// SQLite keeps the space deleted rows leave for reuse; compacting is
	// what makes the file smaller.
	before, err := store.Size()
	if err == nil {
		err = store.Compact()
	}
	if err != nil {
		return fmt.Errorf("%s, but compacting the vault failed: %w", removed, err)
	}
	after, err := store.Size()
	if err != nil {
		return fmt.Errorf("%s and compacted the vault, but couldn't read its size: %w", removed, err)
	}
	_, err = fmt.Fprintf(app.Stdout, "%s, and compacted the vault from %s to %s.\n", removed, vaultSize(before), vaultSize(after))
	return err
}

// vaultSize prints a file size in KB below a megabyte, else in MB.
func vaultSize(n int64) string {
	if n < 1_000_000 {
		return fmt.Sprintf("%d KB", (n+999)/1000)
	}
	return fmt.Sprintf("%.1f MB", float64(n)/1e6)
}

// openAuditStore opens the vault for sesh audit, which needs the sqlite
// backend.
func openAuditStore() (*config.Config, *database.Store, error) {
	cfg, err := settings()
	if err != nil {
		return nil, nil, err
	}
	if cfg.Backend.Value != config.BackendSQLite {
		return nil, nil, errNeedsSQLite("sesh audit")
	}
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		return nil, nil, err
	}
	return cfg, store, nil
}

func closeAuditStore(store *database.Store) {
	if err := store.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to close the vault: %v\n", err) //nolint:errcheck // best-effort warning
	}
}

// pruneAuditLog removes audit events older than the retention setting, if
// one is set. A failure is reported but never stops the command.
func pruneAuditLog(store *database.Store, cfg *config.Config) {
	days := cfg.AuditRetentionDays.Value
	if days == 0 {
		return
	}
	if _, err := store.PruneAudit(time.Now().AddDate(0, 0, -days)); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err) //nolint:errcheck // best-effort warning
	}
}

// auditEntryName turns an audit entry ID, an entry's storage key plus "/"
// and its account, into the kind of entry and a readable name, as --list
// names them: ("password", "github (alice)"), ("totp", "github (work)"),
// ("aws", "default"). A key it doesn't recognise comes back whole, with no
// kind.
func auditEntryName(id string) (kind, name string) {
	key, _, ok := strings.CutLast(id, "/") // drop the account
	if !ok {
		return "", id
	}
	withDetail := func(main string, rest []string) string {
		if len(rest) == 1 {
			return main + " (" + rest[0] + ")"
		}
		return main
	}
	if s, err := keyformat.Parse(key, constants.PasswordServicePrefix); err == nil && (len(s) == 2 || len(s) == 3) {
		return s[0], withDetail(s[1], s[2:])
	}
	if s, err := keyformat.Parse(key, constants.TOTPServicePrefix); err == nil && (len(s) == 1 || len(s) == 2) {
		return "totp", withDetail(s[0], s[1:])
	}
	if s, err := keyformat.Parse(key, constants.AWSServicePrefix); err == nil && len(s) == 1 {
		return "aws", s[0]
	}
	if s, err := keyformat.Parse(key, constants.AWSServiceMFAPrefix); err == nil && len(s) == 1 {
		return "aws serial", s[0]
	}
	return "", id
}

// flagSet reports whether name was given on the command line.
func flagSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) { found = found || f.Name == name })
	return found
}

// plural is "1 event", "2 events".
func plural(n int64, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
