package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/vault"
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
	fmt.Fprintf(&b, "Audit log: %s since %s. ", countOf(count, "event"), oldest.Local().Format("2006-01-02 15:04"))
	if days := cfg.AuditRetentionDays.Value; days > 0 {
		fmt.Fprintf(&b, "Events older than %s are removed automatically (audit.retention_days).\n\n", dayCount(int64(days)))
	} else {
		b.WriteString("Nothing is removed automatically (audit.retention_days = 0); remove old events with: sesh audit prune --older-than <days>\n\n")
	}
	events, err := store.AuditEvents(*limit)
	if err != nil {
		return err
	}
	for _, e := range events {
		when := e.CreatedAt.Local().Format("2006-01-02 15:04:05")
		if e.EntryID == "" {
			// An event about the vault, such as a password change.
			fmt.Fprintf(&b, "%s  %-6s  %s\n", when, e.EventType, e.Detail)
			continue
		}
		kind, name := auditEntryName(e.EntryID)
		// An edit says what changed: "renamed from password/github/alice".
		if change, ok := strings.CutPrefix(e.Detail, "Edit: "); ok {
			name += " (" + change + ")"
		}
		fmt.Fprintf(&b, "%s  %-6s  %-11s  %s\n", when, e.EventType, kind, name)
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
		_, err = fmt.Fprintf(app.Stdout, "No events older than %s.\n", dayCount(int64(*olderThan)))
		return err
	}
	removed := fmt.Sprintf("Removed %s older than %s", countOf(n, "event"), dayCount(int64(*olderThan)))
	if *olderThan == 0 {
		removed = fmt.Sprintf("Removed all %s", countOf(n, "event"))
	}
	// SQLite keeps the space deleted rows leave for reuse; compacting is
	// what makes the file smaller.
	before, err := store.Size()
	if err == nil {
		err = store.Compact()
	}
	if errors.Is(err, database.ErrVaultBusy) {
		_, err = fmt.Fprintf(app.Stdout, "%s. The vault wasn't compacted, because another sesh command was using it; new events will reuse the freed space.\n", removed)
		return err
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

// openAuditStore opens the vault for sesh audit.
func openAuditStore() (*config.Config, *database.Store, error) {
	cfg, err := settings()
	if err != nil {
		return nil, nil, err
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

// auditEntryName turns an audit entry ID, an entry's key in text form,
// into the kind of entry and a readable name, as --list names them:
// ("password", "github (alice)"), ("totp", "github (work)"). An ID it
// doesn't recognise comes back whole, with no kind.
func auditEntryName(id string) (kind, name string) {
	k, err := vault.ParseKey(id)
	if err != nil {
		return "", id
	}
	if k.Username != "" {
		return string(k.Kind), k.Service + " (" + k.Username + ")"
	}
	return string(k.Kind), k.Service
}

// The size warning: it shows when the audit log passes auditWarnEvents
// (about 10 MB), whatever the retention setting, at most once per
// auditWarnEvery, and only to a person at a terminal. Tests replace the
// variables.
const auditWarnEvery = 24 * time.Hour

var (
	auditWarnEvents  int64 = 100_000
	stderrIsTerminal       = func() bool { return term.IsTerminal(int(os.Stderr.Fd())) }
	// auditWarnedPath is a marker file whose time records the last warning.
	auditWarnedPath = defaultAuditWarnedPath
)

// defaultAuditWarnedPath keeps the marker next to the vault, named after
// it, so it can never be the vault itself: the warning is about that
// vault, and its directory exists whenever the warning runs.
func defaultAuditWarnedPath(dbPath string) string {
	return dbPath + ".audit-warned"
}

// warnAuditSize tells a person at the terminal, at most once a day, that
// the audit log has grown past auditWarnEvents, and how to shrink it.
// Nothing here stops the command.
func warnAuditSize(store *database.Store, cfg *config.Config) {
	if !stderrIsTerminal() {
		return
	}
	n, err := store.AuditCountEstimate()
	if err != nil || n < auditWarnEvents {
		return
	}
	marker := auditWarnedPath(store.Path())
	// A marker dated in the future, from a clock that was ahead, doesn't count.
	if fi, err := os.Stat(marker); err == nil {
		if age := time.Since(fi.ModTime()); age >= 0 && age < auditWarnEvery {
			return
		}
	}
	size, err := store.Size()
	if err != nil {
		return
	}
	advice := fmt.Sprintf("Keep fewer days with audit.retention_days (now %s)", dayCount(int64(cfg.AuditRetentionDays.Value)))
	if cfg.AuditRetentionDays.Value == 0 {
		advice = "Set audit.retention_days (now 0, which keeps everything)"
	}
	note("warning: the vault's audit log has about %s events, and the vault is %s. sesh writes to the vault on every command, so backups copy all of it each time.\n%s, or remove old events now with: sesh audit prune --older-than <days>\nThis warning shows at most once a day.",
		thousands(n), vaultSize(size), advice)
	touchMarker(marker)
}

// touchMarker sets marker's time to now, creating it empty if it doesn't
// exist. It never writes into an existing file, so whatever sits at that
// path can't be truncated. Best effort: if it fails, the warning just
// shows again next time.
func touchMarker(marker string) {
	if f, err := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); err == nil { //nolint:gosec // next to the user's own vault
		if err := f.Close(); err != nil {
			return
		}
	}
	now := time.Now()
	_ = os.Chtimes(marker, now, now) //nolint:errcheck // best effort, see above
}

// thousands prints n with comma separators: 1,000,009.
func thousands(n int64) string {
	s := fmt.Sprint(n)
	sign := ""
	if n < 0 {
		sign, s = "-", s[1:]
	}
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return sign + s
}

// flagSet reports whether name was given on the command line.
func flagSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) { found = found || f.Name == name })
	return found
}

// countOf is plural with thousands separators: "1,204 events".
func countOf(n int64, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return thousands(n) + " " + noun + "s"
}

// dayCount is "1 day", "90 days".
func dayCount(n int64) string {
	if n == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", n)
}
