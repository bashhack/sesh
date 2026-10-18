package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/health"
	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/vault"
)

const healthUsage = `Usage: sesh health [--json]

Checks the vault's passwords and API keys: passwords easy to guess, a
secret used on more than one entry, and secrets not changed in
health.old_after_days (365 by default). Reading the secrets is one event
in the audit log.

  --json    print the report as JSON`

// runHealth checks the vault's secrets and prints what it found.
func runHealth(app *App, args []string) error {
	if len(args) > 0 && isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, healthUsage)
		return err
	}
	fs := flag.NewFlagSet("health", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	asJSON := fs.Bool("json", false, "Print the report as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("sesh health takes no arguments, got %q", strings.Join(fs.Args(), " "))
	}
	cfg, err := settings()
	if err != nil {
		return err
	}
	if err := requireVault(cfg.DBPath.Value, "there's no vault yet: sesh add creates it with your first entry (sesh init first chooses where it lives)"); err != nil {
		return err
	}
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	c := &health.Checker{Now: time.Now(), IsWeak: password.IsWeak, OldAfter: time.Duration(cfg.HealthOldAfterDays.Value) * 24 * time.Hour}
	report, err := checkHealth(store, c)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeHealthJSON(app.Stdout, &report, cfg.HealthOldAfterDays.Value)
	}
	return writeHealth(app.Stdout, &report, cfg.HealthOldAfterDays.Value)
}

// checkHealth reads every secret in store into c, and says what it found.
func checkHealth(store *database.Store, c *health.Checker) (health.Report, error) {
	if _, err := store.EachSecret("Health check", health.Kinds, c.Add); err != nil {
		if errors.Is(err, database.ErrVaultKeyChanged) {
			return health.Report{}, errors.New("the master password was changed by another sesh command while this one was checking; run sesh health again")
		}
		return health.Report{}, err
	}
	return c.Report(), nil
}

// writeHealth prints the report as text: each kind of problem, the
// entries with it, and how to fix them.
func writeHealth(w io.Writer, r *health.Report, oldDays int) error {
	var b strings.Builder
	checked := countOf(int64(r.Checked), "password or API key")
	if r.Checked != 1 {
		checked = thousands(int64(r.Checked)) + " passwords and API keys"
	}
	if r.Problems() == 0 {
		fmt.Fprintf(&b, "No problems found in %s.\n", checked)
	} else {
		fmt.Fprintf(&b, "Checked %s.\n", checked)
	}
	section := func(title string, n int, why string) {
		if n > 0 {
			fmt.Fprintf(&b, "\n%s (%d): %s\n", title, n, why)
		}
	}
	section("Weak passwords", len(r.Weak), "easy to guess")
	for _, k := range r.Weak {
		fmt.Fprintf(&b, "  %s\n", k)
	}
	reused := 0
	for _, g := range r.Reused {
		reused += len(g)
	}
	section("Reused", reused, "the same secret on more than one entry")
	for _, g := range r.Reused {
		ids := make([]string, len(g))
		for i, k := range g {
			ids[i] = k.String()
		}
		fmt.Fprintf(&b, "  %s\n", strings.Join(ids, ", "))
	}
	section("Old", len(r.Old), "not changed in "+dayCount(int64(oldDays))+" or more")
	for _, a := range r.Old {
		fmt.Fprintf(&b, "  %-40s changed %s\n", a.Key, a.Changed.Local().Format("2006-01-02"))
	}
	section("Couldn't check", len(r.Unreadable), "the secret doesn't decrypt; sesh doctor says more")
	for _, k := range r.Unreadable {
		fmt.Fprintf(&b, "  %s\n", k)
	}
	if len(r.Weak)+reused+len(r.Old) > 0 {
		b.WriteString("\nTo replace a password: sesh edit <id> --generate (or --secret to type one)\n")
	}
	if oldDays == 0 {
		b.WriteString("\nAge wasn't checked: health.old_after_days is 0.\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// healthJSON is the report as --json prints it.
type healthJSON struct {
	Weak         []string        `json:"weak"`
	Reused       [][]string      `json:"reused"`
	Old          []healthOldJSON `json:"old"`
	Unreadable   []string        `json:"unreadable"`
	Checked      int             `json:"checked"`
	OldAfterDays int             `json:"old_after_days"`
}

type healthOldJSON struct {
	Changed time.Time `json:"changed"`
	ID      string    `json:"id"`
}

func writeHealthJSON(w io.Writer, r *health.Report, oldDays int) error {
	ids := func(keys []vault.Key) []string {
		s := make([]string, len(keys))
		for i, k := range keys {
			s[i] = k.String()
		}
		return s
	}
	out := healthJSON{Checked: r.Checked, OldAfterDays: oldDays, Weak: ids(r.Weak), Unreadable: ids(r.Unreadable),
		Reused: [][]string{}, Old: []healthOldJSON{}}
	for _, g := range r.Reused {
		out.Reused = append(out.Reused, ids(g))
	}
	for _, a := range r.Old {
		out.Old = append(out.Old, healthOldJSON{ID: a.Key.String(), Changed: a.Changed.UTC()})
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(b))
	return err
}
