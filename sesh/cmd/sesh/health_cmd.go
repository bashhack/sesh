package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/health"
	"github.com/bashhack/sesh/internal/hibp"
	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/vault"
)

const healthUsage = `Usage: sesh health [--hibp <file or folder>] [--json]

Checks the vault's passwords and API keys: passwords easy to guess, a
secret used on more than one entry, secrets not changed in
health.old_after_days (365 by default), and, with a downloaded copy of
Have I Been Pwned's passwords, passwords seen in data breaches. Nothing is
sent anywhere. Reading the secrets is one event in the audit log.

  --hibp    the Pwned Passwords download (one file, or its folder of ranges);
            health.hibp_file in the config file sets it for every run
  --json    print the report as JSON`

// runHealth checks the vault's secrets and prints what it found.
func runHealth(app *App, args []string) error {
	if len(args) > 0 && isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, healthUsage)
		return err
	}
	fs := flag.NewFlagSet("health", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	breachFile := fs.String("hibp", "", "The Pwned Passwords download")
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
	path := cfg.HealthHIBPFile.Value
	if *breachFile != "" {
		// A flag's path may be relative, to where the command runs.
		if path, err = filepath.Abs(*breachFile); strings.HasPrefix(*breachFile, "~") {
			path, err = config.ResolvePath(*breachFile)
		}
		if err != nil {
			return fmt.Errorf("--hibp %q: %w", *breachFile, err)
		}
	}
	c := &health.Checker{Now: time.Now(), IsWeak: password.IsWeak, OldAfter: time.Duration(cfg.HealthOldAfterDays.Value) * 24 * time.Hour}
	// The download is opened first, so one that's wrong is said before
	// the vault is unlocked for nothing.
	if path != "" {
		p, err := hibp.Open(path)
		if err != nil {
			return err
		}
		defer p.Close() //nolint:errcheck // read only
		c.Breaches = p
	}
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		return err
	}
	defer store.Close() //nolint:errcheck // read only, but for the audit event
	report, err := checkHealth(store, c)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeHealthJSON(app.Stdout, &report, path != "", cfg.HealthOldAfterDays.Value)
	}
	return writeHealth(app.Stdout, &report, path != "", cfg.HealthOldAfterDays.Value)
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
func writeHealth(w io.Writer, r *health.Report, breaches bool, oldDays int) error {
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
	section("Breached", len(r.Breached), "seen in data breaches, as Have I Been Pwned counts them")
	for _, x := range r.Breached {
		fmt.Fprintf(&b, "  %-40s seen %s\n", x.Key, countOf(int64(x.Count), "time"))
	}
	if r.Problems() > 0 {
		b.WriteString("\nTo replace a password: sesh edit <id> --generate (or --secret to type one)\n")
	}
	switch {
	case !breaches:
		b.WriteString(`
Breaches weren't checked. To check them, download Have I Been Pwned's
passwords (about 100 GB) with their downloader, which needs the .NET 10 SDK:
  dotnet tool install --global haveibeenpwned-downloader
  haveibeenpwned-downloader pwnedpasswords --single
then: sesh health --hibp pwnedpasswords.txt   (or set health.hibp_file)
`)
	case oldDays == 0:
		b.WriteString("\nAge wasn't checked: health.old_after_days is 0.\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// healthJSON is the report as --json prints it.
type healthJSON struct {
	Weak            []string        `json:"weak"`
	Reused          [][]string      `json:"reused"`
	Old             []healthOldJSON `json:"old"`
	Breached        []healthBreach  `json:"breached"`
	Checked         int             `json:"checked"`
	OldAfterDays    int             `json:"old_after_days"`
	BreachesChecked bool            `json:"breaches_checked"`
}

type healthOldJSON struct {
	Changed time.Time `json:"changed"`
	ID      string    `json:"id"`
}

type healthBreach struct {
	ID    string `json:"id"`
	Count int    `json:"count"`
}

func writeHealthJSON(w io.Writer, r *health.Report, breaches bool, oldDays int) error {
	out := healthJSON{Checked: r.Checked, OldAfterDays: oldDays, BreachesChecked: breaches,
		Weak: []string{}, Reused: [][]string{}, Old: []healthOldJSON{}, Breached: []healthBreach{}}
	ids := func(keys []vault.Key) []string {
		s := make([]string, len(keys))
		for i, k := range keys {
			s[i] = k.String()
		}
		return s
	}
	out.Weak = append(out.Weak, ids(r.Weak)...)
	for _, g := range r.Reused {
		out.Reused = append(out.Reused, ids(g))
	}
	for _, a := range r.Old {
		out.Old = append(out.Old, healthOldJSON{ID: a.Key.String(), Changed: a.Changed.UTC()})
	}
	for _, x := range r.Breached {
		out.Breached = append(out.Breached, healthBreach{ID: x.Key.String(), Count: x.Count})
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(b))
	return err
}
