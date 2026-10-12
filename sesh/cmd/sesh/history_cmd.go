package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/shell"
	"github.com/bashhack/sesh/internal/vault"
)

const historyUsage = `Usage:
  sesh history <id>                 List an entry's versions: 1 is its secret now
  sesh history <id> --show N        Print version N's secret
  sesh history <id> --clip N        Copy version N's secret to the clipboard
  sesh history <id> --restore N     Make version N the secret again (the one it replaces is kept)
  sesh history <id> --forget N      Delete version N for good

Each time an entry's secret changes, the one it replaces is kept, the
newest history.keep (10 unless set). Entry IDs are what --list shows.`

// runHistory is sesh history: an entry's earlier secrets.
func runHistory(app *App, args []string) error {
	if len(args) == 0 || isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, historyUsage)
		return err
	}
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	show := fs.Int("show", 0, "Print version N's secret")
	clip := fs.Int("clip", 0, "Copy version N's secret to the clipboard")
	restore := fs.Int("restore", 0, "Make version N the secret again")
	forget := fs.Int("forget", 0, "Delete version N for good")
	ids, err := parseAnywhere(fs, args)
	if err != nil {
		return err
	}
	if len(ids) != 1 {
		return errors.New("name one entry: sesh history <id> [--show|--clip|--restore|--forget N]")
	}
	k, err := vault.ParseKey(ids[0])
	if err != nil {
		return err
	}
	var action string
	n := 0
	for name, v := range map[string]int{"show": *show, "clip": *clip, "restore": *restore, "forget": *forget} {
		if v == 0 {
			continue
		}
		if action != "" {
			return errors.New("use one of --show, --clip, --restore and --forget at a time")
		}
		action, n = name, v
	}
	if action != "" && n < 1 {
		return fmt.Errorf("--%s takes a version number, 1 or more, as sesh history lists them", action)
	}
	if (action == "restore" || action == "forget") && n == 1 {
		return fmt.Errorf("version 1 is the secret now; --%s takes an earlier one, 2 or more", action)
	}

	_, store, err := openTrashStore()
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	switch action {
	case "":
		return listHistory(app, store, k)
	case "restore":
		if err := store.RestoreVersion(k, n); err != nil {
			return err
		}
		_, err := fmt.Fprintf(app.Stdout, "✅ %s's secret is version %d's again; the one it replaced is now version 2.\n", k, n)
		return err
	case "forget":
		if err := store.ForgetVersion(k, n); err != nil {
			return err
		}
		_, err := fmt.Fprintf(app.Stdout, "✅ Deleted %s's version %d for good.\n", k, n)
		return err
	}
	var secret []byte
	if n == 1 {
		secret, err = store.GetFor(k, "history --"+action+" 1")
	} else {
		secret, err = store.ReadVersion(k, n, "with --"+action)
	}
	if err != nil {
		return err
	}
	defer secure.SecureZeroBytes(secret)
	if action == "show" {
		_, err := fmt.Fprintf(app.Stdout, "%s\n", secret)
		return err
	}
	if app.ClipboardCopy == nil {
		return errors.New("there's no clipboard to copy to here; use --show")
	}
	if err := app.ClipboardCopy(string(secret)); err != nil {
		return err
	}
	_, err = fmt.Fprintf(app.Stdout, "✅ Copied %s's version %d to the clipboard.\n", k, n)
	return err
}

// listHistory prints k's versions: 1, its secret now, and the earlier
// ones, the newest first, with when each was replaced. Never a secret.
func listHistory(app *App, store *database.Store, k vault.Key) error {
	e, err := store.Lookup(k)
	if err != nil {
		return err
	}
	versions, err := store.History(k)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(app.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "VERSION\tSECRET")                                                 //nolint:errcheck // flushed below
	fmt.Fprintf(w, "1\tnow, set %s\n", e.UpdatedAt.Local().Format("2006-01-02 15:04")) //nolint:errcheck // flushed below
	for i, v := range versions {
		when := "?"
		if !v.ReplacedAt.IsZero() {
			when = v.ReplacedAt.Local().Format("2006-01-02 15:04")
		}
		fmt.Fprintf(w, "%d\treplaced %s\n", i+2, when) //nolint:errcheck // flushed below
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if len(versions) == 0 {
		msg := "\nNo earlier secrets yet: each time this one changes, the one it replaces is kept here.\n"
		if store.HistoryKeep() == 0 {
			msg = "\nNo earlier secrets are kept (history.keep is 0).\n"
		}
		_, err := io.WriteString(app.Stdout, msg)
		return err
	}
	_, err = fmt.Fprintf(app.Stdout, "\nSee one with: sesh history %s --show <version>\n", shell.Quote(k.String()))
	return err
}
