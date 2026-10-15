package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/shell"
	"github.com/bashhack/sesh/internal/vault"
)

const historyUsage = `Usage:
  sesh history <entry>                 List an entry's versions: 1 is its secret now
  sesh history <entry> --show N        Print version N's secret
  sesh history <entry> --clip N        Copy version N's secret to the clipboard
  sesh history <entry> --restore N     Make version N the secret again (the one it replaces is kept)
  sesh history <entry> --forget N,...  Delete versions for good (several at once keep their numbers)

Each time an entry's secret changes, the one it replaces is kept, the
newest history.keep (10 unless set).

` + entryWordsHelp

// runHistory is sesh history: an entry's earlier secrets.
func runHistory(app *App, args []string) error {
	if len(args) == 0 || isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, historyUsage)
		return err
	}
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	fs.String("show", "", "Print version N's secret")
	fs.String("clip", "", "Copy version N's secret to the clipboard")
	fs.String("restore", "", "Make version N the secret again")
	fs.String("forget", "", "Delete versions for good: N, or N,M,...")
	ids, err := parseAnywhere(fs, args)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return errors.New("name the entry: sesh history <entry> [--show|--clip|--restore|--forget N]")
	}
	var action, value string
	var twice bool
	fs.Visit(func(f *flag.Flag) {
		twice = twice || action != ""
		action, value = f.Name, f.Value.String()
	})
	if twice {
		return errors.New("use one of --show, --clip, --restore and --forget at a time")
	}
	var ns []int
	if action != "" {
		for part := range strings.SplitSeq(value, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil || n < 1 {
				return fmt.Errorf("--%s takes a version number, 1 or more, as sesh history lists them, not %q", action, part)
			}
			if (action == "restore" || action == "forget") && n == 1 {
				return fmt.Errorf("version 1 is the secret now; --%s takes an earlier one, 2 or more", action)
			}
			ns = append(ns, n)
		}
		if len(ns) > 1 && action != "forget" {
			return fmt.Errorf("--%s takes one version", action)
		}
	}

	cfg, err := settings()
	if err != nil {
		return err
	}
	if err := requireVault(cfg.DBPath.Value, "there's no vault yet: create it first, by running any sesh command or sesh init"); err != nil {
		return err
	}
	_, store, err := openAuditStore()
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	k, err := resolveEntry(app, store, ids, "")
	if err != nil {
		return err
	}
	switch action {
	case "":
		return listHistory(app, store, k)
	case "restore":
		kept, err := store.RestoreVersion(k, ns[0])
		if err != nil {
			return err
		}
		msg := fmt.Sprintf("✅ %s's secret is version %d's again; the one it replaced is now version 2.\n", k, ns[0])
		if !kept {
			msg = fmt.Sprintf("✅ %s's secret is version %d's again.\n", k, ns[0])
		}
		_, err = io.WriteString(app.Stdout, msg)
		return err
	case "forget":
		if err := store.ForgetVersions(k, ns...); err != nil {
			return err
		}
		slices.Sort(ns)
		ns = slices.Compact(ns)
		what := fmt.Sprintf("version %d", ns[0])
		if len(ns) > 1 {
			parts := make([]string, len(ns))
			for i, n := range ns {
				parts[i] = strconv.Itoa(n)
			}
			what = "versions " + strings.Join(parts, ", ")
		}
		_, err := fmt.Fprintf(app.Stdout, "✅ Deleted %s's %s for good.\n", k, what)
		return err
	}
	n := ns[0]
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
	versions, err := store.History(k)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(app.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "VERSION\tSECRET") //nolint:errcheck // flushed below
	fmt.Fprintln(w, "1\tnow")          //nolint:errcheck // flushed below
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

// pruneHistory drops earlier secrets past history.keep, which may have
// been lowered since they were kept. 0 keeps no new ones but drops none:
// what's kept stays until forgotten. A failure is reported but never stops
// the command.
func pruneHistory(store *database.Store, cfg *config.Config) {
	if cfg.HistoryKeep.Value == 0 {
		return
	}
	if _, err := store.PruneHistory(cfg.HistoryKeep.Value); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err) //nolint:errcheck // best-effort warning
	}
}
