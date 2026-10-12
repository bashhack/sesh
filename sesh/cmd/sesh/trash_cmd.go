package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/vault"
)

// trashCommands are what follows sesh trash.
var trashCommands = []candidate{
	{"list", "Show the deleted entries, the newest first"},
	{"restore", "Put a deleted entry back"},
	{"remove", "Delete entries in the trash for good"},
	{"empty", "Delete everything in the trash for good"},
}

const trashUsage = `Usage:
  sesh trash [list]                         Show the deleted entries, the newest first
  sesh trash restore <trash id> [--as <id>] Put one back, under its own name or another
  sesh trash remove <trash id>… [--force]   Delete them for good
  sesh trash empty [--force]                Delete everything in the trash for good

Deleted entries stay in the trash for trash.keep_days (30 unless set), then
go for good. To delete an entry for good straight away, delete it with --purge.`

// runTrash is sesh trash: list, restore, remove, empty.
func runTrash(app *App, args []string) error {
	if len(args) > 0 && isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, trashUsage)
		return err
	}
	verb := "list"
	if len(args) > 0 {
		verb, args = args[0], args[1:]
	}
	switch verb {
	case "list":
		if len(args) > 0 {
			return fmt.Errorf("sesh trash list takes nothing more, not %q", args[0])
		}
		return listTrash(app)
	case "restore":
		return restoreFromTrash(app, args)
	case "remove":
		return removeFromTrash(app, args)
	case "empty":
		return emptyTrash(app, args)
	}
	return fmt.Errorf("sesh trash has no %q: list, restore, remove or empty", verb)
}

// openTrashStore opens the vault for a trash command, with its settings.
func openTrashStore() (*config.Config, *database.Store, error) {
	cfg, err := settings()
	if err != nil {
		return nil, nil, err
	}
	if err := requireVault(cfg.DBPath.Value, "there's no vault yet, so nothing in the trash"); err != nil {
		return nil, nil, err
	}
	return openAuditStore()
}

// listTrash prints the trash: each entry's trash id, name, folder, when it
// was deleted, and when it will go for good.
func listTrash(app *App) error {
	cfg, store, err := openTrashStore()
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	trashed, err := store.Trash()
	if err != nil {
		return err
	}
	days := cfg.TrashKeepDays.Value
	if len(trashed) == 0 {
		msg := "The trash is empty."
		if days == 0 {
			msg += " Deleting is for good (trash.keep_days is 0)."
		}
		_, err := fmt.Fprintln(app.Stdout, msg)
		return err
	}
	w := tabwriter.NewWriter(app.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tENTRY\tFOLDER\tDELETED\tGOES FOR GOOD") //nolint:errcheck // flushed below
	for i := range trashed {
		t := &trashed[i]
		deleted, goes := "?", "unknown" // when it was deleted doesn't read
		if !t.DeletedAt.IsZero() {
			deleted, goes = t.DeletedAt.Local().Format("2006-01-02 15:04"), "when emptied"
			if days > 0 {
				goes = t.DeletedAt.AddDate(0, 0, days).Local().Format("2006-01-02")
			}
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", t.ID, t.Key, t.Folder, deleted, goes) //nolint:errcheck // flushed below
	}
	if err := w.Flush(); err != nil {
		return err
	}
	_, err = fmt.Fprintf(app.Stdout, "\nPut one back with: sesh trash restore <id>\n")
	return err
}

// trashIDs reads trash ids.
func trashIDs(args []string) ([]int64, error) {
	var ids []int64
	for _, a := range args {
		id, err := strconv.ParseInt(a, 10, 64)
		if err != nil || id < 1 {
			return nil, fmt.Errorf("%q isn't a trash id: sesh trash lists them", a)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// restoreFromTrash is sesh trash restore <id> [--as <entry id>].
func restoreFromTrash(app *App, args []string) error {
	fs := flag.NewFlagSet("trash restore", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	as := fs.String("as", "", "Restore it under this entry ID instead, such as password/github-old/alice")
	ids, err := parseAnywhere(fs, args)
	if err != nil {
		return err
	}
	if len(ids) != 1 {
		return errors.New("name one trash id: sesh trash restore <id> [--as <entry id>]")
	}
	parsed, err := trashIDs(ids)
	if err != nil {
		return err
	}
	var to vault.Key
	if *as != "" {
		if to, err = vault.ParseKey(*as); err != nil {
			return fmt.Errorf("--as: %w", err)
		}
	}
	_, store, err := openTrashStore()
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	got, err := store.RestoreFromTrash(parsed[0], to)
	if err != nil {
		return err
	}
	msg := fmt.Sprintf("✅ Restored %s from the trash.\n", got.Key)
	if got.TagsLost {
		msg += "Its tags were damaged in the trash, so it came back without them.\n"
	}
	_, err = io.WriteString(app.Stdout, msg)
	return err
}

// removeFromTrash is sesh trash remove <id>… [--force].
func removeFromTrash(app *App, args []string) error {
	fs := flag.NewFlagSet("trash remove", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	force := fs.Bool("force", false, "Don't ask first")
	idArgs, err := parseAnywhere(fs, args)
	if err != nil {
		return err
	}
	if len(idArgs) == 0 {
		return errors.New("name the trash ids to delete for good: sesh trash remove <id>…")
	}
	ids, err := trashIDs(idArgs)
	if err != nil {
		return err
	}
	_, store, err := openTrashStore()
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	trashed, err := store.Trash()
	if err != nil {
		return err
	}
	byID := map[int64]vault.Key{}
	for i := range trashed {
		byID[trashed[i].ID] = trashed[i].Key
	}
	var names []string
	named := map[int64]bool{}
	for _, id := range ids {
		k, ok := byID[id]
		if !ok {
			return fmt.Errorf("%w: %d; nothing was removed", database.ErrNotInTrash, id)
		}
		if named[id] {
			continue
		}
		named[id] = true
		names = append(names, k.String())
	}
	if !*force {
		ok, err := confirmForGood(app, "Delete "+strings.Join(names, ", ")+" for good?")
		if err != nil || !ok {
			return err
		}
	}
	gone, err := store.RemoveFromTrash(ids...)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(app.Stdout, "✅ Deleted %s for good.\n", entryCount(len(gone)))
	return err
}

// emptyTrash is sesh trash empty [--force].
func emptyTrash(app *App, args []string) error {
	fs := flag.NewFlagSet("trash empty", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	force := fs.Bool("force", false, "Don't ask first")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("sesh trash empty takes no entries, not %q; to delete some, use sesh trash remove <id>", fs.Arg(0))
	}
	_, store, err := openTrashStore()
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	trashed, err := store.Trash()
	if err != nil {
		return err
	}
	if len(trashed) == 0 {
		_, err := fmt.Fprintln(app.Stdout, "The trash is empty.")
		return err
	}
	if !*force {
		ok, err := confirmForGood(app, fmt.Sprintf("Delete the %s in the trash for good?", entryCount(len(trashed))))
		if err != nil || !ok {
			return err
		}
	}
	n, err := store.EmptyTrash()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(app.Stdout, "✅ Emptied the trash: %s deleted for good.\n", entryCount(n))
	return err
}

// confirmForGood asks question at the terminal; without one, --force is
// needed. A no says nothing was deleted, and isn't an error.
func confirmForGood(app *App, question string) (bool, error) {
	if app.StdinIsTerminal == nil || !app.StdinIsTerminal() {
		return false, errors.New("add --force to delete for good without being asked")
	}
	ok, err := promptYesNo(app.Stdin, app.Stderr, question+" [y/N]: ")
	if err != nil {
		return false, err
	}
	if !ok {
		_, err := fmt.Fprintln(app.Stderr, "Nothing deleted.")
		return false, err
	}
	return true, nil
}

// parseAnywhere parses fs's flags wherever they are among args, before
// or after the trash ids, and returns the ids.
func parseAnywhere(fs *flag.FlagSet, args []string) ([]string, error) {
	var flags, plain []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			plain = append(plain, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			plain = append(plain, a)
			continue
		}
		flags = append(flags, a)
		// A flag that takes a value, given as "-as v", takes the next.
		name := strings.TrimLeft(a, "-")
		if f := fs.Lookup(name); f != nil && !strings.Contains(a, "=") && i+1 < len(args) {
			if b, ok := f.Value.(interface{ IsBoolFlag() bool }); !ok || !b.IsBoolFlag() {
				i++
				flags = append(flags, args[i])
			}
		}
	}
	if err := fs.Parse(flags); err != nil {
		return nil, err
	}
	return plain, nil
}

// expireTrash deletes for good what has been in the trash longer than
// trash.keep_days. A failure is reported but never stops the command.
func expireTrash(store *database.Store, cfg *config.Config) {
	days := cfg.TrashKeepDays.Value
	if days == 0 {
		return
	}
	if _, err := store.ExpireTrash(time.Now().AddDate(0, 0, -days)); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err) //nolint:errcheck // best-effort warning
	}
}
