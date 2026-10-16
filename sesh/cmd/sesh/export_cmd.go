package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/exportfile"
	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

const exportUsage = `Usage: sesh export [passwords|keys|notes|totp|files] [--file F] [--format encrypted|json|csv] [--folder F] [--tag T] [--force]
  Write every entry, or those of a kind, folder or tag, to a file (or to
  the output). The default, encrypted, asks for a password that opens it
  anywhere sesh runs (sesh import --from sesh reads it back); json and csv
  hold every secret unencrypted. A file there already is replaced only with
  --force, and only once the export is whole; the vault's own file never is.

  sesh export --file backup.enc
  sesh export notes --format json > notes.json`

// addExportFlags defines sesh export's flags on fs.
func addExportFlags(fs *flag.FlagSet) (file, format *string, force *bool, filing *provider.FilingFlags) {
	file = fs.String("file", "", "Where to write it (default: the output)")
	format = fs.String("format", "encrypted", "encrypted, json, or csv")
	force = fs.Bool("force", false, "Replace a file there already")
	filing = &provider.FilingFlags{}
	filing.RegisterFilter(fs)
	return file, format, force, filing
}

// runExport is sesh export: the entries, written as an export.
func runExport(app *App, args []string) error {
	if len(args) > 0 && isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, exportUsage)
		return err
	}
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	file, format, force, filing := addExportFlags(fs)
	fs.Usage = func() { fmt.Fprintln(app.Stderr, exportUsage) } //nolint:errcheck // usage text
	words, err := parseAnywhere(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	var kind vault.Kind
	for _, w := range words {
		k, ok := listKinds[strings.ToLower(w)]
		switch {
		case !ok:
			return fmt.Errorf("sesh export takes a kind (passwords, keys, notes, totp, files), not %q", w)
		case kind != "" && k != kind:
			return errors.New("sesh export takes one kind at a time")
		}
		kind = k
	}
	if *format != "encrypted" && *format != "json" && *format != "csv" {
		return fmt.Errorf("--format is encrypted, json, or csv, not %q", *format)
	}
	if kind == vault.KindFile && *format == "csv" {
		return errors.New("a CSV export holds text, so it leaves files out: use --format json, or the encrypted export")
	}
	if *format == "encrypted" && (app.StdinIsTerminal == nil || !app.StdinIsTerminal()) {
		return errExportNeedsTerminal
	}

	cfg, err := settings()
	if err != nil {
		return err
	}
	store, err := openFilingStore()
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	mgr := password.NewManager(store)
	f := filing.Filter()
	if err := checkExportMatches(store, kind, &f); err != nil {
		return err
	}
	opts := &password.ExportOptions{EntryType: kind, Folder: f.Folder, FolderSet: f.FolderSet, Tags: f.Tags}

	// The file is opened before the password is asked, so a path that
	// can't be written fails first, and is left as it is until the export
	// is whole.
	w := app.Stdout
	dest := "the output"
	var out *exportfile.File
	if *file != "" {
		dest = tildePath(*file)
		if out, err = exportfile.Open(*file, *force, cfg.DBPath.Value); err != nil {
			return err
		}
		defer out.Abort()
		w = out
	}
	var pw []byte
	if *format == "encrypted" {
		if pw, err = readExportPassword(app); err != nil {
			return err
		}
		defer secure.SecureZeroBytes(pw)
	}
	if out != nil {
		if err := out.Start(); err != nil {
			return fmt.Errorf("can't write an export in %s: %w", filepath.Dir(*file), err)
		}
		// Interrupted while it's written, the file being made is removed:
		// it holds part of the export.
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
		defer signal.Stop(stop)
		done := make(chan struct{})
		defer close(done)
		go func() {
			select {
			case sig := <-stop:
				out.Abort()
				code := 1
				if s, ok := sig.(syscall.Signal); ok {
					code = 128 + int(s)
				}
				os.Exit(code)
			case <-done:
			}
		}()
	}
	var count int
	switch *format {
	case "encrypted":
		opts.KDF = cfg.KDF()
		count, err = mgr.ExportEncrypted(w, opts, pw)
	case "csv":
		opts.Format = password.FormatCSV
		count, err = mgr.Export(w, opts)
	default:
		opts.Format = password.FormatJSON
		count, err = mgr.Export(w, opts)
	}
	if err != nil {
		return err
	}
	if out != nil {
		if err := out.Finish(); err != nil {
			return fmt.Errorf("write the export to %s: %w", dest, err)
		}
	}
	msg := fmt.Sprintf("Exported %s to %s", entryCount(count), dest)
	if opts.LeftOut > 0 {
		msg += fmt.Sprintf(" (%d file %s left out: CSV holds text, and --format json or the encrypted export takes files)", opts.LeftOut, plural(opts.LeftOut, "entry", "entries"))
	}
	if *format != "encrypted" {
		msg += ". It holds every secret unencrypted: delete it when you're done"
	}
	_, err = fmt.Fprintln(app.Stderr, msg)
	return err
}

var errExportNeedsTerminal = errors.New("an encrypted export asks for its password at a terminal; --format json or csv writes one without")

// checkExportMatches refuses an export of a kind, folder or tag (f) that
// no entry has: likely a typo, since folders and tags are case-sensitive.
// It's said before a file is touched or a password asked for.
func checkExportMatches(store *database.Store, kind vault.Kind, f *vault.Filter) error {
	if kind == "" && !f.FolderSet && len(f.Tags) == 0 {
		return nil
	}
	found, err := password.NewManager(store).ListEntriesFiltered(&password.ListFilter{EntryType: kind, Folder: f.Folder, FolderSet: f.FolderSet, Tags: f.Tags, Limit: 1})
	if err != nil || len(found) > 0 {
		return err
	}
	what := "entries"
	if kind != "" {
		what = kindName(kind) + " entries"
	}
	msg := "no " + what
	if s := provider.Scope(f); s != "" {
		msg += " " + s
	}
	if h := provider.NoMatchHint(store, f, ""); h != "" {
		msg += ": " + h
	}
	return errors.New(msg + ", so nothing was exported")
}

// readExportPassword asks for a new export's password, twice, at the
// terminal: at least 8 characters, and one that's easy to guess is asked
// about, since anyone with the file can try passwords against it.
func readExportPassword(app *App) ([]byte, error) {
	if app.StdinIsTerminal == nil || !app.StdinIsTerminal() {
		return nil, errExportNeedsTerminal
	}
	fmt.Fprint(app.Stderr, "Export password: ") //nolint:errcheck // prompt
	pw, err := readSecret()
	fmt.Fprintln(app.Stderr) //nolint:errcheck // ends the prompt line
	if err != nil {
		return nil, fmt.Errorf("read the password: %w", err)
	}
	if len(pw) < 8 {
		secure.SecureZeroBytes(pw)
		return nil, errors.New("the export password must be at least 8 characters")
	}
	if password.IsWeak(pw) {
		yes, err := promptYesNo(app.Stdin, app.Stderr, "⚠️  This password is easy to guess: a cracking program would likely find it in under 100 million tries, and anyone with the file can try. Use it anyway? [y/N]: ")
		if err != nil || !yes {
			secure.SecureZeroBytes(pw)
			if err == nil {
				err = errors.New("nothing exported: choose a stronger password")
			}
			return nil, err
		}
	}
	fmt.Fprint(app.Stderr, "Export password again: ") //nolint:errcheck // prompt
	again, err := readSecret()
	fmt.Fprintln(app.Stderr) //nolint:errcheck // ends the prompt line
	defer secure.SecureZeroBytes(again)
	if err != nil {
		secure.SecureZeroBytes(pw)
		return nil, fmt.Errorf("read the password: %w", err)
	}
	if !bytes.Equal(pw, again) {
		secure.SecureZeroBytes(pw)
		return nil, errors.New("the passwords don't match; nothing exported")
	}
	return pw, nil
}
