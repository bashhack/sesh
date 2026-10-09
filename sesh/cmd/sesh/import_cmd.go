package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/importer"
	"github.com/bashhack/sesh/internal/importer/bitwarden"
	"github.com/bashhack/sesh/internal/importer/gauth"
	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/qrcode"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/shell"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

const importUsage = `Usage: sesh import --from <source> [--dry-run] [--yes] [--on-conflict skip|overwrite] <file>...
  Bring entries over from another app. sesh shows what it found, what
  clashes with entries you have, and what it will skip, then asks.

  Sources:
    bitwarden             A Bitwarden JSON export: plain, or protected by a
                          password of its own (sesh asks for it).
    google-authenticator  The "Transfer accounts" QR codes: screenshots or
                          photos (PNG or JPEG), or their otpauth-migration://
                          text in a file, or piped in with - as the file.
                          Give every code of a large export.

  sesh import --from google-authenticator IMG_1234.png IMG_1235.png
  sesh import --from bitwarden bitwarden_export.json

sesh's own exports are imported with --service password --action import.`

// importSources are the apps sesh import reads.
var importSources = []string{"bitwarden", "google-authenticator"}

func addImportFlags(fs *flag.FlagSet) (from, onConflict *string, dryRun, yes *bool) {
	from = fs.String("from", "", "Where the file comes from: "+strings.Join(importSources, ", "))
	onConflict = fs.String("on-conflict", "", "For an entry you already have: skip, or overwrite (default: stop and list them)")
	dryRun = fs.Bool("dry-run", false, "Show what would be imported, and import nothing")
	yes = fs.Bool("yes", false, "Import without asking")
	return from, onConflict, dryRun, yes
}

// runImport is `sesh import`: it reads every file first, shows what it
// will do, asks, then stores the entries.
func runImport(app *App, args []string) error {
	if len(args) == 0 || isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, importUsage)
		return err
	}
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	from, onConflict, dryRun, yes := addImportFlags(fs)
	fs.Usage = func() { fmt.Fprintln(app.Stderr, importUsage) } //nolint:errcheck // usage text
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("name the files to import: sesh import --from <source> <files>")
	}
	if *onConflict != "" && *onConflict != "skip" && *onConflict != "overwrite" {
		return fmt.Errorf("--on-conflict is skip or overwrite, not %q", *onConflict)
	}
	for _, a := range fs.Args()[1:] {
		if strings.HasPrefix(a, "-") && a != "-" {
			return fmt.Errorf("put %s before the files: sesh import [flags] <files>", a)
		}
	}
	terminal := app.StdinIsTerminal != nil && app.StdinIsTerminal()
	source := *from
	if source == "" {
		source = detectSource(fs.Args())
	}
	var f found
	var err error
	switch source {
	case "google-authenticator":
		f, err = readGoogleAuthenticator(fs.Args(), app.Stdin, terminal)
	case "bitwarden":
		f, err = readBitwarden(app, fs.Args(), terminal)
	default:
		return fmt.Errorf("sesh can't import from %q; it can from: %s", source, strings.Join(importSources, ", "))
	}
	if err != nil {
		return err
	}
	defer func() {
		for _, e := range f.entries {
			secure.SecureZeroBytes(e.Secret)
			e.Details.Zero()
		}
	}()

	// Importing can be the first thing done with sesh: the vault is made
	// if there's none yet, as any command makes it, unless this is only a
	// dry run, which has nothing to clash with then.
	cfg, err := settings()
	if err != nil {
		return err
	}
	var store *database.Store
	if !*dryRun || !vaultMissing(cfg.DBPath.Value) {
		if _, store, err = openAuditStore(); err != nil {
			return err
		}
		defer closeAuditStore(store)
	}
	var fresh, clashes, skipped []*importer.Entry
	for _, e := range f.entries {
		if e.Skip != "" {
			skipped = append(skipped, e)
			continue
		}
		if store != nil {
			if err := store.Exists(e.Key); err == nil {
				clashes = append(clashes, e)
				continue
			} else if !errors.Is(err, vault.ErrNotFound) {
				return err
			}
			// A name differing only in case from one you have is said,
			// so a second entry isn't added unnoticed.
			if twins, err := password.NewManager(store).CaseTwins(e.Key); err == nil && len(twins) > 0 {
				e.Changes = append(e.Changes, "you have "+twins[0].String())
			}
		}
		fresh = append(fresh, e)
	}

	if _, err := fmt.Fprint(app.Stderr, importSummary(&f, fresh, clashes, skipped, *onConflict)); err != nil {
		return err
	}
	toImport := len(fresh)
	if *onConflict == "overwrite" {
		toImport += len(clashes)
	}
	clashHint := "some of these are already in the vault: add --on-conflict skip to leave them, or --on-conflict overwrite to replace them"
	if *dryRun {
		if len(clashes) > 0 && *onConflict == "" {
			fmt.Fprintf(app.Stderr, "\nTo import, %s.\n", clashHint) //nolint:errcheck // best effort
		}
		_, err := fmt.Fprintln(app.Stderr, "\nNothing imported (--dry-run).")
		return err
	}
	if len(clashes) > 0 && *onConflict == "" {
		return errors.New(clashHint)
	}
	if toImport == 0 {
		if _, err := fmt.Fprintln(app.Stderr, "\nNothing to import."); err != nil || f.after == "" {
			return err
		}
		_, err := fmt.Fprintln(app.Stdout, f.after)
		return err
	}
	if !*yes {
		if !terminal {
			return errors.New("add --yes to import without being asked")
		}
		ok, err := promptYesNo(app.Stdin, app.Stderr, fmt.Sprintf("\nImport %s? [y/N]: ", nouns(toImport, "entry", "entries")))
		if err != nil {
			return err
		}
		if !ok {
			_, err := fmt.Fprintln(app.Stderr, "Nothing imported.")
			return err
		}
	}

	write := fresh
	if *onConflict == "overwrite" {
		write = append(write, clashes...)
	}
	allTOTP := !slices.ContainsFunc(write, func(e *importer.Entry) bool { return e.Key.Kind != vault.KindTOTP })
	what := func(n int) string {
		if allTOTP {
			return nouns(n, "TOTP entry", "TOTP entries")
		}
		return nouns(n, "entry", "entries")
	}
	done := 0
	for _, e := range write {
		if err := writeImported(store, e, slices.Contains(clashes, e)); err != nil {
			if done > 0 {
				store.LogImport(fmt.Sprintf("%s from %s, then stopped", what(done), f.source))
			}
			return fmt.Errorf("imported %s, then %s failed: %w; to import the rest, run this again with --on-conflict skip", nouns(done, "entry", "entries"), e.Key, err)
		}
		done++
	}
	store.LogImport(what(done) + " from " + f.source)
	if _, err := fmt.Fprintf(app.Stdout, "✅ Imported %s from %s.\n", what(done), f.source); err != nil {
		return err
	}
	if i := slices.IndexFunc(write, func(e *importer.Entry) bool { return e.Key.Kind == vault.KindTOTP }); i >= 0 && source == "google-authenticator" {
		k := write[i].Key
		check := "sesh --service totp --service-name " + shell.Quote(k.Service)
		if k.Username != "" {
			check += " --profile " + shell.Quote(k.Username)
		}
		fmt.Fprintf(app.Stdout, "Before removing an account from your phone, check that its code matches, as with: %s\n", check) //nolint:errcheck // best effort
	}
	if f.after != "" {
		_, err = fmt.Fprintln(app.Stdout, f.after)
	}
	return err
}

// found is what an import read from its files.
type found struct {
	source   string // the app, as messages name it
	header   string // the summary's first line
	after    string // said once the import is done, if anything
	warnings []string
	entries  []*importer.Entry
}

// detectSource is the app the files come from: Bitwarden for one of its
// JSON exports, Google Authenticator otherwise.
func detectSource(args []string) string {
	for _, a := range args {
		if b, err := os.ReadFile(a); err == nil && bitwarden.IsExport(b) { //nolint:gosec // the file the user named
			return "bitwarden"
		}
	}
	return "google-authenticator"
}

// writeImported stores e. One replacing an entry you have keeps that
// entry's folder, tags, creation time and details where the import
// brings none.
func writeImported(store *database.Store, e *importer.Entry, exists bool) error {
	ent := vault.Entry{Key: e.Key, Settings: e.Settings, Folder: e.Folder, Tags: e.Tags, CreatedAt: e.Created, UpdatedAt: e.Updated}
	if exists {
		cur, err := store.Lookup(e.Key)
		if err != nil {
			return err
		}
		if ent.Folder == "" {
			ent.Folder = cur.Folder
		}
		if len(ent.Tags) == 0 {
			ent.Tags = cur.Tags
		}
		if ent.CreatedAt.IsZero() {
			ent.CreatedAt = cur.CreatedAt
		}
		if e.Details.IsZero() {
			return store.Save(&ent, e.Secret)
		}
	}
	return store.SaveWithDetails(&ent, e.Secret, &e.Details)
}

// importSummary is what an import found, as sesh shows it before asking:
// folders renamed once, then each entry to import with what changed on
// the way, the ones already in the vault, and the ones skipped.
func importSummary(f *found, fresh, clashes, skipped []*importer.Entry, onConflict string) string {
	var b strings.Builder
	b.WriteString(f.header + "\n")
	for _, w := range f.warnings {
		fmt.Fprintf(&b, "⚠️  %s\n", w)
	}
	var folders []string
	for _, e := range f.entries {
		for _, c := range e.Changes {
			if strings.HasPrefix(c, "folder ") && !slices.Contains(folders, c) {
				folders = append(folders, c)
			}
		}
	}
	if len(folders) > 0 {
		b.WriteString("\nFolders, renamed to fit sesh's rules:\n")
		for _, c := range folders {
			fmt.Fprintf(&b, "  %s\n", strings.TrimPrefix(c, "folder "))
		}
	}
	section := func(title string, list []*importer.Entry, line func(*importer.Entry) string) {
		if len(list) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n%s (%d):\n", title, len(list))
		for _, e := range list {
			fmt.Fprintf(&b, "  %s\n", line(e))
			for _, c := range e.Changes {
				if !strings.HasPrefix(c, "folder ") {
					fmt.Fprintf(&b, "      %s\n", c)
				}
			}
		}
	}
	section("To import", fresh, func(e *importer.Entry) string { return e.Key.String() + describeParams(e.Settings.TOTP) })
	clashTitle := "Already in the vault"
	switch onConflict {
	case "skip":
		clashTitle += ", left as they are"
	case "overwrite":
		clashTitle += ", to be replaced"
	}
	section(clashTitle, clashes, func(e *importer.Entry) string { return e.Key.String() })
	var b2 strings.Builder
	if len(skipped) > 0 {
		fmt.Fprintf(&b2, "\nSkipped (%d):\n", len(skipped))
		for _, e := range skipped {
			fmt.Fprintf(&b2, "  %q: %s\n", e.Name, e.Skip)
		}
	}
	return b.String() + b2.String()
}

// readBitwarden reads one Bitwarden JSON export, asking at the terminal
// for the password of one protected by a password.
func readBitwarden(app *App, args []string, terminal bool) (found, error) {
	if len(args) != 1 {
		return found{}, errors.New("give one Bitwarden export: sesh import --from bitwarden <export.json>")
	}
	b, err := os.ReadFile(args[0])
	if err != nil {
		return found{}, err
	}
	defer secure.SecureZeroBytes(b)
	protected := false
	exp, err := bitwarden.Parse(b, func() ([]byte, error) {
		protected = true
		if !terminal {
			return nil, errors.New("this Bitwarden export is protected by a password: run sesh import at a terminal to type it")
		}
		fmt.Fprint(app.Stderr, "Password for the Bitwarden export: ") //nolint:errcheck // prompt
		pw, err := readSecret()
		fmt.Fprintln(app.Stderr) //nolint:errcheck // ends the prompt line
		return pw, err
	})
	if err != nil {
		return found{}, err
	}
	f := found{
		source: "Bitwarden",
		header: fmt.Sprintf("Found %s and %s in the Bitwarden export.", nouns(len(exp.Items), "item", "items"), nouns(len(exp.Folders), "folder", "folders")),
	}
	f.entries = bitwarden.Entries(&exp)
	if !protected {
		f.after = "This export holds your passwords unencrypted: delete " + args[0] + " now, and empty the trash."
	}
	return f, nil
}

// readGoogleAuthenticator reads Google Authenticator transfer codes.
func readGoogleAuthenticator(args []string, stdin io.Reader, terminal bool) (found, error) {
	payloads, err := readTransferCodes(args, stdin, terminal)
	if err != nil {
		return found{}, err
	}
	accounts := 0
	for _, p := range payloads {
		accounts += len(p.Accounts)
	}
	return found{
		source:   "Google Authenticator",
		header:   fmt.Sprintf("Found %s in %s from Google Authenticator.", nouns(accounts, "account", "accounts"), nouns(len(payloads), "transfer code", "transfer codes")),
		warnings: missingBatches(payloads),
		entries:  plannedTransfer(payloads),
	}, nil
}

// readTransferCodes reads each argument: an otpauth-migration:// code
// itself, "-" for stdin, an image of codes (by its content, whatever its
// name), or a text file of codes, one per line. Errors name an argument
// given as a code by its place ("code 2"), never its text, which holds
// secrets.
func readTransferCodes(args []string, stdin io.Reader, stdinTerminal bool) ([]gauth.Payload, error) {
	var payloads []gauth.Payload
	for n, arg := range args {
		arg = strings.TrimSpace(arg)
		name := arg
		var codes []string
		switch {
		case strings.HasPrefix(arg, gauth.Prefix):
			name, codes = fmt.Sprintf("code %d", n+1), []string{arg}
		case strings.Contains(arg, "data="):
			return nil, fmt.Errorf("argument %d looks like a transfer code, but doesn't start with %s; copy the whole code", n+1, gauth.Prefix)
		case strings.Contains(arg, "://"):
			return nil, fmt.Errorf("argument %d isn't a Google Authenticator transfer code (otpauth-migration://) or a file; a single account's otpauth:// code is added with: sesh --service totp --setup", n+1)
		default:
			var b []byte
			var err error
			if arg == "-" {
				if stdinTerminal {
					// A terminal takes only so long a line; a code is
					// longer.
					return nil, errors.New("pipe the codes in rather than typing or pasting them: pbpaste | sesh import -")
				}
				name = "stdin"
				b, err = io.ReadAll(io.LimitReader(stdin, 16<<20))
			} else {
				b, err = os.ReadFile(arg) //nolint:gosec // the file the user named
			}
			if err != nil {
				return nil, err
			}
			if qrcode.IsImage(arg, b) {
				texts, err := qrcode.ReadTextsFromBytes(name, b)
				if err != nil {
					return nil, err
				}
				for _, t := range texts {
					if strings.HasPrefix(t, gauth.Prefix) {
						codes = append(codes, t)
					}
				}
				if len(codes) == 0 {
					return nil, fmt.Errorf("the QR code in %s isn't a Google Authenticator transfer code: in the app, use Transfer accounts, then Export accounts", name)
				}
				break
			}
			for line := range strings.SplitSeq(string(b), "\n") {
				if line = strings.TrimSpace(line); strings.HasPrefix(line, gauth.Prefix) {
					codes = append(codes, line)
				}
			}
			if len(codes) == 0 {
				return nil, fmt.Errorf("%s has no otpauth-migration:// codes, and isn't a PNG or JPEG of one", name)
			}
		}
		for _, c := range codes {
			p, err := gauth.Parse(c)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			payloads = append(payloads, p)
		}
	}
	return payloads, nil
}

// plannedTransfer is the entries the transfer codes hold, in order: the
// same account given twice is skipped the second time, and another with
// a name already given is told apart.
func plannedTransfer(payloads []gauth.Payload) []*importer.Entry {
	var entries []*importer.Entry
	seen := map[vault.Key]string{} // each name's secret
	for _, p := range payloads {
		for i := range p.Accounts {
			a := &p.Accounts[i]
			k, params, skip := a.Entry()
			name := a.Name
			if a.Issuer != "" && !strings.HasPrefix(a.Name, a.Issuer+":") {
				name = a.Issuer + ": " + a.Name
			}
			if was, ok := seen[k]; ok && skip == "" {
				skip = "the same account twice"
				if was != a.Secret {
					skip = "another account here has this name: rename one in Google Authenticator, export again, and import that"
				}
			}
			e := &importer.Entry{Key: k, Name: name, Skip: skip, Settings: vault.Settings{TOTP: params}}
			if skip == "" {
				seen[k] = a.Secret
				secret, _ := totp.ValidateAndNormalizeSecret(a.Secret) //nolint:errcheck // Entry checked it
				e.Secret = []byte(secret)
			}
			entries = append(entries, e)
		}
	}
	return entries
}

// missingBatches says which codes of a split export weren't given.
func missingBatches(payloads []gauth.Payload) []string {
	type batch struct {
		got  map[int]bool
		size int
	}
	batches := map[int]*batch{}
	var order []int
	for _, p := range payloads {
		b, ok := batches[p.BatchID]
		if !ok {
			b = &batch{got: map[int]bool{}, size: p.BatchSize}
			batches[p.BatchID] = b
			order = append(order, p.BatchID)
		}
		b.got[p.BatchIndex] = true
	}
	var msgs []string
	for _, id := range order {
		b := batches[id]
		var missing []string
		for i := range b.size {
			if !b.got[i] {
				missing = append(missing, fmt.Sprint(i+1))
			}
		}
		switch len(missing) {
		case 0:
		case 1:
			msgs = append(msgs, fmt.Sprintf("The export has %d codes, and code %s wasn't given: the accounts on it aren't here. Add it to import them too.", b.size, missing[0]))
		default:
			msgs = append(msgs, fmt.Sprintf("The export has %d codes, and codes %s weren't given: the accounts on them aren't here. Add them to import those too.",
				b.size, strings.Join(missing[:len(missing)-1], ", ")+" and "+missing[len(missing)-1]))
		}
	}
	return msgs
}

// describeParams notes code settings other than the usual ones.
func describeParams(p totp.Params) string {
	var parts []string
	if p.Algorithm != "" {
		parts = append(parts, p.Algorithm)
	}
	if p.Digits != 0 {
		parts = append(parts, fmt.Sprintf("%d digits", p.Digits))
	}
	if len(parts) == 0 {
		return ""
	}
	return "  (" + strings.Join(parts, ", ") + ")"
}

// nouns is n and the noun for it: one, or many.
func nouns(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
