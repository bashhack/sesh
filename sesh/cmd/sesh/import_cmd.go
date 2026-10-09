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
	"github.com/bashhack/sesh/internal/importer/gauth"
	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/qrcode"
	"github.com/bashhack/sesh/internal/shell"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

const importUsage = `Usage: sesh import --from <source> [--dry-run] [--yes] [--on-conflict skip|overwrite] <file>...
  Bring entries over from another app. sesh shows what it found, what
  clashes with entries you have, and what it will skip, then asks.

  Sources:
    google-authenticator  The "Transfer accounts" QR codes: screenshots or
                          photos (PNG or JPEG), or their otpauth-migration://
                          text in a file, or piped in with - as the file.
                          Give every code of a large export.

  sesh import --from google-authenticator IMG_1234.png IMG_1235.png

sesh's own exports are imported with --service password --action import.`

// importSources are the apps sesh import reads.
var importSources = []string{"google-authenticator"}

func addImportFlags(fs *flag.FlagSet) (from, onConflict *string, dryRun, yes *bool) {
	from = fs.String("from", "", "Where the file comes from: "+strings.Join(importSources, ", "))
	onConflict = fs.String("on-conflict", "", "For an entry you already have: skip, or overwrite (default: stop and list them)")
	dryRun = fs.Bool("dry-run", false, "Show what would be imported, and import nothing")
	yes = fs.Bool("yes", false, "Import without asking")
	return from, onConflict, dryRun, yes
}

// importEntry is an entry an import found: what it would store, or why
// it can't.
type importEntry struct {
	key    vault.Key
	name   string // as the source names it
	secret string
	skip   string
	note   string // shown after the name in the summary
	params totp.Params
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
	switch *from {
	case "", "google-authenticator":
	default:
		return fmt.Errorf("sesh can't import from %q yet; it can from: %s", *from, strings.Join(importSources, ", "))
	}

	for _, a := range fs.Args()[1:] {
		if strings.HasPrefix(a, "-") && a != "-" {
			return fmt.Errorf("put %s before the files: sesh import [flags] <files>", a)
		}
	}
	payloads, err := readTransferCodes(fs.Args(), app.Stdin, app.StdinIsTerminal != nil && app.StdinIsTerminal())
	if err != nil {
		return err
	}
	entries := plannedTransfer(payloads)

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
	var clashes []*importEntry
	for _, e := range entries {
		if e.skip != "" || store == nil {
			continue
		}
		if err := store.Exists(e.key); err == nil {
			clashes = append(clashes, e)
			continue
		} else if !errors.Is(err, vault.ErrNotFound) {
			return err
		}
		// A name differing only in case from one you have is said, so a
		// second entry isn't added unnoticed.
		if twins, err := password.NewManager(store).CaseTwins(e.key); err == nil && len(twins) > 0 {
			e.note = "  (you have " + twins[0].String() + ")"
		}
	}

	toImport := 0
	var b strings.Builder
	accounts := 0
	for _, p := range payloads {
		accounts += len(p.Accounts)
	}
	fmt.Fprintf(&b, "Found %s in %s from Google Authenticator.\n", nouns(accounts, "account", "accounts"), nouns(len(payloads), "transfer code", "transfer codes"))
	for _, m := range missingBatches(payloads) {
		fmt.Fprintf(&b, "⚠️  %s\n", m)
	}
	section := func(title string, list []*importEntry, line func(*importEntry) string) {
		if len(list) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n%s (%d):\n", title, len(list))
		for _, e := range list {
			fmt.Fprintf(&b, "  %s\n", line(e))
		}
	}
	var fresh, skipped []*importEntry
	for _, e := range entries {
		switch {
		case e.skip != "":
			skipped = append(skipped, e)
		case !slices.ContainsFunc(clashes, func(c *importEntry) bool { return c.key == e.key }):
			fresh = append(fresh, e)
		}
	}
	section("To import", fresh, func(e *importEntry) string { return e.key.String() + describeParams(e.params) + e.note })
	clashTitle := "Already in the vault"
	switch *onConflict {
	case "skip":
		clashTitle += ", left as they are"
	case "overwrite":
		clashTitle += ", to be replaced"
	}
	section(clashTitle, clashes, func(e *importEntry) string { return e.key.String() })
	section("Skipped", skipped, func(e *importEntry) string { return fmt.Sprintf("%q: %s", e.name, e.skip) })
	toImport = len(fresh)
	if *onConflict == "overwrite" {
		toImport += len(clashes)
	}
	if _, err := fmt.Fprint(app.Stderr, b.String()); err != nil {
		return err
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
		_, err := fmt.Fprintln(app.Stderr, "\nNothing to import.")
		return err
	}
	if !*yes {
		if app.StdinIsTerminal == nil || !app.StdinIsTerminal() {
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

	mgr := password.NewManager(store)
	write := fresh
	if *onConflict == "overwrite" {
		write = append(write, clashes...)
	}
	done := 0
	for _, e := range write {
		if err := mgr.StoreTOTPSecretWithParams(e.key.Service, e.key.Username, e.secret, e.params, vault.Filing{}); err != nil {
			if done > 0 {
				store.LogImport(fmt.Sprintf("%s from Google Authenticator, then stopped", nouns(done, "TOTP entry", "TOTP entries")))
			}
			return fmt.Errorf("imported %s, then %s failed: %w; to import the rest, run this again with --on-conflict skip", nouns(done, "entry", "entries"), e.key, err)
		}
		done++
	}
	store.LogImport(nouns(done, "TOTP entry", "TOTP entries") + " from Google Authenticator")
	first := write[0].key
	check := "sesh --service totp --service-name " + shell.Quote(first.Service)
	if first.Username != "" {
		check += " --profile " + shell.Quote(first.Username)
	}
	_, err = fmt.Fprintf(app.Stdout, "✅ Imported %s from Google Authenticator.\nBefore removing an account from your phone, check that its code matches, as with: %s\n",
		nouns(done, "TOTP entry", "TOTP entries"), check)
	return err
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

// plannedTransfer is the entries the transfer codes hold, in order; an
// account given twice is skipped the second time.
func plannedTransfer(payloads []gauth.Payload) []*importEntry {
	var entries []*importEntry
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
			if skip == "" {
				seen[k] = a.Secret
			}
			entries = append(entries, &importEntry{key: k, params: params, name: name, secret: a.Secret, skip: skip})
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
