package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bashhack/sesh/internal/clipboard"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/shell"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

const listUsage = `Usage: sesh list [passwords|keys|notes|totp …] [--folder F] [--tag T] [--sort S] [--json]
  List the entries, or those of the kinds named. --folder keeps the entries
  in a folder and the folders under it ("" for no folder); --tag keeps those
  with a tag (repeat it: all must match). --sort is name, created, updated,
  or folder.

  sesh list
  sesh list notes
  sesh list totp --folder work`

const searchUsage = `Usage: sesh search <words> [--folder F] [--tag T] [--json]
  Find entries by any part of their name, username, or URL's host, best
  match first, as sesh ui's search does. A kind word (totp, note, key,
  password) narrows to that kind.

  sesh search github
  sesh search bank note`

const copyUsage = `Usage: sesh copy <entry> [--username | --url | --field NAME]
  Copy an entry's password, API key or note, or a TOTP entry's current code,
  to the clipboard, which clears after clipboard_timeout. --username,
  --url and --field copy that instead.

  sesh copy github
  sesh copy aws totp
  sesh copy github --field pin

` + entryWordsHelp

const getUsage = `Usage: sesh get <entry> [--username | --url | --field NAME] [--json]
  Print an entry's password, API key or note, or a TOTP entry's current
  code, for a pipe or a script; --username, --url and --field print that
  instead.

  sesh get github
  sesh get stripe key | pbcopy

` + entryWordsHelp

const codeUsage = `Usage: sesh code <entry> [--json]
  Print a TOTP entry's current code, and how long it has left; near its end,
  the next code too.

  sesh code github

` + entryWordsHelp

const openUsage = `Usage: sesh open <entry>
  Open an entry's URL in the browser (http and https only).

` + entryWordsHelp

const generateUsage = `Usage: sesh generate [--length N] [--no-symbols] [--copy]
  Print a new random password, stored nowhere; --copy copies it instead.
  To store one, use sesh add password <name> --generate.`

// listKinds are the words sesh list takes as kinds.
var listKinds = map[string]vault.Kind{
	"password": vault.KindPassword, "passwords": vault.KindPassword,
	"key": vault.KindAPIKey, "keys": vault.KindAPIKey, "api_key": vault.KindAPIKey, "api-key": vault.KindAPIKey, "apikey": vault.KindAPIKey,
	"note": vault.KindNote, "notes": vault.KindNote, "secure_note": vault.KindNote,
	"totp": vault.KindTOTP, "code": vault.KindTOTP, "codes": vault.KindTOTP, "2fa": vault.KindTOTP, "mfa": vault.KindTOTP, "otp": vault.KindTOTP,
}

// listSorts are what sesh list's --sort takes, and the order each is.
var listSorts = map[string]password.SortField{
	"name": password.SortByService, "created": password.SortByCreatedAt, "updated": password.SortByUpdatedAt, "folder": password.SortByFolder,
}

// addListFlags defines sesh list's flags on fs.
func addListFlags(fs *flag.FlagSet) (filing *provider.FilingFlags, sortBy *string, asJSON *bool) {
	filing = &provider.FilingFlags{}
	filing.RegisterFilter(fs)
	return filing, fs.String("sort", "name", "name, created, updated, or folder"), fs.Bool("json", false, "Print them as JSON")
}

// addSearchFlags defines sesh search's flags on fs.
func addSearchFlags(fs *flag.FlagSet) (filing *provider.FilingFlags, asJSON *bool) {
	filing = &provider.FilingFlags{}
	filing.RegisterFilter(fs)
	return filing, fs.Bool("json", false, "Print them as JSON")
}

// addCopyFlags defines sesh copy's flags on fs.
func addCopyFlags(fs *flag.FlagSet) *valueFlags {
	v := &valueFlags{}
	v.register(fs)
	return v
}

// addGetFlags defines sesh get's flags on fs.
func addGetFlags(fs *flag.FlagSet) (*valueFlags, *bool) {
	return addCopyFlags(fs), fs.Bool("json", false, "Print it as JSON, with the entry's name")
}

// addCodeFlags defines sesh code's flags on fs.
func addCodeFlags(fs *flag.FlagSet) *bool {
	return fs.Bool("json", false, "Print it as JSON")
}

// addGenerateFlags defines sesh generate's flags on fs.
func addGenerateFlags(fs *flag.FlagSet) (length *int, noSymbols, toClipboard *bool) {
	return fs.Int("length", 24, "How many characters"), fs.Bool("no-symbols", false, "Letters and digits only"), fs.Bool("copy", false, "Copy it instead of printing it")
}

// runList is sesh list: every entry, or those of the kinds named.
func runList(app *App, args []string) error {
	if len(args) > 0 && isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, listUsage)
		return err
	}
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	filing, sortBy, asJSON := addListFlags(fs)
	fs.Usage = func() { fmt.Fprintln(app.Stderr, listUsage) } //nolint:errcheck // usage text
	words, err := parseAnywhere(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	kinds := map[vault.Kind]bool{}
	for _, w := range words {
		k, ok := listKinds[strings.ToLower(w)]
		if !ok {
			return fmt.Errorf("sesh list takes kinds (passwords, keys, notes, totp), not %q; to find entries by name: sesh search %s", w, w)
		}
		kinds[k] = true
	}
	order, ok := listSorts[*sortBy]
	if !ok {
		return fmt.Errorf("--sort is name, created, updated, or folder, not %q", *sortBy)
	}

	store, err := openFilingStore()
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	f := filing.Filter()
	entries, err := password.NewManager(store).ListEntriesFiltered(&password.ListFilter{SortBy: order, Folder: f.Folder, FolderSet: f.FolderSet, Tags: f.Tags})
	if err != nil {
		return err
	}
	if len(kinds) > 0 {
		entries = slices.DeleteFunc(entries, func(e password.Entry) bool { return !kinds[e.Type] })
	}
	if *asJSON {
		return writeJSON(app.Stdout, entries)
	}
	if len(entries) == 0 {
		msg := "No entries"
		if len(kinds) > 0 {
			var named []string
			for _, k := range []vault.Kind{vault.KindPassword, vault.KindAPIKey, vault.KindNote, vault.KindTOTP} {
				if kinds[k] {
					named = append(named, kindName(k))
				}
			}
			msg = "No " + strings.Join(named, " or ") + " entries"
		}
		if s := provider.Scope(&f); s != "" {
			msg += " " + s
		}
		among := ""
		if len(kinds) == 1 {
			for k := range kinds {
				among = kindName(k) + " entries"
			}
		}
		if h := provider.NoMatchHint(store, &f, among); h != "" {
			msg += ": " + h
		} else if len(f.Tags) == 0 && !f.FolderSet && len(kinds) == 0 {
			msg += " yet. Add one with: sesh add password <name>"
		}
		_, err := fmt.Fprintln(app.Stderr, msg)
		return err
	}
	return writeEntryTable(app.Stdout, entries, nil)
}

// runSearch is sesh search: the entries matching words, best first.
func runSearch(app *App, args []string) error {
	if len(args) == 0 || isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, searchUsage)
		return err
	}
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	filing, asJSON := addSearchFlags(fs)
	fs.Usage = func() { fmt.Fprintln(app.Stderr, searchUsage) } //nolint:errcheck // usage text
	words, err := parseAnywhere(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if len(words) == 0 {
		return errors.New("give words to search for: sesh search <words>")
	}
	query := strings.Join(words, " ")

	store, err := openFilingStore()
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	f := filing.Filter()
	in := &password.ListFilter{Folder: f.Folder, FolderSet: f.FolderSet, Tags: f.Tags}
	mgr := password.NewManager(store)
	entries, err := mgr.SearchIn(query, in)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(app.Stdout, entries)
	}
	if len(entries) == 0 {
		msg := fmt.Sprintf("No entries matching %q", query)
		if s := provider.Scope(&f); s != "" {
			msg = fmt.Sprintf("No entries %s matching %q", s, query)
		}
		if h := provider.NoMatchHint(store, &f, ""); h != "" {
			msg += ": " + h
		} else if names, err := mgr.SuggestionsIn(query, in); err == nil && len(names) > 0 {
			msg += ". Did you mean: " + strings.Join(names, ", ") + "?"
		}
		_, err := fmt.Fprintln(app.Stderr, msg)
		return err
	}
	if _, err := fmt.Fprintf(app.Stdout, "Found %s matching %q:\n", entryCount(len(entries)), query); err != nil {
		return err
	}
	if err := writeEntryTable(app.Stdout, entries, words); err != nil {
		return err
	}
	if len(entries) == 1 {
		_, err := fmt.Fprintln(app.Stderr, "Copy it: sesh copy "+entryArg(&entries[0]))
		return err
	}
	return nil
}

// writeEntryTable lays entries out in columns, with FOLDER and TAGS only
// when an entry has one. The words searched for are bolded in names and
// usernames when w is a terminal that allows color.
func writeEntryTable(w io.Writer, entries []password.Entry, words []string) error {
	var folders, tags bool
	for i := range entries {
		folders = folders || entries[i].Folder != ""
		tags = tags || len(entries[i].Tags) > 0
	}
	row := func(name, user, kind, folder, tagList, id string) []string {
		r := []string{name, user, kind}
		if folders {
			r = append(r, folder)
		}
		if tags {
			r = append(r, tagList)
		}
		return append(r, id)
	}
	rows := [][]string{row("NAME", "USERNAME", "KIND", "FOLDER", "TAGS", "ID")}
	for i := range entries {
		e := &entries[i]
		rows = append(rows, row(e.Service, e.Username, kindName(e.Type), e.Folder, strings.Join(e.Tags, " "), e.ID))
	}
	widths := make([]int, len(rows[0]))
	for _, r := range rows {
		for c, cell := range r {
			widths[c] = max(widths[c], utf8.RuneCountInString(cell))
		}
	}
	bold := len(words) > 0 && uiStdoutIsTerminal(w) && os.Getenv("NO_COLOR") == ""
	lower := make([]string, len(words))
	for i, word := range words {
		lower[i] = strings.ToLower(word)
	}
	var sb strings.Builder
	for i, r := range rows {
		sb.WriteString(" ")
		for c, cell := range r {
			shown := cell
			if bold && i > 0 && c < 2 {
				shown = highlightWords(cell, lower)
			}
			sb.WriteString(" " + shown)
			if c < len(r)-1 {
				sb.WriteString(strings.Repeat(" ", widths[c]-utf8.RuneCountInString(cell)+1))
			}
		}
		sb.WriteString("\n")
	}
	_, err := io.WriteString(w, sb.String())
	return err
}

// highlightWords bolds every place a word appears in text, ignoring case.
// Text or words that aren't plain ASCII are left as they are: lowercasing
// can change their byte lengths (Turkish "İ" becomes "i\u0307"), so the
// offsets found in the lowercased text wouldn't fit the original.
func highlightWords(text string, words []string) string {
	if !isASCII(text) {
		return text
	}
	lower := strings.ToLower(text)
	var spans [][2]int
	for _, w := range words {
		if w == "" || !isASCII(w) {
			continue
		}
		for from := 0; ; {
			i := strings.Index(lower[from:], w)
			if i < 0 {
				break
			}
			spans = append(spans, [2]int{from + i, from + i + len(w)})
			from += i + 1
		}
	}
	if len(spans) == 0 {
		return text
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i][0] < spans[j][0] })
	var sb strings.Builder
	at := 0
	for i := 0; i < len(spans); {
		start, end := spans[i][0], spans[i][1]
		for i++; i < len(spans) && spans[i][0] <= end; i++ {
			end = max(end, spans[i][1])
		}
		sb.WriteString(text[at:start] + "\033[1m" + text[start:end] + "\033[0m")
		at = end
	}
	sb.WriteString(text[at:])
	return sb.String()
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// entryArg is e named for a command: its ID, quoted for the shell when
// it needs to be.
func entryArg(e *password.Entry) string {
	return shell.Quote(e.ID)
}

// writeJSON prints v as indented JSON.
func writeJSON(w io.Writer, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON output: %w", err)
	}
	_, err = fmt.Fprintf(w, "%s\n", b)
	return err
}

// valueFlags are the flags that pick what of an entry copy and get take:
// its secret (or code), or its username, URL, or a field.
type valueFlags struct {
	field         string
	username, url bool
}

func (v *valueFlags) register(fs *flag.FlagSet) {
	fs.BoolVar(&v.username, "username", false, "Its username instead")
	fs.BoolVar(&v.url, "url", false, "Its URL instead")
	fs.StringVar(&v.field, "field", "", "A field instead: a custom field's name, or notes")
}

// which is the part named, "" for the secret, or an error for more than
// one.
func (v *valueFlags) which() (string, error) {
	var picked []string
	if v.username {
		picked = append(picked, "username")
	}
	if v.url {
		picked = append(picked, "url")
	}
	if v.field != "" {
		picked = append(picked, v.field)
	}
	if len(picked) > 1 {
		return "", errors.New("take one of --username, --url and --field at a time")
	}
	if len(picked) == 0 {
		return "", nil
	}
	return picked[0], nil
}

// entryValue is what of entry k part names ("" for its secret, or for a
// TOTP entry its current code), for the caller to zero, with how it's said
// ("github (alice)'s password"). Reading a secret is recorded in the audit
// log as being for why.
func entryValue(store *database.Store, k vault.Key, part, why string) ([]byte, string, error) {
	e, err := store.Lookup(k)
	if err != nil {
		return nil, "", err
	}
	name := password.EntryName(k)
	switch strings.ToLower(part) {
	case "":
		if k.Kind == vault.KindTOTP {
			c, err := totpCodesOf(store, &e, why)
			if err != nil {
				return nil, "", err
			}
			return []byte(c.current), name + "'s code", nil
		}
		v, err := store.GetFor(k, "secret, "+why)
		return v, name + "'s " + strings.ToLower(secretLabel(k.Kind)), err
	case "password", "secret":
		v, err := store.GetFor(k, "secret, "+why)
		return v, name + "'s " + strings.ToLower(secretLabel(k.Kind)), err
	case "username":
		if e.Username == "" {
			return nil, "", fmt.Errorf("%s has no username", name)
		}
		return []byte(e.Username), name + "'s username", nil
	case "url":
		if e.URL == "" {
			return nil, "", fmt.Errorf("%s has no URL; add one with: sesh edit %s --url <url>", name, shell.Quote(k.String()))
		}
		return []byte(e.URL), name + "'s URL", nil
	case "notes":
		if k.Kind == vault.KindNote {
			return nil, "", fmt.Errorf("%s is a note: its text is its secret, which sesh copy and get give without --field", name)
		}
		if !e.HasNotes {
			return nil, "", fmt.Errorf("%s has no notes; add them with: sesh edit %s --notes", name, shell.Quote(k.String()))
		}
		d, err := store.Details(k, "notes, "+why)
		if err != nil {
			return nil, "", err
		}
		defer d.Zero()
		return bytes.Clone(d.Notes), name + "'s notes", nil
	}
	i := slices.IndexFunc(e.Fields, func(f vault.Field) bool { return strings.EqualFold(f.Name, part) })
	if i < 0 {
		if len(e.Fields) == 0 {
			return nil, "", fmt.Errorf("%s has no field %q; it has no fields", name, part)
		}
		names := make([]string, len(e.Fields))
		for j, f := range e.Fields {
			names[j] = f.Name
		}
		return nil, "", fmt.Errorf("%s has no field %q; its fields: %s", name, part, strings.Join(names, ", "))
	}
	stored := e.Fields[i].Name
	if !e.Fields[i].Secret {
		return bytes.Clone(e.Fields[i].Value), name + "'s " + stored, nil
	}
	d, err := store.Details(k, "field "+stored+", "+why)
	if err != nil {
		return nil, "", err
	}
	defer d.Zero()
	f, ok := d.Field(stored)
	if !ok {
		return nil, "", fmt.Errorf("%s has no field %q", name, stored)
	}
	return bytes.Clone(f.Value), name + "'s " + stored, nil
}

// totpCodes is a TOTP entry's current and next code, with the seconds the
// current one has left.
type totpCodes struct {
	current, next string
	secondsLeft   int64
}

// totpCodesOf makes e's codes from its key, read for why.
func totpCodesOf(store *database.Store, e *vault.Entry, why string) (totpCodes, error) {
	key, err := store.GetFor(e.Key, "TOTP key, "+why)
	if err != nil {
		return totpCodes{}, err
	}
	defer secure.SecureZeroBytes(key)
	params := e.Settings.TOTP
	current, next, err := totp.GenerateConsecutiveCodesBytesWithParams(key, params)
	if err != nil {
		return totpCodes{}, fmt.Errorf("make a code for %s: %w", password.EntryName(e.Key), err)
	}
	period := int64(30)
	if params.Period > 0 {
		period = int64(params.Period)
	}
	return totpCodes{current: current, next: next, secondsLeft: period - time.Now().Unix()%period}, nil
}

// runCopy is sesh copy: an entry's secret, or its code, to the clipboard.
func runCopy(app *App, args []string) error {
	if len(args) == 0 || isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, copyUsage)
		return err
	}
	fs := flag.NewFlagSet("copy", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	v := addCopyFlags(fs)
	fs.Usage = func() { fmt.Fprintln(app.Stderr, copyUsage) } //nolint:errcheck // usage text
	words, err := parseAnywhere(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	part, err := v.which()
	if err != nil {
		return err
	}
	if len(words) == 0 {
		return errors.New("name the entry: sesh copy <entry>")
	}
	if app.ClipboardCheck != nil {
		if err := app.ClipboardCheck(); err != nil {
			if errors.Is(err, clipboard.ErrNoDisplay) {
				return fmt.Errorf("can't copy: %w; sesh get prints it instead", err)
			}
			return fmt.Errorf("can't copy: %w", err)
		}
	}
	store, err := openFilingStore()
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	k, err := resolveEntry(app, store, words, "")
	if err != nil {
		return err
	}
	value, said, err := entryValue(store, k, part, "to copy it")
	if err != nil {
		return err
	}
	defer secure.SecureZeroBytes(value)
	if err := app.ClipboardCopy(string(value)); err != nil {
		return fmt.Errorf("copy to the clipboard: %w", err)
	}
	msg := "✅ Copied " + said
	if t := app.settings.ClipboardTimeout; t > 0 {
		msg += "; the clipboard clears in " + t.String()
	}
	_, err = fmt.Fprintln(app.Stderr, msg)
	return err
}

// runGet is sesh get: an entry's secret, or its code, printed.
func runGet(app *App, args []string) error {
	if len(args) == 0 || isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, getUsage)
		return err
	}
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	v, asJSON := addGetFlags(fs)
	fs.Usage = func() { fmt.Fprintln(app.Stderr, getUsage) } //nolint:errcheck // usage text
	words, err := parseAnywhere(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	part, err := v.which()
	if err != nil {
		return err
	}
	if len(words) == 0 {
		return errors.New("name the entry: sesh get <entry>")
	}
	store, err := openFilingStore()
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	k, err := resolveEntry(app, store, words, "")
	if err != nil {
		return err
	}
	value, _, err := entryValue(store, k, part, "to print it")
	if err != nil {
		return err
	}
	defer secure.SecureZeroBytes(value)
	if *asJSON {
		out := struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Username string `json:"username,omitempty"`
			Kind     string `json:"kind"`
			Part     string `json:"part"`
			Value    string `json:"value"`
		}{k.String(), k.Service, k.Username, string(k.Kind), cmpOr(part, "secret"), string(value)}
		return writeJSON(app.Stdout, out) //nolint:gosec // --json prints the value asked for by design
	}
	return printValue(app.Stdout, value)
}

// cmpOr is s, or else when s is empty.
func cmpOr(s, orElse string) string {
	if s == "" {
		return orElse
	}
	return s
}

// printValue writes a value asked for to w, ending it with a newline
// unless it has one.
func printValue(w io.Writer, v []byte) error {
	if _, err := w.Write(v); err != nil {
		return err
	}
	if len(v) == 0 || v[len(v)-1] != '\n' {
		_, err := io.WriteString(w, "\n")
		return err
	}
	return nil
}

// runCode is sesh code: a TOTP entry's current code and the time it has.
func runCode(app *App, args []string) error {
	if len(args) == 0 || isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, codeUsage)
		return err
	}
	fs := flag.NewFlagSet("code", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	asJSON := addCodeFlags(fs)
	fs.Usage = func() { fmt.Fprintln(app.Stderr, codeUsage) } //nolint:errcheck // usage text
	words, err := parseAnywhere(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if len(words) == 0 {
		return errors.New("name the TOTP entry: sesh code <entry>")
	}
	store, err := openFilingStore()
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	k, err := resolveEntry(app, store, words, vault.KindTOTP)
	if err != nil {
		return err
	}
	e, err := store.Lookup(k)
	if err != nil {
		return err
	}
	c, err := totpCodesOf(store, &e, "to print a code")
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(app.Stdout, struct {
			ID          string `json:"id"`
			Code        string `json:"code"`
			Next        string `json:"next"`
			SecondsLeft int64  `json:"seconds_left"`
		}{k.String(), c.current, c.next, c.secondsLeft})
	}
	if _, err := fmt.Fprintln(app.Stdout, c.current); err != nil {
		return err
	}
	msg := fmt.Sprintf("%s's code, for %ds more", password.EntryName(k), c.secondsLeft)
	if c.secondsLeft <= 5 {
		msg += "; the next is " + c.next
	}
	_, err = fmt.Fprintln(app.Stderr, msg)
	return err
}

// runOpen is sesh open: an entry's URL, in the browser.
func runOpen(app *App, args []string) error {
	if len(args) == 0 || isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, openUsage)
		return err
	}
	fs := flag.NewFlagSet("open", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	fs.Usage = func() { fmt.Fprintln(app.Stderr, openUsage) } //nolint:errcheck // usage text
	words, err := parseAnywhere(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	store, err := openFilingStore()
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	k, err := resolveEntry(app, store, words, "")
	if err != nil {
		return err
	}
	e, err := store.Lookup(k)
	if err != nil {
		return err
	}
	if e.URL == "" {
		return fmt.Errorf("%s has no URL; add one with: sesh edit %s --url <url>", password.EntryName(k), shell.Quote(k.String()))
	}
	if err := openURL(e.URL); err != nil {
		return err
	}
	_, err = fmt.Fprintln(app.Stderr, "Opened "+e.URL)
	return err
}

// runGenerate is sesh generate: a new password, stored nowhere.
func runGenerate(app *App, args []string) error {
	if len(args) > 0 && isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, generateUsage)
		return err
	}
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	length, noSymbols, toClipboard := addGenerateFlags(fs)
	fs.Usage = func() { fmt.Fprintln(app.Stderr, generateUsage) } //nolint:errcheck // usage text
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("sesh generate takes no words, got %q; to store one: sesh add password <name> --generate", strings.Join(fs.Args(), " "))
	}
	opts := password.DefaultGenerateOptions()
	opts.Length = *length
	opts.Symbols = !*noSymbols
	pw, err := password.GeneratePassword(opts)
	if err != nil {
		return err
	}
	defer secure.SecureZeroBytes(pw)
	if !*toClipboard {
		return printValue(app.Stdout, pw)
	}
	if err := app.ClipboardCopy(string(pw)); err != nil {
		return fmt.Errorf("copy to the clipboard: %w", err)
	}
	msg := "✅ Copied a new password"
	if t := app.settings.ClipboardTimeout; t > 0 {
		msg += "; the clipboard clears in " + t.String()
	}
	_, err = fmt.Fprintln(app.Stderr, msg)
	return err
}
