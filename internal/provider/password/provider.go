// Package password implements the password manager provider for sesh.
package password

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"golang.org/x/term"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/kdf"
	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/qrcode"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/shell"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// Provider implements ServiceProvider for the password manager.
type Provider struct {
	store  vault.Store
	stdin  io.Reader
	stdout io.Writer
	// lines reads answers from stdin; one reader for every prompt, so a
	// line buffered for one answer isn't lost to the next.
	lines *bufio.Reader

	query      string // search query
	sortBy     string
	username   string
	entryType  string
	action     string // "store", "get", "search", "generate", "export", "import", "totp-store", "totp-generate"
	file       string // file path for export/import
	onConflict string // import conflict strategy: "skip", "overwrite"
	format     string // output format: "table", "json", "csv"
	service    string
	field      string // get: the field to read instead of the secret, from --field
	filing     provider.FilingFlags
	details    provider.DetailsFlags
	pwLength   int // password generation length
	limit      int
	offset     int
	force      bool // skip confirmation
	noSymbols  bool // password generation: exclude symbols
	show       bool // show password instead of clipboard
	// exportKDF is the Argon2id settings for encrypted exports.
	exportKDF kdf.Params
}

var _ provider.ServiceProvider = (*Provider)(nil)

// Package-level seams for TTY/QR interactions that can't be driven through
// the p.stdin/stdout/stderr fields. Tests save + restore these via defer.
var (
	readPassword = func() ([]byte, error) {
		return term.ReadPassword(int(os.Stdin.Fd()))
	}
	stdinIsTerminal = func() bool {
		return term.IsTerminal(int(os.Stdin.Fd()))
	}
	stdoutIsTerminal = func() bool {
		return term.IsTerminal(int(os.Stdout.Fd()))
	}
	scanQRCodeFull = qrcode.ScanQRCodeFull
)

// NewProvider creates a password manager provider over the vault.
func NewProvider(store vault.Store) *Provider {
	return &Provider{
		store:  store,
		stdin:  os.Stdin,
		stdout: os.Stdout,
	}
}

// WithExportKDF sets the Argon2id settings an encrypted export's password
// is stretched with; zero means kdf.Default().
func (p *Provider) WithExportKDF(k kdf.Params) *Provider {
	p.exportKDF = k
	return p
}

func (p *Provider) Name() string         { return "password" }
func (p *Provider) Description() string  { return "Secure password manager" }
func (p *Provider) GetSetupHandler() any { return nil }

// SuppressActionFraming opts out of the app's generic
// "Generating credentials… / Credentials acquired in Xs" wrapper. The
// password provider dispatches many sub-actions (store/search/export/
// import/etc.) that don't fit the acquire-a-time-limited-credential
// framing and produce their own status via DisplayInfo.
func (p *Provider) SuppressActionFraming() bool { return true }

func (p *Provider) SetupFlags(fs provider.FlagSet) error {
	fs.StringVar(&p.action, "action", "", "Action to perform (store, get, generate, search, export, import, totp-store, totp-generate)")
	fs.StringVar(&p.service, "service-name", "", "Service name")
	fs.StringVar(&p.username, "username", "", "Username for the service")
	fs.StringVar(&p.entryType, "entry-type", "", "Entry type filter (password, api_key, totp, secure_note); empty shows all")
	fs.StringVar(&p.query, "query", "", "Search query")
	fs.StringVar(&p.file, "file", "", "File path for export/import (default: stdout/stdin)")
	fs.StringVar(&p.onConflict, "on-conflict", "", "Import conflict strategy: skip, overwrite (default: error)")
	fs.StringVar(&p.sortBy, "sort", "service", "Sort by (service, created_at, updated_at, folder)")
	fs.StringVar(&p.format, "format", "table", "Output format (table, json, csv)")
	fs.BoolVar(&p.show, "show", false, "Show password instead of copying to clipboard")
	fs.BoolVar(&p.force, "force", false, "Skip confirmation prompts")
	fs.BoolVar(&p.noSymbols, "no-symbols", false, "Exclude symbols from generated passwords")
	fs.IntVar(&p.pwLength, "length", 24, "Generated password length")
	fs.IntVar(&p.limit, "limit", 0, "Limit number of results (0 = no limit)")
	fs.IntVar(&p.offset, "offset", 0, "Skip first N results")
	p.filing.Register(fs, filingNarrows)
	p.details.Register(fs)
	return nil
}

// Filing is what --folder and --tag say, for the actions that store.
func (p *Provider) Filing() vault.Filing { return p.filing.Filing() }

// UsesFiling reports whether the action uses --folder and --tag: to file
// the entry it stores, or to narrow the entries it searches or exports.
func (p *Provider) UsesFiling() (bool, string) {
	switch p.action {
	case "store", "generate", "totp-store", "search", "export":
		return true, ""
	}
	return false, "--action store, generate, totp-store, search, or export, or with --list"
}

// filter is the entries --entry-type, --folder, and --tag let through.
func (p *Provider) filter() *password.ListFilter {
	f := p.filing.Filter()
	return &password.ListFilter{
		EntryType: password.EntryType(p.entryType),
		SortBy:    password.SortField(p.sortBy),
		Limit:     p.limit,
		Offset:    p.offset,
		Folder:    f.Folder,
		FolderSet: f.FolderSet,
		Tags:      f.Tags,
	}
}

// filingNarrows is what --folder and --tag narrow here.
const filingNarrows = "--list, search, or export"

// NoMatchHint says why --list, search, or export found nothing, when
// --folder or --tag names what no entry (of --entry-type's kind) has.
func (p *Provider) NoMatchHint() string {
	f := p.filing.Filter()
	f.Kind = password.EntryType(p.entryType)
	among := ""
	if p.entryType != "" {
		among = p.entryType + " entries"
	}
	return provider.NoMatchHint(p.store, &f, among)
}

// scope describes --folder and --tag for a message ("in folder "work""),
// with a leading space; "" without them.
func (p *Provider) scope() string {
	f := p.filing.Filter()
	if s := provider.Scope(&f); s != "" {
		return " " + s
	}
	return ""
}

func (p *Provider) GetFlagInfo() []provider.FlagInfo {
	return append([]provider.FlagInfo{
		{Name: "action", Type: "string", Description: "Action: store, get, generate, search, export, import, totp-store, totp-generate",
			Values: []string{"store", "get", "generate", "search", "export", "import", "totp-store", "totp-generate"}},
		{Name: "service-name", Type: "string", Description: "Service name"},
		{Name: "username", Type: "string", Description: "Username for the service"},
		{Name: "entry-type", Type: "string", Description: "Entry type (password, api_key, totp, secure_note)",
			Values: []string{string(password.EntryTypePassword), string(password.EntryTypeAPIKey), string(password.EntryTypeTOTP), string(password.EntryTypeNote)}},
		{Name: "query", Type: "string", Description: "Search query"},
		{Name: "sort", Type: "string", Description: "Sort by (service, created_at, updated_at, folder)",
			Values: []string{string(password.SortByService), string(password.SortByCreatedAt), string(password.SortByUpdatedAt), string(password.SortByFolder)}},
		{Name: "format", Type: "string", Description: "Output format (table, json, csv)",
			Values: []string{"table", "json", "csv", "encrypted"}},
		{Name: "file", Type: "string", Description: "File path for export/import (default: stdout/stdin)", Path: true},
		{Name: "on-conflict", Type: "string", Description: "Import conflict strategy: skip, overwrite",
			Values: []string{string(password.ConflictSkip), string(password.ConflictOverwrite)}},
		{Name: "show", Type: "bool", Description: "Show password instead of copying to clipboard"},
		{Name: "force", Type: "bool", Description: "Skip confirmation prompts"},
		{Name: "no-symbols", Type: "bool", Description: "Exclude symbols from generated passwords"},
		{Name: "length", Type: "int", Description: "Generated password length (default 24)"},
		{Name: "limit", Type: "int", Description: "Limit number of results (0 = no limit)"},
		{Name: "offset", Type: "int", Description: "Skip first N results"},
	}, append(p.filing.FlagInfo(filingNarrows), p.details.FlagInfo()...)...)
}

func (p *Provider) ValidateRequest() error {
	if err := p.checkEntryType(); err != nil {
		return err
	}
	switch p.action {
	case "store":
		if p.service == "" {
			return fmt.Errorf("--service-name is required for store action")
		}
	case "get":
		if p.service == "" {
			return fmt.Errorf("--service-name is required for get action")
		}
	case "search":
		if p.query == "" {
			return fmt.Errorf("--query is required for search action")
		}
	case "totp-store":
		if p.service == "" {
			return fmt.Errorf("--service-name is required for totp-store action")
		}
	case "totp-generate":
		if p.service == "" {
			return fmt.Errorf("--service-name is required for totp-generate action")
		}
	case "generate":
		if p.service == "" {
			return fmt.Errorf("--service-name is required for generate action")
		}
		if p.entryType == string(password.EntryTypeTOTP) {
			store := "sesh --service password --action totp-store --service-name " + shell.Quote(p.service)
			if p.username != "" {
				store += " --username " + shell.Quote(p.username)
			}
			return fmt.Errorf("sesh can't generate a TOTP secret: the service gives you one. Store it with: %s", store)
		}
	case "export", "import":
		if p.format == "table" {
			p.format = "json"
		}
		if p.format != "json" && p.format != "csv" && p.format != "encrypted" {
			return fmt.Errorf("--format for %s must be json, csv, or encrypted, got %q", p.action, p.format)
		}
		if p.action == "import" && p.onConflict != "" && p.onConflict != "skip" && p.onConflict != "overwrite" {
			return fmt.Errorf("--on-conflict must be skip or overwrite, got %q", p.onConflict)
		}
	case "":
		// Default action handled by GetCredentials
	default:
		return fmt.Errorf("unknown action: %q (use store, get, search, generate, export, import, totp-store, totp-generate)", p.action)
	}
	if err := p.checkField(); err != nil {
		return err
	}
	return p.CheckArgs()
}

// checkField reads --field: with get (or --clip), the name of the one
// field to read instead of the secret; with store, fields to set, as the
// other details flags do. Other actions take neither.
func (p *Provider) checkField() error {
	fields := p.details.Fields()
	switch {
	case p.action == "store":
		return nil
	case p.details.GivenBesidesField() || (len(fields) > 0 && p.action != "get" && p.action != ""):
		return errors.New("--url, --notes and the field flags work with --action store, or with sesh edit; --field also works with --action get, to read one field")
	case len(fields) > 1:
		return errors.New("get reads one field: give --field once")
	case len(fields) == 1:
		p.field = fields[0]
	}
	if p.field == "" {
		return nil
	}
	if slices.Contains(vault.ReservedFieldNames, strings.ToLower(p.field)) {
		return nil
	}
	return vault.CheckFieldName(p.field)
}

// CheckArgs refuses arguments that are wrong without looking at the vault
// (a name no entry can have, a negative --limit or --offset), so the CLI
// can stop before opening it.
func (p *Provider) CheckArgs() error {
	if err := p.checkListNumbers(); err != nil {
		return err
	}
	return p.checkName()
}

// CheckListArgs refuses what --list and --delete can't use: the details
// flags, or what checkListNumbers refuses.
func (p *Provider) CheckListArgs() error {
	if p.details.Given() {
		return errors.New("--field and the other details flags don't go with --list or --delete; --field reads a field with --action get or --clip")
	}
	return p.checkListNumbers()
}

// checkListNumbers refuses a negative --limit or --offset, or an unknown
// --sort.
func (p *Provider) checkListNumbers() error {
	switch password.SortField(p.sortBy) {
	case "", password.SortByService, password.SortByCreatedAt, password.SortByUpdatedAt, password.SortByFolder:
	default:
		return fmt.Errorf("unknown --sort %q: use service, created_at, updated_at, or folder", p.sortBy)
	}
	if p.limit < 0 {
		return fmt.Errorf("--limit wants 0 (no limit) or more, got %d", p.limit)
	}
	if p.offset < 0 {
		return fmt.Errorf("--offset wants 0 or more, got %d", p.offset)
	}
	return nil
}

// checkName refuses a name no entry can have, so an action that names an
// entry says why at once. It needs no vault, so it runs before the vault
// opens (see CheckArgs).
func (p *Provider) checkName() error {
	kind := p.effectiveEntryType()
	switch p.action {
	case "", "store", "generate", "get": // "" is --clip, which gets the entry
	case "totp-store", "totp-generate":
		kind = password.EntryTypeTOTP
	default:
		return nil
	}
	if p.service == "" {
		return nil // reported by ValidateRequest
	}
	return vault.Key{Kind: kind, Service: p.service, Username: p.username}.Validate()
}

// GetCredentials handles the main operation based on --action flag.
func (p *Provider) GetCredentials() (provider.Credentials, error) {
	mgr := password.NewManager(p.store)

	switch p.action {
	case "store":
		return p.storePassword(mgr)
	case "get":
		return p.getPassword(mgr)
	case "search":
		return p.searchPasswords(mgr)
	case "generate":
		return p.generatePassword(mgr)
	case "export":
		return p.exportEntries(mgr)
	case "import":
		return p.importEntries(mgr)
	case "totp-store":
		return p.storeTOTP(mgr)
	case "totp-generate":
		creds, err := p.generateTOTP(mgr)
		if err != nil {
			return provider.Credentials{}, err
		}
		return provider.Credentials{Provider: p.Name()}, p.printValue([]byte(creds.CopyValue))
	default:
		return provider.Credentials{}, fmt.Errorf("specify --action (store, get, search, generate, export, import, totp-store, totp-generate) or use --list, --delete")
	}
}

// CheckClip refuses --clip for an action with nothing to copy.
func (p *Provider) CheckClip() error {
	switch p.action {
	case "", "get", "generate", "totp-generate":
		return nil
	}
	return fmt.Errorf("--clip works with --action get, generate, or totp-generate, not %s", p.action)
}

// GetClipboardValue returns what --clip copies for the action: the stored
// secret for get (the default), a newly generated and stored password for
// generate, or the current code for totp-generate. Other actions have
// nothing to copy.
func (p *Provider) GetClipboardValue() (provider.Credentials, error) {
	if err := p.CheckClip(); err != nil {
		return provider.Credentials{}, err
	}
	if p.service == "" {
		return provider.Credentials{}, fmt.Errorf("--service-name is required")
	}

	mgr := password.NewManager(p.store)
	switch p.action {
	case "generate":
		generated, desc, err := p.generateAndStore(mgr)
		if err != nil {
			return provider.Credentials{}, err
		}
		defer secure.SecureZeroBytes(generated)
		return provider.Credentials{
			Provider:             p.Name(),
			CopyValue:            string(generated),
			ClipboardDescription: fmt.Sprintf("generated %s for %s", p.effectiveEntryType(), desc),
			DisplayInfo:          fmt.Sprintf("✅ Generated and stored %s for %s", p.effectiveEntryType(), desc),
		}, nil
	case "totp-generate":
		return p.generateTOTP(mgr)
	}
	if p.field != "" {
		value, name, err := p.fieldValue()
		if err != nil {
			return provider.Credentials{}, err
		}
		defer secure.SecureZeroBytes(value)
		return provider.Credentials{
			Provider:             p.Name(),
			CopyValue:            string(value),
			ClipboardDescription: fmt.Sprintf("field %s of %s", name, p.desc()),
		}, nil
	}
	et := p.effectiveEntryType()

	secretBytes, err := mgr.GetPassword(p.service, p.username, et)
	if err != nil {
		return provider.Credentials{}, err
	}
	defer secure.SecureZeroBytes(secretBytes)

	return provider.Credentials{
		Provider:             p.Name(),
		CopyValue:            string(secretBytes),
		ClipboardDescription: fmt.Sprintf("%s for %s", et, p.desc()),
	}, nil
}

// desc names the entry for a message: "github", or "github (alice)".
func (p *Provider) desc() string {
	if p.username == "" {
		return p.service
	}
	return fmt.Sprintf("%s (%s)", p.service, p.username)
}

// fieldValue reads --field of the entry: the secret for password or
// secret, its URL, its notes, or a custom field, found in any case. It
// returns the value, which the caller zeroes, and the name it's stored
// under.
func (p *Provider) fieldValue() ([]byte, string, error) {
	k := vault.Key{Kind: p.effectiveEntryType(), Service: p.service, Username: p.username}
	name := strings.ToLower(p.field)
	if name == "password" || name == "secret" {
		v, err := password.NewManager(p.store).GetPassword(p.service, p.username, k.Kind)
		return v, name, err
	}
	e, err := p.store.Lookup(k)
	if err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			if h := password.CaseHint(p.store, k); h != "" {
				err = fmt.Errorf("%w; %s", err, h)
			}
		}
		return nil, "", err
	}
	switch name {
	case "url":
		if e.URL == "" {
			return nil, "", fmt.Errorf("%s has no URL; add one with: sesh edit %s --url <url>", k, shell.Quote(k.String()))
		}
		return []byte(e.URL), name, nil
	case "notes":
		if k.Kind == vault.KindNote {
			return nil, "", fmt.Errorf("%s is a secure note: its note is its secret, which --field secret reads", k)
		}
		if !e.HasNotes {
			return nil, "", fmt.Errorf("%s has no notes; add them with: sesh edit %s --notes", k, shell.Quote(k.String()))
		}
		d, err := p.store.Details(k, "notes")
		if err != nil {
			return nil, "", err
		}
		defer d.Zero()
		return bytes.Clone(d.Notes), name, nil
	}
	i := slices.IndexFunc(e.Fields, func(f vault.Field) bool { return strings.EqualFold(f.Name, p.field) })
	if i < 0 {
		if len(e.Fields) == 0 {
			return nil, "", fmt.Errorf("%s has no field %q; it has no fields", k, p.field)
		}
		names := make([]string, len(e.Fields))
		for j, f := range e.Fields {
			names[j] = f.Name
		}
		return nil, "", fmt.Errorf("%s has no field %q; its fields: %s", k, p.field, strings.Join(names, ", "))
	}
	stored := e.Fields[i].Name
	if !e.Fields[i].Secret {
		return e.Fields[i].Value, stored, nil
	}
	d, err := p.store.Details(k, "field "+stored)
	if err != nil {
		return nil, "", err
	}
	defer d.Zero()
	f, ok := d.Field(stored)
	if !ok {
		return nil, "", fmt.Errorf("%s has no field %q", k, stored)
	}
	return bytes.Clone(f.Value), stored, nil
}

// getField is get --field: the value shown, as JSON, or offered to copy.
func (p *Provider) getField() (provider.Credentials, error) {
	value, name, err := p.fieldValue()
	if err != nil {
		return provider.Credentials{}, err
	}
	defer secure.SecureZeroBytes(value)
	switch {
	case p.format == "json":
		out := struct {
			Service  string `json:"service"`
			Username string `json:"username,omitempty"`
			Type     string `json:"type"`
			Field    string `json:"field"`
			Value    string `json:"value"`
		}{p.service, p.username, string(p.effectiveEntryType()), name, string(value)}
		b, err := json.MarshalIndent(out, "", "  ") //nolint:gosec // --format json prints the requested field by design
		if err != nil {
			return provider.Credentials{}, fmt.Errorf("marshal JSON output: %w", err)
		}
		return provider.Credentials{Provider: p.Name()}, p.printValue(b)
	case p.show:
		return provider.Credentials{Provider: p.Name()}, p.printValue(value)
	}
	return provider.Credentials{
		Provider:             p.Name(),
		CopyValue:            string(value),
		ClipboardDescription: fmt.Sprintf("field %s of %s", name, p.desc()),
		DisplayInfo:          "💡 Use --show to display it, or --clip to copy",
	}, nil
}

// ListEntries returns all password manager entries.
func (p *Provider) ListEntries() ([]provider.ProviderEntry, error) {
	if err := p.checkEntryType(); err != nil {
		return nil, err
	}
	mgr := password.NewManager(p.store)

	entries, err := mgr.ListEntriesFiltered(p.filter())
	if err != nil {
		return nil, err
	}

	result := make([]provider.ProviderEntry, 0, len(entries))
	for i := range entries {
		e := &entries[i]
		name := e.Service
		if e.Username != "" {
			name = fmt.Sprintf("%s (%s)", e.Service, e.Username)
		}
		result = append(result, provider.ProviderEntry{
			Name:   name,
			Type:   string(e.Type),
			ID:     e.ID,
			Folder: e.Folder,
			Tags:   e.Tags,
		})
	}
	return result, nil
}

// DeleteForced reports whether --force says to delete without asking.
func (p *Provider) DeleteForced() bool { return p.force }

// DeleteEntries deletes the entries ids name, of any kind, asking first
// unless --force.
func (p *Provider) DeleteEntries(ids []string, confirm provider.ConfirmDelete) (int, error) {
	return provider.DeleteEntries(p.store, ids, nil, p.caseHint, p.force, confirm)
}

// checkEntryType refuses an --entry-type that isn't one of the kinds: an
// entry stored under an unknown kind would never be listed or found.
func (p *Provider) checkEntryType() error {
	if p.entryType == "" || password.EntryType(p.entryType).Valid() {
		return nil
	}
	return fmt.Errorf("unknown --entry-type %q: use password, api_key, totp, or secure_note", p.entryType)
}

// noMatch is ": " and the hint when n is zero and there is one.
func noMatch(n int, hint func() string) string {
	if n > 0 {
		return ""
	}
	if h := hint(); h != "" {
		return ": " + h
	}
	return ""
}

// --- action implementations ---

func (p *Provider) effectiveEntryType() password.EntryType {
	if p.entryType == "" {
		return password.EntryTypePassword
	}
	return password.EntryType(p.entryType)
}

func (p *Provider) storePassword(mgr *password.Manager) (provider.Credentials, error) {
	et := p.effectiveEntryType()
	terminal := stdinIsTerminal()
	change, err := p.details.Change(et, et, terminal)
	if err != nil {
		return provider.Credentials{}, err
	}
	if !terminal && change != nil {
		fromStdin := p.details.FromStdin()
		if et == password.EntryTypeNote {
			fromStdin++
		}
		if fromStdin > 1 {
			return provider.Credentials{}, errors.New("without a terminal, only one value can come from stdin: store the entry, then add the rest with sesh edit")
		}
	}

	// What the details change can't do to the entry it replaces (or a new
	// one) is refused before anything is asked.
	if change != nil {
		current, err := p.store.Lookup(vault.Key{Kind: et, Service: p.service, Username: p.username})
		if err != nil && !errors.Is(err, vault.ErrNotFound) {
			return provider.Credentials{}, err
		}
		if err := provider.CheckAgainst(&current, change); err != nil {
			return provider.Credentials{}, err
		}
	}

	if err := p.confirmSave(mgr, et); err != nil {
		return provider.Credentials{}, err
	}

	// Read input — method depends on entry type
	var pw []byte
	if et == password.EntryTypeNote {
		// Secure notes: read multi-line from stdin until EOF. Works with
		// pipes (echo "..." | sesh ...) and heredocs. Only show the
		// prompt when stdin is an interactive terminal — for piped input
		// the content is already queued and a "please type" prompt would
		// be misleading.
		if stdinIsTerminal() {
			fmt.Fprintf(os.Stderr, "Enter note for %s (end with Ctrl+D):\n", p.service)
		}
		var err error
		// Read no more than an entry can hold, plus one byte to tell.
		pw, err = io.ReadAll(io.LimitReader(p.stdin, database.MaxSecretSize+1))
		if err != nil {
			return provider.Credentials{}, fmt.Errorf("failed to read note: %w", err)
		}
		if len(pw) > database.MaxSecretSize {
			secure.SecureZeroBytes(pw)
			return provider.Credentials{}, fmt.Errorf("the note is over %d bytes, the most an entry holds", database.MaxSecretSize)
		}
	} else {
		// Passwords/API keys: hidden single-line input
		fmt.Fprintf(os.Stderr, "Enter %s for %s", et, p.service)
		if p.username != "" {
			fmt.Fprintf(os.Stderr, " (%s)", p.username)
		}
		fmt.Fprintf(os.Stderr, ": ")
		var err error
		pw, err = readPassword()
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return provider.Credentials{}, fmt.Errorf("failed to read %s: %w", et, err)
		}
	}
	defer secure.SecureZeroBytes(pw)

	if change != nil {
		defer provider.ZeroChange(change)
		k := vault.Key{Kind: et, Service: p.service, Username: p.username}
		in := &provider.DetailsInput{
			Stdin: p.stdin, Stderr: os.Stderr, ReadSecret: readPassword, Name: k.String(), Terminal: terminal, KeepNotes: true,
			Notes: func() ([]byte, error) { return mgr.Notes(k) },
		}
		// Notes ended at once at a terminal leave the notes as they are.
		if err := p.details.Read(change, in); errors.Is(err, provider.ErrNothingTyped) {
			change.SetNotes = false
		} else if err != nil {
			return provider.Credentials{}, err
		}
	}
	if err := mgr.StorePasswordWithDetails(p.service, p.username, pw, et, p.Filing(), change); err != nil {
		return provider.Credentials{}, err
	}
	// A typed password only; API keys and notes come from elsewhere.
	if et == password.EntryTypePassword && password.IsWeak(pw, p.service, p.username) {
		generate := "sesh --service password --action generate --service-name " + shell.Quote(p.service)
		if p.username != "" {
			generate += " --username " + shell.Quote(p.username)
		}
		warnWeak(et, "run: "+generate)
	}

	return provider.Credentials{
		Provider:    p.Name(),
		DisplayInfo: fmt.Sprintf("✅ Stored %s for %s", et, p.service),
	}, nil
}

// generateAndStore generates a password with the requested options and
// stores it, returning it (for the caller to zero) and the entry's
// description, "service (username)".
func (p *Provider) generateAndStore(mgr *password.Manager) ([]byte, string, error) {
	if err := p.confirmSave(mgr, p.effectiveEntryType()); err != nil {
		return nil, "", err
	}
	opts := password.DefaultGenerateOptions()
	opts.Length = p.pwLength
	if p.noSymbols {
		opts.Symbols = false
	}

	generated, err := password.GeneratePassword(opts)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate password: %w", err)
	}
	if err := mgr.StorePassword(p.service, p.username, generated, p.effectiveEntryType(), p.Filing()); err != nil {
		secure.SecureZeroBytes(generated)
		return nil, "", err
	}
	// Only a short --length makes one weak; the default never is.
	if password.IsWeak(generated, p.service, p.username) {
		warnWeak(p.effectiveEntryType(), "use --length 12 or more")
	}

	desc := p.service
	if p.username != "" {
		desc = fmt.Sprintf("%s (%s)", p.service, p.username)
	}
	return generated, desc, nil
}

func (p *Provider) generatePassword(mgr *password.Manager) (provider.Credentials, error) {
	generated, desc, err := p.generateAndStore(mgr)
	if err != nil {
		return provider.Credentials{}, err
	}
	// Zero the generator's raw buffer once we're done. Downstream string
	// copies (JSON, CopyValue) can't be zeroed — that's a broader API issue —
	// but we can at least avoid leaving the pre-copy buffer on the heap.
	defer secure.SecureZeroBytes(generated)
	et := p.effectiveEntryType()

	if p.format == "json" {
		out := struct {
			Service  string `json:"service"`
			Username string `json:"username,omitempty"`
			Type     string `json:"type"`
			Password string `json:"password"`
		}{
			Service:  p.service,
			Username: p.username,
			Type:     string(et),
			Password: string(generated),
		}
		b, err := json.MarshalIndent(out, "", "  ") //nolint:gosec // --format json prints the generated password by design
		if err != nil {
			return provider.Credentials{}, fmt.Errorf("marshal JSON output: %w", err)
		}
		return provider.Credentials{Provider: p.Name()}, p.printValue(b)
	}

	if p.show {
		// Print the generated password so the user can actually use it.
		// Without --show the value only reaches the user via --clip or
		// a follow-up `get --show`, which is a strange default for an
		// explicitly-interactive `generate` invocation.
		return provider.Credentials{
			Provider:    p.Name(),
			DisplayInfo: fmt.Sprintf("✅ Generated and stored %s for %s", et, desc),
		}, p.printValue(generated)
	}

	return provider.Credentials{
		Provider:             p.Name(),
		CopyValue:            string(generated),
		ClipboardDescription: fmt.Sprintf("generated password for %s", desc),
		DisplayInfo:          fmt.Sprintf("✅ Generated and stored %s for %s\n💡 Use --show to display it or --clip to copy", et, desc),
	}, nil
}

func (p *Provider) getPassword(mgr *password.Manager) (provider.Credentials, error) {
	if p.field != "" {
		return p.getField()
	}
	et := p.effectiveEntryType()

	secretBytes, err := mgr.GetPassword(p.service, p.username, et)
	if err != nil {
		return provider.Credentials{}, err
	}
	defer secure.SecureZeroBytes(secretBytes)

	if p.format == "json" {
		e, err := mgr.LookupEntry(p.service, p.username, et)
		if err != nil {
			return provider.Credentials{}, err
		}
		out := struct {
			Service  string   `json:"service"`
			Username string   `json:"username,omitempty"`
			Type     string   `json:"type"`
			Folder   string   `json:"folder,omitempty"`
			Password string   `json:"password"`
			Tags     []string `json:"tags,omitempty"`
		}{
			Service:  p.service,
			Username: p.username,
			Type:     string(et),
			Folder:   e.Folder,
			Tags:     e.Tags,
			Password: string(secretBytes),
		}
		b, err := json.MarshalIndent(out, "", "  ") //nolint:gosec // --format json prints the requested password by design
		if err != nil {
			return provider.Credentials{}, fmt.Errorf("marshal JSON output: %w", err)
		}
		return provider.Credentials{Provider: p.Name()}, p.printValue(b)
	}

	if p.show {
		return provider.Credentials{Provider: p.Name()}, p.printValue(secretBytes)
	}

	desc := p.service
	if p.username != "" {
		desc = fmt.Sprintf("%s (%s)", p.service, p.username)
	}

	return provider.Credentials{
		Provider:             p.Name(),
		CopyValue:            string(secretBytes),
		ClipboardDescription: fmt.Sprintf("%s for %s", et, desc),
		DisplayInfo:          "💡 Use --show to display the password, or --clip to copy",
	}, nil
}

func (p *Provider) storeTOTP(mgr *password.Manager) (provider.Credentials, error) {
	// Offer QR code scanning option
	fmt.Fprintln(os.Stderr, "How would you like to provide the TOTP secret?")
	fmt.Fprintln(os.Stderr, "  1) Enter manually")
	fmt.Fprintln(os.Stderr, "  2) Scan QR code from screen")
	fmt.Fprintf(os.Stderr, "Choose [1/2]: ")

	answer, err := p.readLine()
	if err != nil {
		return provider.Credentials{}, fmt.Errorf("read input: %w", err)
	}
	answer = strings.TrimSpace(answer)

	// Ask before replacing an existing secret, before it's captured. When
	// the username may still come from the QR code, ask after the scan.
	asked := answer != "2" || p.username != ""
	if asked {
		if err := p.confirmSave(mgr, password.EntryTypeTOTP); err != nil {
			return provider.Credentials{}, err
		}
	}

	var secret string
	var params totp.Params

	switch answer {
	case "2":
		info, err := scanQRCodeFull()
		if err != nil {
			return provider.Credentials{}, fmt.Errorf("QR code scan failed: %w", err)
		}
		secret = info.Secret
		params = totp.Params{
			Issuer:    info.Issuer,
			Algorithm: info.Algorithm,
			Digits:    info.Digits,
			Period:    info.Period,
		}
		// The Key URI Format labels an entry as "issuer:account"; if the
		// user didn't pass --username explicitly, inherit the account
		// from the QR so it's stored/indexed under the right identity
		// rather than an empty username. An explicit flag always wins.
		if p.username == "" && info.Account != "" {
			p.username = info.Account
			// Checked like a --username, before anything is stored.
			if err := p.checkName(); err != nil {
				return provider.Credentials{}, fmt.Errorf("the QR code's account name can't be used: %w; choose one with --username", err)
			}
		}
		if !asked {
			if err := p.confirmSave(mgr, password.EntryTypeTOTP); err != nil {
				return provider.Credentials{}, err
			}
		}
		fmt.Fprintf(os.Stderr, "✅ QR code scanned successfully\n")
		if info.Issuer != "" {
			fmt.Fprintf(os.Stderr, "   Issuer: %s\n", info.Issuer)
		}
		if info.Account != "" {
			fmt.Fprintf(os.Stderr, "   Account: %s\n", info.Account)
		}
	default:
		fmt.Fprintf(os.Stderr, "Enter TOTP secret for %s", p.service)
		if p.username != "" {
			fmt.Fprintf(os.Stderr, " (%s)", p.username)
		}
		fmt.Fprintf(os.Stderr, ": ")

		secretBytes, err := readPassword()
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return provider.Credentials{}, fmt.Errorf("failed to read TOTP secret: %w", err)
		}
		defer secure.SecureZeroBytes(secretBytes)
		secret = string(secretBytes)
	}

	if err := mgr.StoreTOTPSecretWithParams(p.service, p.username, secret, params, p.Filing()); err != nil {
		return provider.Credentials{}, err
	}

	display := fmt.Sprintf("✅ Stored TOTP secret for %s", p.service)
	if !params.IsDefault() {
		display += fmt.Sprintf(" (algorithm=%s, digits=%d, period=%ds)",
			params.Algorithm, params.Digits, params.Period)
	}

	return provider.Credentials{
		Provider:    p.Name(),
		DisplayInfo: display,
	}, nil
}

func (p *Provider) generateTOTP(mgr *password.Manager) (provider.Credentials, error) {
	code, err := mgr.GenerateTOTPCode(p.service, p.username)
	if err != nil {
		return provider.Credentials{}, err
	}

	desc := p.service
	if p.username != "" {
		desc = fmt.Sprintf("%s (%s)", p.service, p.username)
	}

	return provider.Credentials{
		Provider:             p.Name(),
		CopyValue:            code,
		ClipboardDescription: fmt.Sprintf("TOTP code for %s", desc),
		DisplayInfo:          fmt.Sprintf("TOTP code: %s", code),
	}, nil
}

// printValue writes a value the user asked for (a secret, a code, or JSON)
// to stdout, so it can be captured or piped, ending it with a newline
// unless it has one. Messages about it go to stderr, through DisplayInfo.
func (p *Provider) printValue(v []byte) error {
	if _, err := p.stdout.Write(v); err != nil {
		return fmt.Errorf("write to stdout: %w", err)
	}
	if len(v) == 0 || v[len(v)-1] != '\n' {
		if _, err := io.WriteString(p.stdout, "\n"); err != nil {
			return fmt.Errorf("write to stdout: %w", err)
		}
	}
	return nil
}

// readExportPassword prompts for a password used to encrypt/decrypt an
// export envelope. When confirm is true, requires the password be entered
// twice and match.
func (p *Provider) readExportPassword(label string, confirm bool) ([]byte, error) {
	fmt.Fprintf(os.Stderr, "%s: ", label)
	pw, err := readPassword()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}
	if len(pw) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	if confirm {
		fmt.Fprintf(os.Stderr, "Confirm %s: ", label)
		pw2, err := readPassword()
		fmt.Fprintln(os.Stderr)
		if err != nil {
			secure.SecureZeroBytes(pw)
			return nil, fmt.Errorf("read confirmation: %w", err)
		}
		if !bytes.Equal(pw, pw2) {
			secure.SecureZeroBytes(pw)
			secure.SecureZeroBytes(pw2)
			return nil, fmt.Errorf("passwords do not match")
		}
		secure.SecureZeroBytes(pw2)
	}

	return pw, nil
}

func (p *Provider) exportEntries(mgr *password.Manager) (provider.Credentials, error) {
	// A filter that matches nothing is likely a typo (folders and tags are
	// case-sensitive): fail before --file is emptied or a password asked
	// for.
	if filter := p.filter(); p.entryType != "" || filter.FolderSet || len(filter.Tags) > 0 {
		filter.Limit, filter.Offset = 1, 0
		found, err := mgr.ListEntriesFiltered(filter)
		if err != nil {
			return provider.Credentials{}, err
		}
		if len(found) == 0 {
			kind := ""
			if p.entryType != "" {
				kind = p.entryType + " "
			}
			return provider.Credentials{}, fmt.Errorf("no %sentries%s, so nothing was exported%s", kind, p.scope(), noMatch(0, p.NoMatchHint))
		}
	}
	f := p.filing.Filter()
	opts := &password.ExportOptions{
		EntryType: password.EntryType(p.entryType),
		Folder:    f.Folder,
		FolderSet: f.FolderSet,
		Tags:      f.Tags,
	}

	// Default export target is p.stdout so callers can redirect with
	// `sesh ... --action export > backup.json`. Status text is returned
	// via DisplayInfo, which the caller routes to stderr; keeping status
	// off stdout preserves the data stream for shell redirection.
	w := p.stdout
	dest := "stdout"
	if p.file != "" {
		f, err := os.OpenFile(p.file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return provider.Credentials{}, fmt.Errorf("create export file: %w", err)
		}
		defer func() {
			if cerr := f.Close(); cerr != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to close export file: %v\n", cerr)
			}
		}()
		w = f
		dest = p.file
	}

	var count int
	var err error

	if p.format == "encrypted" {
		pw, perr := p.readExportPassword("Encryption password", true)
		if perr != nil {
			return provider.Credentials{}, perr
		}
		defer secure.SecureZeroBytes(pw)
		opts.KDF = p.exportKDF
		count, err = mgr.ExportEncrypted(w, opts, pw)
	} else {
		opts.Format = password.FormatJSON
		if p.format == "csv" {
			opts.Format = password.FormatCSV
		}
		count, err = mgr.Export(w, opts)
	}
	if err != nil {
		return provider.Credentials{}, err
	}

	return provider.Credentials{
		Provider:    p.Name(),
		DisplayInfo: fmt.Sprintf("Exported %s to %s", entryCount(count), dest),
	}, nil
}

func (p *Provider) importEntries(mgr *password.Manager) (provider.Credentials, error) {
	opts := password.ImportOptions{
		OnConflict: password.ConflictStrategy(p.onConflict),
	}

	var r io.Reader
	if p.file != "" {
		f, err := os.Open(p.file)
		if err != nil {
			return provider.Credentials{}, fmt.Errorf("open import file: %w", err)
		}
		defer func() {
			if cerr := f.Close(); cerr != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to close import file: %v\n", cerr)
			}
		}()
		r = f
	} else {
		r = p.stdin
	}

	var result password.ImportResult
	var err error

	if p.format == "encrypted" {
		pw, perr := p.readExportPassword("Decryption password", false)
		if perr != nil {
			return provider.Credentials{}, perr
		}
		defer secure.SecureZeroBytes(pw)
		result, err = mgr.ImportEncrypted(r, opts, pw)
	} else {
		opts.Format = password.FormatJSON
		if p.format == "csv" {
			opts.Format = password.FormatCSV
		}
		result, err = mgr.Import(r, opts)
	}
	if err != nil {
		return provider.Credentials{}, err
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Imported %s", entryCount(result.Imported))
	if result.Skipped > 0 {
		fmt.Fprintf(&sb, ", skipped %d", result.Skipped)
	}
	if len(result.Errors) > 0 {
		fmt.Fprintf(&sb, ", %s:", countOf(len(result.Errors), "error"))
		for _, e := range result.Errors {
			fmt.Fprintf(&sb, "\n  %s", e)
		}
	}

	return provider.Credentials{
		Provider:    p.Name(),
		DisplayInfo: sb.String(),
	}, nil
}

// entryCount says how many entries, as "1 entry" or "n entries".
func entryCount(n int) string {
	if n == 1 {
		return "1 entry"
	}
	return fmt.Sprintf("%d entries", n)
}

// countOf says how many of a thing, as "1 error" or "n errors".
func countOf(n int, thing string) string {
	if n == 1 {
		return "1 " + thing
	}
	return fmt.Sprintf("%d %ss", n, thing)
}

// warnWeak tells the user the secret of kind et just stored is easy to
// guess, and how to get a strong one.
func warnWeak(et password.EntryType, fix string) {
	what := map[password.EntryType]string{password.EntryTypeAPIKey: "API key", password.EntryTypeNote: "note"}[et]
	if what == "" {
		what = "password"
	}
	fmt.Fprintf(os.Stderr, "⚠️  This %s is easy to guess: a cracking program would likely find it in under 100 million tries. It's stored; for a strong one, %s\n", what, fix) //nolint:errcheck // best-effort warning
}

// confirmSave asks before p.action saves the entry, unless --force: when it
// would replace an existing entry, or make a second one whose name differs
// from an existing one only in case. Without a terminal it refuses instead:
// an "answer" read from piped stdin would swallow the piped input (a note's
// body, say).
func (p *Provider) confirmSave(mgr *password.Manager, et password.EntryType) error {
	if p.force {
		return nil
	}
	k := vault.Key{Kind: et, Service: p.service, Username: p.username}
	exists, err := mgr.EntryExists(p.service, p.username, et)
	if err != nil {
		return fmt.Errorf("check existing entry: %w", err)
	}
	name := password.EntryName(k)
	var refusal, question string
	if exists {
		refusal = fmt.Sprintf("entry already exists for %s; re-run with --force to overwrite", name)
		question = fmt.Sprintf("Entry already exists for %s. Overwrite? [y/N]: ", name)
	} else {
		twins, err := mgr.CaseTwins(k)
		if err != nil {
			return fmt.Errorf("check existing entries: %w", err)
		}
		if len(twins) == 0 {
			return nil
		}
		twin := password.EntryName(twins[0])
		refusal = fmt.Sprintf("an entry %s already exists, and names are case-sensitive; use that name, or re-run with --force to create %s too", twin, name)
		question = fmt.Sprintf("An entry %s already exists, and names are case-sensitive. Create %s as well? [y/N]: ", twin, name)
	}
	if !stdinIsTerminal() {
		return errors.New(refusal)
	}
	fmt.Fprint(os.Stderr, question) //nolint:errcheck // best-effort prompt
	answer, err := p.readLine()
	if err != nil {
		return fmt.Errorf("read confirmation: %w", err)
	}
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(answer)), "y") {
		return fmt.Errorf("%s cancelled", p.action)
	}
	return nil
}

// readLine reads one line of an answer from stdin.
func (p *Provider) readLine() (string, error) {
	if p.lines == nil {
		p.lines = bufio.NewReader(p.stdin)
	}
	return p.lines.ReadString('\n')
}

// caseHint names the entries k misses only by case, or is "".
func (p *Provider) caseHint(k vault.Key) string {
	return password.CaseHint(p.store, k)
}
