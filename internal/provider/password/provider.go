// Package password implements the password manager provider for sesh.
package password

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/qrcode"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// Provider implements ServiceProvider for the password manager.
type Provider struct {
	store  vault.Store
	stdin  io.Reader
	stdout io.Writer

	query      string // search query
	sortBy     string
	username   string
	entryType  string
	action     string // "store", "get", "search", "generate", "export", "import", "totp-store", "totp-generate"
	file       string // file path for export/import
	onConflict string // import conflict strategy: "skip", "overwrite"
	format     string // output format: "table", "json", "csv"
	service    string
	pwLength   int // password generation length
	limit      int
	offset     int
	force      bool // skip confirmation
	noSymbols  bool // password generation: exclude symbols
	show       bool // show password instead of clipboard
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
	fs.StringVar(&p.sortBy, "sort", "service", "Sort by (service, created_at, updated_at)")
	fs.StringVar(&p.format, "format", "table", "Output format (table, json, csv)")
	fs.BoolVar(&p.show, "show", false, "Show password instead of copying to clipboard")
	fs.BoolVar(&p.force, "force", false, "Skip confirmation prompts")
	fs.BoolVar(&p.noSymbols, "no-symbols", false, "Exclude symbols from generated passwords")
	fs.IntVar(&p.pwLength, "length", 24, "Generated password length")
	fs.IntVar(&p.limit, "limit", 0, "Limit number of results (0 = no limit)")
	fs.IntVar(&p.offset, "offset", 0, "Skip first N results")
	return nil
}

func (p *Provider) GetFlagInfo() []provider.FlagInfo {
	return []provider.FlagInfo{
		{Name: "action", Type: "string", Description: "Action: store, get, generate, search, export, import, totp-store, totp-generate",
			Values: []string{"store", "get", "generate", "search", "export", "import", "totp-store", "totp-generate"}},
		{Name: "service-name", Type: "string", Description: "Service name"},
		{Name: "username", Type: "string", Description: "Username for the service"},
		{Name: "entry-type", Type: "string", Description: "Entry type (password, api_key, totp, secure_note)",
			Values: []string{string(password.EntryTypePassword), string(password.EntryTypeAPIKey), string(password.EntryTypeTOTP), string(password.EntryTypeNote)}},
		{Name: "query", Type: "string", Description: "Search query"},
		{Name: "sort", Type: "string", Description: "Sort by (service, created_at, updated_at)",
			Values: []string{string(password.SortByService), string(password.SortByCreatedAt), string(password.SortByUpdatedAt)}},
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
	}
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
			store := "sesh --service password --action totp-store --service-name " + shellQuote(p.service)
			if p.username != "" {
				store += " --username " + shellQuote(p.username)
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
	return p.checkName()
}

// CheckNames refuses a service name or username no entry can have, without
// the vault, so the CLI can stop before opening it.
func (p *Provider) CheckNames() error {
	return p.checkName()
}

// checkName refuses a name no entry can have, so an action that names an
// entry says why at once. It needs no vault, so it runs before the vault
// opens (see CheckNames).
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

// GetClipboardValue returns what --clip copies for the action: the stored
// secret for get (the default), a newly generated and stored password for
// generate, or the current code for totp-generate. Other actions have
// nothing to copy.
func (p *Provider) GetClipboardValue() (provider.Credentials, error) {
	switch p.action {
	case "", "get", "generate", "totp-generate":
	default:
		return provider.Credentials{}, fmt.Errorf("--clip works with --action get, generate, or totp-generate, not %s", p.action)
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
	et := p.effectiveEntryType()

	secretBytes, err := mgr.GetPassword(p.service, p.username, et)
	if err != nil {
		return provider.Credentials{}, err
	}
	defer secure.SecureZeroBytes(secretBytes)

	desc := p.service
	if p.username != "" {
		desc = fmt.Sprintf("%s (%s)", p.service, p.username)
	}

	return provider.Credentials{
		Provider:             p.Name(),
		CopyValue:            string(secretBytes),
		ClipboardDescription: fmt.Sprintf("%s for %s", et, desc),
	}, nil
}

// ListEntries returns all password manager entries.
func (p *Provider) ListEntries() ([]provider.ProviderEntry, error) {
	if err := p.checkEntryType(); err != nil {
		return nil, err
	}
	mgr := password.NewManager(p.store)

	filter := password.ListFilter{
		EntryType: password.EntryType(p.entryType),
		SortBy:    password.SortField(p.sortBy),
		Limit:     p.limit,
		Offset:    p.offset,
	}

	entries, err := mgr.ListEntriesFiltered(filter)
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
			Name:        name,
			Description: fmt.Sprintf("[%s]", e.Type),
			ID:          e.ID,
		})
	}
	return result, nil
}

// DeleteEntry deletes a password entry by ID, with confirmation unless --force.
func (p *Provider) DeleteEntry(id string) error {
	k, err := vault.ParseKey(id)
	if err != nil {
		return err
	}
	if !p.force {
		fmt.Fprintf(os.Stderr, "Delete entry %q? [y/N]: ", id)
		answer, err := bufio.NewReader(p.stdin).ReadString('\n')
		if err != nil {
			return fmt.Errorf("read confirmation: %w", err)
		}
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(answer)), "y") {
			return fmt.Errorf("delete cancelled")
		}
	}
	return p.store.Delete(k)
}

// checkEntryType refuses an --entry-type that isn't one of the kinds: an
// entry stored under an unknown kind would never be listed or found.
func (p *Provider) checkEntryType() error {
	if p.entryType == "" || password.EntryType(p.entryType).Valid() {
		return nil
	}
	return fmt.Errorf("unknown --entry-type %q: use password, api_key, totp, or secure_note", p.entryType)
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

	// Check for existing entry and confirm overwrite unless --force.
	if !p.force {
		exists, err := mgr.EntryExists(p.service, p.username, et)
		if err != nil {
			return provider.Credentials{}, fmt.Errorf("check existing entry: %w", err)
		}
		if exists {
			// Interactive prompts require a TTY. With piped stdin the
			// "answer" would silently consume piped content (e.g. the
			// note body) — fail loudly and direct the caller to --force.
			if !stdinIsTerminal() {
				who := ""
				if p.username != "" {
					who = fmt.Sprintf(" (%s)", p.username)
				}
				return provider.Credentials{}, fmt.Errorf("entry already exists for %s%s; re-run with --force to overwrite",
					p.service, who)
			}
			fmt.Fprintf(os.Stderr, "Entry already exists for %s", p.service)
			if p.username != "" {
				fmt.Fprintf(os.Stderr, " (%s)", p.username)
			}
			fmt.Fprintf(os.Stderr, ". Overwrite? [y/N]: ")
			answer, readErr := bufio.NewReader(p.stdin).ReadString('\n')
			if readErr != nil {
				return provider.Credentials{}, fmt.Errorf("read confirmation: %w", readErr)
			}
			if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(answer)), "y") {
				return provider.Credentials{}, fmt.Errorf("store cancelled")
			}
		}
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
		pw, err = io.ReadAll(p.stdin)
		if err != nil {
			return provider.Credentials{}, fmt.Errorf("failed to read note: %w", err)
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

	if err := mgr.StorePassword(p.service, p.username, pw, et); err != nil {
		return provider.Credentials{}, err
	}
	// A typed password only; API keys and notes come from elsewhere.
	if et == password.EntryTypePassword && password.IsWeak(pw, p.service, p.username) {
		generate := "sesh --service password --action generate --service-name " + shellQuote(p.service)
		if p.username != "" {
			generate += " --username " + shellQuote(p.username)
		}
		warnWeak("run: " + generate)
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
	opts := password.DefaultGenerateOptions()
	opts.Length = p.pwLength
	if p.noSymbols {
		opts.Symbols = false
	}

	generated, err := password.GeneratePassword(opts)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate password: %w", err)
	}
	if err := mgr.StorePassword(p.service, p.username, generated, p.effectiveEntryType()); err != nil {
		secure.SecureZeroBytes(generated)
		return nil, "", err
	}
	// Only a short --length makes one weak; the default never is.
	if password.IsWeak(generated, p.service, p.username) {
		warnWeak("use --length 12 or more")
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
	et := p.effectiveEntryType()

	secretBytes, err := mgr.GetPassword(p.service, p.username, et)
	if err != nil {
		return provider.Credentials{}, err
	}
	defer secure.SecureZeroBytes(secretBytes)

	if p.format == "json" {
		out := struct {
			Service  string `json:"service"`
			Username string `json:"username,omitempty"`
			Type     string `json:"type"`
			Password string `json:"password"`
		}{
			Service:  p.service,
			Username: p.username,
			Type:     string(p.effectiveEntryType()),
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

	answer, err := bufio.NewReader(p.stdin).ReadString('\n')
	if err != nil {
		return provider.Credentials{}, fmt.Errorf("read input: %w", err)
	}
	answer = strings.TrimSpace(answer)

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

	if err := mgr.StoreTOTPSecretWithParams(p.service, p.username, secret, params); err != nil {
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
	opts := password.ExportOptions{
		EntryType: password.EntryType(p.entryType),
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

// warnWeak tells the user the password just stored is easy to guess, and
// how to get a strong one.
func warnWeak(fix string) {
	fmt.Fprintf(os.Stderr, "⚠️  This password is easy to guess: a cracking program would likely find it in under 100 million tries. It's stored; for a strong one, %s\n", fix) //nolint:errcheck // best-effort warning
}
