// Package password implements the password manager provider for sesh.
package password

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/bashhack/sesh/internal/env"
	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/qrcode"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/totp"
)

// Provider implements ServiceProvider for the password manager.
type Provider struct {
	keychain keychain.Provider

	query      string // search query
	sortBy     string
	username   string
	entryType  string
	action     string // "store", "get", "search", "generate", "export", "import", "totp-store", "totp-generate"
	file       string // file path for export/import
	onConflict string // import conflict strategy: "skip", "overwrite"
	provider.KeyUser
	format    string // output format: "table", "json", "csv"
	service   string
	pwLength  int // password generation length
	limit     int
	offset    int
	force     bool // skip confirmation
	noSymbols bool // password generation: exclude symbols
	show      bool // show password instead of clipboard
}

var _ provider.ServiceProvider = (*Provider)(nil)

// NewProvider creates a new password manager provider.
func NewProvider(kc keychain.Provider) *Provider {
	return &Provider{keychain: kc}
}

func (p *Provider) Name() string         { return "password" }
func (p *Provider) Description() string  { return "Secure password manager" }
func (p *Provider) GetSetupHandler() any { return nil }

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

	defaultUser, err := env.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}
	p.User = defaultUser
	return nil
}

func (p *Provider) GetFlagInfo() []provider.FlagInfo {
	return []provider.FlagInfo{
		{Name: "action", Type: "string", Description: "Action: store, get, generate, search, export, import, totp-store, totp-generate"},
		{Name: "service-name", Type: "string", Description: "Service name"},
		{Name: "username", Type: "string", Description: "Username for the service"},
		{Name: "entry-type", Type: "string", Description: "Entry type (password, api_key, totp, secure_note)"},
		{Name: "query", Type: "string", Description: "Search query"},
		{Name: "sort", Type: "string", Description: "Sort by (service, created_at, updated_at)"},
		{Name: "format", Type: "string", Description: "Output format (table, json, csv)"},
		{Name: "file", Type: "string", Description: "File path for export/import (default: stdout/stdin)"},
		{Name: "on-conflict", Type: "string", Description: "Import conflict strategy: skip, overwrite"},
		{Name: "show", Type: "bool", Description: "Show password instead of copying to clipboard"},
		{Name: "force", Type: "bool", Description: "Skip confirmation prompts"},
		{Name: "no-symbols", Type: "bool", Description: "Exclude symbols from generated passwords"},
		{Name: "length", Type: "int", Description: "Generated password length (default 24)"},
		{Name: "limit", Type: "int", Description: "Limit number of results (0 = no limit)"},
		{Name: "offset", Type: "int", Description: "Skip first N results"},
	}
}

func (p *Provider) ValidateRequest() error {
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
	case "export", "import":
		if p.format == "table" {
			p.format = "json"
		}
		if p.format != "json" && p.format != "csv" {
			return fmt.Errorf("--format for %s must be json or csv, got %q", p.action, p.format)
		}
		if p.action == "import" && p.onConflict != "" && p.onConflict != "skip" && p.onConflict != "overwrite" {
			return fmt.Errorf("--on-conflict must be skip or overwrite, got %q", p.onConflict)
		}
	case "":
		// Default action handled by GetCredentials
	default:
		return fmt.Errorf("unknown action: %q (use store, get, search, generate, export, import, totp-store, totp-generate)", p.action)
	}
	return nil
}

// GetCredentials handles the main operation based on --action flag.
func (p *Provider) GetCredentials() (provider.Credentials, error) {
	mgr := password.NewManager(p.keychain, p.User)

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
		return p.generateTOTP(mgr)
	default:
		return provider.Credentials{}, fmt.Errorf("specify --action (store, get, search, generate, export, import, totp-store, totp-generate) or use --list, --delete")
	}
}

// GetClipboardValue retrieves a password and prepares it for clipboard.
func (p *Provider) GetClipboardValue() (provider.Credentials, error) {
	if p.service == "" {
		return provider.Credentials{}, fmt.Errorf("--service-name is required")
	}

	mgr := password.NewManager(p.keychain, p.User)
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
	mgr := password.NewManager(p.keychain, p.User)

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
			Description: fmt.Sprintf("[%s] %s", e.Type, e.Description),
			ID:          e.ID,
		})
	}
	return result, nil
}

// DeleteEntry deletes a password entry by ID, with confirmation unless --force.
func (p *Provider) DeleteEntry(id string) error {
	if !p.force {
		fmt.Fprintf(os.Stderr, "Delete entry %q? [y/N]: ", id)
		answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return fmt.Errorf("read confirmation: %w", err)
		}
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(answer)), "y") {
			return fmt.Errorf("delete cancelled")
		}
	}

	service, account, err := provider.ParseEntryID(id)
	if err != nil {
		return err
	}
	return p.keychain.DeleteEntry(account, service)
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

	// Check for existing entry and confirm overwrite unless --force
	if !p.force {
		_, err := mgr.GetPassword(p.service, p.username, et)
		if err == nil {
			fmt.Fprintf(os.Stderr, "Entry already exists for %s", p.service)
			if p.username != "" {
				fmt.Fprintf(os.Stderr, " (%s)", p.username)
			}
			fmt.Fprintf(os.Stderr, ". Overwrite? [y/N]: ")
			answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
			if err != nil {
				return provider.Credentials{}, fmt.Errorf("read confirmation: %w", err)
			}
			if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(answer)), "y") {
				return provider.Credentials{}, fmt.Errorf("store cancelled")
			}
		}
	}

	// Read input — method depends on entry type
	var pw []byte
	if et == password.EntryTypeNote {
		// Secure notes: read multi-line from stdin until EOF.
		// Works with pipes (echo "..." | sesh ...) and heredocs.
		fmt.Fprintf(os.Stderr, "Enter note for %s (end with Ctrl+D):\n", p.service)
		var err error
		pw, err = io.ReadAll(os.Stdin)
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
		pw, err = term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return provider.Credentials{}, fmt.Errorf("failed to read %s: %w", et, err)
		}
	}
	defer secure.SecureZeroBytes(pw)

	if err := mgr.StorePassword(p.service, p.username, pw, et); err != nil {
		return provider.Credentials{}, err
	}

	return provider.Credentials{
		Provider:    p.Name(),
		DisplayInfo: fmt.Sprintf("✅ Stored %s for %s", et, p.service),
	}, nil
}

func (p *Provider) generatePassword(mgr *password.Manager) (provider.Credentials, error) {
	opts := password.DefaultGenerateOptions()
	opts.Length = p.pwLength
	if p.noSymbols {
		opts.Symbols = false
	}

	generated, err := password.GeneratePassword(opts)
	if err != nil {
		return provider.Credentials{}, fmt.Errorf("failed to generate password: %w", err)
	}

	// Store the generated password
	et := p.effectiveEntryType()
	if err := mgr.StorePassword(p.service, p.username, []byte(generated), et); err != nil {
		return provider.Credentials{}, err
	}

	desc := p.service
	if p.username != "" {
		desc = fmt.Sprintf("%s (%s)", p.service, p.username)
	}

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
			Password: generated,
		}
		b, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return provider.Credentials{}, fmt.Errorf("marshal JSON output: %w", err)
		}
		return provider.Credentials{
			Provider:    p.Name(),
			DisplayInfo: string(b),
		}, nil
	}

	return provider.Credentials{
		Provider:             p.Name(),
		CopyValue:            generated,
		ClipboardDescription: fmt.Sprintf("generated password for %s", desc),
		DisplayInfo:          fmt.Sprintf("✅ Generated and stored %s for %s\n💡 Use --clip to copy the password", et, desc),
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
		b, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return provider.Credentials{}, fmt.Errorf("marshal JSON output: %w", err)
		}
		return provider.Credentials{
			Provider:    p.Name(),
			DisplayInfo: string(b),
		}, nil
	}

	if p.show {
		return provider.Credentials{
			Provider:    p.Name(),
			DisplayInfo: string(secretBytes),
		}, nil
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

func (p *Provider) searchPasswords(mgr *password.Manager) (provider.Credentials, error) {
	entries, err := mgr.SearchEntries(p.query)
	if err != nil {
		return provider.Credentials{}, err
	}

	if len(entries) == 0 {
		return provider.Credentials{
			Provider:    p.Name(),
			DisplayInfo: fmt.Sprintf("No entries matching %q", p.query),
		}, nil
	}

	if p.format == "json" {
		b, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			return provider.Credentials{}, fmt.Errorf("marshal JSON output: %w", err)
		}
		return provider.Credentials{
			Provider:    p.Name(),
			DisplayInfo: string(b),
		}, nil
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Found %d entries matching %q:\n", len(entries), p.query)
	q := strings.ToLower(p.query)
	for i := range entries {
		e := &entries[i]
		name := e.Service
		if e.Username != "" {
			name = fmt.Sprintf("%s (%s)", e.Service, e.Username)
		}
		// Highlight matching portion in service name
		highlighted := highlightMatch(name, q)
		fmt.Fprintf(&sb, "  %-30s [%s] %s\n", highlighted, e.Type, e.Description)
	}

	return provider.Credentials{
		Provider:    p.Name(),
		DisplayInfo: sb.String(),
	}, nil
}

func (p *Provider) storeTOTP(mgr *password.Manager) (provider.Credentials, error) {
	// Offer QR code scanning option
	fmt.Fprintln(os.Stderr, "How would you like to provide the TOTP secret?")
	fmt.Fprintln(os.Stderr, "  1) Enter manually")
	fmt.Fprintln(os.Stderr, "  2) Scan QR code from screen")
	fmt.Fprintf(os.Stderr, "Choose [1/2]: ")

	answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return provider.Credentials{}, fmt.Errorf("read input: %w", err)
	}
	answer = strings.TrimSpace(answer)

	var secret string
	var params totp.Params

	switch answer {
	case "2":
		info, err := qrcode.ScanQRCodeFull()
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
		fmt.Fprintf(os.Stderr, "✅ QR code scanned successfully\n")
		if info.Issuer != "" {
			fmt.Fprintf(os.Stderr, "   Issuer: %s\n", info.Issuer)
		}
	default:
		fmt.Fprintf(os.Stderr, "Enter TOTP secret for %s", p.service)
		if p.username != "" {
			fmt.Fprintf(os.Stderr, " (%s)", p.username)
		}
		fmt.Fprintf(os.Stderr, ": ")

		secretBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
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

func (p *Provider) exportEntries(mgr *password.Manager) (provider.Credentials, error) {
	format := password.FormatJSON
	if p.format == "csv" {
		format = password.FormatCSV
	}

	opts := password.ExportOptions{
		Format:    format,
		EntryType: password.EntryType(p.entryType),
	}

	var w io.Writer
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
	} else {
		var buf strings.Builder
		w = &buf
		defer func() {
			// Print to stderr since stdout is for eval-safe output
			fmt.Fprint(os.Stderr, buf.String())
		}()
	}

	count, err := mgr.Export(w, opts)
	if err != nil {
		return provider.Credentials{}, err
	}

	dest := "stdout"
	if p.file != "" {
		dest = p.file
	}

	return provider.Credentials{
		Provider:    p.Name(),
		DisplayInfo: fmt.Sprintf("Exported %d entries to %s", count, dest),
	}, nil
}

func (p *Provider) importEntries(mgr *password.Manager) (provider.Credentials, error) {
	format := password.FormatJSON
	if p.format == "csv" {
		format = password.FormatCSV
	}

	opts := password.ImportOptions{
		Format:     format,
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
		r = os.Stdin
	}

	result, err := mgr.Import(r, opts)
	if err != nil {
		return provider.Credentials{}, err
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Imported %d entries", result.Imported)
	if result.Skipped > 0 {
		fmt.Fprintf(&sb, ", skipped %d", result.Skipped)
	}
	if len(result.Errors) > 0 {
		fmt.Fprintf(&sb, ", %d errors:", len(result.Errors))
		for _, e := range result.Errors {
			fmt.Fprintf(&sb, "\n  %s", e)
		}
	}

	return provider.Credentials{
		Provider:    p.Name(),
		DisplayInfo: sb.String(),
	}, nil
}

// highlightMatch wraps the first case-insensitive occurrence of query in text
// with ANSI bold escape codes.
func highlightMatch(text, query string) string {
	lower := strings.ToLower(text)
	idx := strings.Index(lower, query)
	if idx < 0 {
		return text
	}
	return text[:idx] + "\033[1m" + text[idx:idx+len(query)] + "\033[0m" + text[idx+len(query):]
}
