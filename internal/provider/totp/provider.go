// Package totp implements the TOTP provider for sesh, handling generic TOTP credential management.
package totp

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"

	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/setup"
	"github.com/bashhack/sesh/internal/shell"
	internalTotp "github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// stdoutIsTerminal reports whether stdout is a terminal; tests replace it.
var stdoutIsTerminal = func() bool { return term.IsTerminal(int(os.Stdout.Fd())) }

// Provider implements ServiceProvider for generic TOTP.
type Provider struct {
	store vault.Store
	totp  internalTotp.Provider

	provider.Clock

	serviceName string
	profile     string
	filing      provider.FilingFlags
	force       bool
}

var _ provider.ServiceProvider = (*Provider)(nil)

// NewProvider creates a TOTP provider over the vault's TOTP entries.
func NewProvider(store vault.Store, totp internalTotp.Provider) *Provider {
	return &Provider{store: store, totp: totp}
}

// key is the entry the flags name: the TOTP entry for the service, with
// the profile as its username.
func (p *Provider) key() vault.Key {
	return vault.Key{Kind: vault.KindTOTP, Service: p.serviceName, Username: p.profile}
}

// Name returns the provider name.
func (p *Provider) Name() string {
	return "totp"
}

// Description returns the provider description.
func (p *Provider) Description() string {
	return "Generic TOTP provider for any service"
}

// SetupFlags adds provider-specific flags to the given FlagSet.
func (p *Provider) SetupFlags(fs provider.FlagSet) error {
	fs.StringVar(&p.serviceName, "service-name", "", "Name of the service to authenticate with")
	fs.StringVar(&p.profile, "profile", "", "Profile name for the service (for multiple accounts)")
	fs.BoolVar(&p.force, "force", false, "Delete without asking")
	p.filing.Register(fs)
	return nil
}

// GetSetupHandler returns a setup handler for TOTP.
func (p *Provider) GetSetupHandler() any {
	return setup.NewTOTPSetupHandler(p.store)
}

// GetCredentials returns the current code as Value, which the app prints
// alone to stdout so it can be captured; the next code and the time left
// go to stderr. At a terminal it also suggests --clip.
func (p *Provider) GetCredentials() (provider.Credentials, error) {
	c, err := p.generateTOTP()
	if err != nil {
		return provider.Credentials{}, err
	}
	creds := provider.CreateClipboardCredentials(p.Name(), c.current, c.next, c.secondsLeft, "TOTP code", c.desc)
	creds.Value = c.current
	creds.DisplayInfo = fmt.Sprintf("Next: %s  |  Time left: %ds\n🔑 TOTP code for %s", c.next, c.secondsLeft, c.desc)

	if stdoutIsTerminal() {
		cmd := "sesh --service totp --service-name " + shell.Quote(p.serviceName)
		if p.profile != "" {
			cmd += " --profile " + shell.Quote(p.profile)
		}
		fmt.Fprintf(os.Stderr, "💡 To copy it instead: %s --clip\n", cmd)
	}
	return creds, nil
}

// GetClipboardValue implements the ServiceProvider interface for clipboard mode.
func (p *Provider) GetClipboardValue() (provider.Credentials, error) {
	c, err := p.generateTOTP()
	if err != nil {
		return provider.Credentials{}, err
	}
	return provider.CreateClipboardCredentials(p.Name(), c.current, c.next, c.secondsLeft, "TOTP code", c.desc), nil
}

// totpCodes is the current and next code for an entry, with the seconds
// left on the current one and the entry's description.
type totpCodes struct {
	current, next, desc string
	secondsLeft         int64
}

// generateTOTP computes the codes for both GetCredentials and GetClipboardValue.
func (p *Provider) generateTOTP() (totpCodes, error) {
	if p.serviceName == "" {
		return totpCodes{}, fmt.Errorf("service name is required, use --service-name flag")
	}

	k := p.key()
	fmt.Fprintf(os.Stderr, "🔑 Retrieving TOTP secret for %s\n", p.serviceName)

	secretBytes, err := p.store.Get(k)
	if err != nil {
		return totpCodes{}, fmt.Errorf("failed to retrieve TOTP secret for %s: %w", p.serviceName, err)
	}

	secretCopy := make([]byte, len(secretBytes))
	copy(secretCopy, secretBytes)
	defer secure.SecureZeroBytes(secretCopy)

	secure.SecureZeroBytes(secretBytes)

	// The entry's code settings (algorithm, digits, period) decide which
	// codes are right, so not reading them is an error, not the defaults.
	e, err := p.store.Lookup(k)
	if err != nil {
		return totpCodes{}, fmt.Errorf("failed to read the code settings for %s: %w", p.serviceName, err)
	}
	params := e.Settings.TOTP

	currentCode, nextCode, err := p.totp.GenerateConsecutiveCodesBytesWithParams(secretCopy, params)
	if err != nil {
		return totpCodes{}, fmt.Errorf("could not generate TOTP codes: %w", err)
	}

	period := int64(30)
	if params.Period > 0 {
		period = int64(params.Period)
	}
	secondsLeft := period - (p.TimeNow().Unix() % period)

	serviceDesc := p.serviceName
	if p.profile != "" {
		serviceDesc = fmt.Sprintf("%s (%s)", p.serviceName, p.profile)
	}

	return totpCodes{current: currentCode, next: nextCode, desc: serviceDesc, secondsLeft: secondsLeft}, nil
}

// ListEntries returns the TOTP entries; an entry's ID is its key.
func (p *Provider) ListEntries() ([]provider.ProviderEntry, error) {
	f := p.listFilter()
	entries, err := p.store.List(&f)
	if err != nil {
		return nil, fmt.Errorf("failed to list TOTP entries: %w", err)
	}
	result := make([]provider.ProviderEntry, 0, len(entries))
	for i := range entries {
		e := &entries[i]
		name := e.Service
		if e.Username != "" {
			name = fmt.Sprintf("%s (%s)", e.Service, e.Username)
		}
		result = append(result, provider.ProviderEntry{Name: name, Type: string(vault.KindTOTP), ID: e.Key.String(), Folder: e.Folder, Tags: e.Tags})
	}
	return result, nil
}

// DeleteForced reports whether --force says to delete without asking.
func (p *Provider) DeleteForced() bool { return p.force }

// DeleteEntries deletes the TOTP entries ids name, asking first unless
// --force.
func (p *Provider) DeleteEntries(ids []string, confirm provider.ConfirmDelete) (int, error) {
	own := func(k vault.Key) error {
		if k.Kind != vault.KindTOTP {
			return fmt.Errorf("%s isn't a TOTP entry; delete it with --service password", k)
		}
		return nil
	}
	hint := func(k vault.Key) string { return password.CaseHint(p.store, k) }
	return provider.DeleteEntries(p.store, ids, own, hint, p.force, confirm)
}

// ValidateRequest performs early validation before any TOTP operations.
func (p *Provider) ValidateRequest() error {
	if p.serviceName == "" {
		return fmt.Errorf("--service-name is required for TOTP provider")
	}

	if _, err := p.store.Lookup(p.key()); err != nil {
		if !errors.Is(err, vault.ErrNotFound) {
			return fmt.Errorf("failed to look up the TOTP entry: %w", err)
		}
		missing := fmt.Sprintf("no TOTP entry found for service '%s'", p.serviceName)
		if p.profile != "" {
			missing += fmt.Sprintf(" with profile '%s'", p.profile)
		}
		if twins, terr := password.NewManager(p.store).CaseTwins(p.key()); terr == nil && len(twins) > 0 {
			return fmt.Errorf("%s; did you mean %s? Names are case-sensitive", missing, password.EntryName(twins[0]))
		}
		if p.profile != "" {
			return fmt.Errorf("no TOTP entry found for service '%s' with profile '%s'. Run 'sesh --service totp --setup' first", p.serviceName, p.profile)
		}
		return fmt.Errorf("no TOTP entry found for service '%s'. Run 'sesh --service totp --setup' first", p.serviceName)
	}
	return nil
}

// GetFlagInfo returns information about TOTP provider-specific flags.
func (p *Provider) GetFlagInfo() []provider.FlagInfo {
	return append([]provider.FlagInfo{
		{
			Name:        "service-name",
			Type:        "string",
			Description: "Name of the service to authenticate with",
			Required:    true,
		},
		{
			Name:        "profile",
			Type:        "string",
			Description: "Profile name for the service (for multiple accounts)",
			Required:    false,
		},
		{
			Name:        "force",
			Type:        "bool",
			Description: "Delete without asking",
			Required:    false,
		},
	}, p.filing.FlagInfo()...)
}

// Filing is what --folder and --tag say, for --setup.
func (p *Provider) Filing() vault.Filing { return p.filing.Filing() }

// UsesFiling reports that only --setup and --list use --folder and --tag.
func (p *Provider) UsesFiling() (bool, string) { return false, "--setup or --list" }

// listFilter is the entries --list shows: this provider's, narrowed by
// --folder and --tag.
func (p *Provider) listFilter() vault.Filter {
	f := p.filing.Filter()
	f.Kind = vault.KindTOTP
	return f
}

// NoMatchHint says why --list found nothing, when --folder or --tag names
// what no entry has.
func (p *Provider) NoMatchHint() string {
	f := p.listFilter()
	return provider.NoMatchHint(p.store, &f)
}

// CheckArgs refuses a service name or profile no entry can have, without
// the vault, so the CLI can stop before opening it.
func (p *Provider) CheckArgs() error {
	if p.serviceName == "" {
		return nil // reported by ValidateRequest when it's needed
	}
	if err := vault.CheckName("service name", p.serviceName); err != nil {
		return err
	}
	return vault.CheckName("profile", p.profile)
}
