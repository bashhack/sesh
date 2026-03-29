// Package totp implements the TOTP provider for sesh, handling generic TOTP credential management.
package totp

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/bashhack/sesh/internal/constants"
	"github.com/bashhack/sesh/internal/env"
	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/keyformat"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/setup"
	internalTotp "github.com/bashhack/sesh/internal/totp"
)

// Provider implements ServiceProvider for generic TOTP.
type Provider struct {
	keychain keychain.Provider
	totp     internalTotp.Provider

	provider.Clock
	provider.KeyUser

	serviceName string
	profile     string
}

var _ provider.ServiceProvider = (*Provider)(nil)

// NewProvider creates a new Generic TOTP provider.
func NewProvider(
	kc keychain.Provider,
	totp internalTotp.Provider,
) *Provider {
	return &Provider{
		keychain: kc,
		totp:     totp,
	}
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

	defaultKeyUser, err := env.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}
	p.User = defaultKeyUser
	return nil
}

// GetSetupHandler returns a setup handler for TOTP.
func (p *Provider) GetSetupHandler() any {
	return setup.NewTOTPSetupHandler(p.keychain)
}

// GetCredentials generates a TOTP code.
func (p *Provider) GetCredentials() (provider.Credentials, error) {
	creds, err := p.generateTOTP()
	if err != nil {
		return creds, err
	}

	// Suggest clipboard mode when called directly
	cmd := fmt.Sprintf("sesh --service totp --service-name %q", p.serviceName)
	if p.profile != "" {
		cmd += fmt.Sprintf(" --profile %q", p.profile)
	}
	fmt.Fprintf(os.Stderr, "⚠️  TOTP codes are typically used with clipboard mode for easy copying.\n💡 Recommended: %s --clip\n\n", cmd)

	return creds, nil
}

// GetClipboardValue implements the ServiceProvider interface for clipboard mode.
func (p *Provider) GetClipboardValue() (provider.Credentials, error) {
	return p.generateTOTP()
}

// generateTOTP is the shared implementation for both GetCredentials and GetClipboardValue.
func (p *Provider) generateTOTP() (provider.Credentials, error) {
	if p.serviceName == "" {
		return provider.Credentials{}, fmt.Errorf("service name is required, use --service-name flag")
	}

	if err := p.EnsureUser(); err != nil {
		return provider.Credentials{}, err
	}

	serviceKey, err := buildServiceKey(p.serviceName, p.profile)
	if err != nil {
		return provider.Credentials{}, fmt.Errorf("failed to build service key: %w", err)
	}

	fmt.Fprintf(os.Stderr, "🔑 Retrieving TOTP secret for %s\n", p.serviceName)

	secretBytes, err := p.keychain.GetSecret(p.User, serviceKey)
	if err != nil {
		return provider.Credentials{}, fmt.Errorf("failed to retrieve TOTP secret for %s: %w", p.serviceName, err)
	}

	secretCopy := make([]byte, len(secretBytes))
	copy(secretCopy, secretBytes)
	defer secure.SecureZeroBytes(secretCopy)

	secure.SecureZeroBytes(secretBytes)

	currentCode, nextCode, err := p.totp.GenerateConsecutiveCodesBytes(secretCopy)
	if err != nil {
		return provider.Credentials{}, fmt.Errorf("could not generate TOTP codes: %w", err)
	}

	secondsLeft := p.SecondsLeftInWindow()

	serviceDesc := p.serviceName
	if p.profile != "" {
		serviceDesc = fmt.Sprintf("%s (%s)", p.serviceName, p.profile)
	}

	return provider.CreateClipboardCredentials(p.Name(), currentCode, nextCode, secondsLeft,
		"TOTP code", serviceDesc), nil
}

// ListEntries returns all TOTP entries in the keychain.
func (p *Provider) ListEntries() ([]provider.ProviderEntry, error) {
	entries, err := p.keychain.ListEntries(constants.TOTPServicePrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list TOTP entries: %w", err)
	}

	result := make([]provider.ProviderEntry, 0, len(entries))
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Service, constants.TOTPServicePrefix+"/") {
			continue
		}

		serviceName, profile := parseServiceKey(entry.Service)

		displayName := serviceName
		description := fmt.Sprintf("TOTP for %s", serviceName)

		if profile != "" {
			displayName = fmt.Sprintf("%s (%s)", serviceName, profile)
			description = fmt.Sprintf("TOTP for %s profile %s", serviceName, profile)
		}

		result = append(result, provider.ProviderEntry{
			Name:        displayName,
			Description: description,
			ID:          fmt.Sprintf("%s:%s", entry.Service, entry.Account),
		})
	}

	return result, nil
}

// DeleteEntry deletes a TOTP entry from the keychain.
func (p *Provider) DeleteEntry(id string) error {
	service, account, err := provider.ParseEntryID(id)
	if err != nil {
		return err
	}

	if err := p.keychain.DeleteEntry(account, service); err != nil {
		return fmt.Errorf("failed to delete TOTP entry: %w", err)
	}

	return nil
}

// ValidateRequest performs early validation before any TOTP operations.
func (p *Provider) ValidateRequest() error {
	if p.serviceName == "" {
		return fmt.Errorf("--service-name is required for TOTP provider")
	}

	if err := p.EnsureUser(); err != nil {
		return err
	}

	keyName, err := buildServiceKey(p.serviceName, p.profile)
	if err != nil {
		return fmt.Errorf("failed to build service key: %w", err)
	}

	secret, err := p.keychain.GetSecret(p.User, keyName)
	if err != nil {
		if !errors.Is(err, keychain.ErrNotFound) {
			return fmt.Errorf("failed to read TOTP secret from keychain: %w", err)
		}
		if p.profile != "" {
			return fmt.Errorf("no TOTP entry found for service '%s' with profile '%s'. Run 'sesh --service totp --setup' first", p.serviceName, p.profile)
		}
		return fmt.Errorf("no TOTP entry found for service '%s'. Run 'sesh --service totp --setup' first", p.serviceName)
	}
	secure.SecureZeroBytes(secret)

	return nil
}

// GetFlagInfo returns information about TOTP provider-specific flags.
func (p *Provider) GetFlagInfo() []provider.FlagInfo {
	return []provider.FlagInfo{
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
	}
}

// buildServiceKey creates a service key using keyformat.Build.
// Format: sesh-totp/{service} or sesh-totp/{service}/{profile}
func buildServiceKey(service, profile string) (string, error) {
	if profile == "" {
		return keyformat.Build(constants.TOTPServicePrefix, service)
	}
	return keyformat.Build(constants.TOTPServicePrefix, service, profile)
}

// parseServiceKey extracts service name and profile from a service key.
// For "sesh-totp/github" returns ("github", "").
// For "sesh-totp/github/work" returns ("github", "work").
func parseServiceKey(serviceKey string) (serviceName, profile string) {
	segments, err := keyformat.Parse(serviceKey, constants.TOTPServicePrefix)
	if err != nil || len(segments) == 0 {
		return serviceKey, ""
	}
	if len(segments) == 1 {
		return segments[0], ""
	}
	return segments[0], segments[1]
}
