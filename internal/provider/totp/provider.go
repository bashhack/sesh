package totp

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/constants"
	"github.com/bashhack/sesh/internal/env"
	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/setup"
	internalTotp "github.com/bashhack/sesh/internal/totp"
)


// Provider implements ServiceProvider for generic TOTP
type Provider struct {
	keychain    keychain.Provider
	totp        internalTotp.Provider

	// Flags
	serviceName string
	keyUser     string
	label       string
	profile     string // Used for multiple profiles for the same service
}

// Ensure Provider implements ServiceProvider interface
var _ provider.ServiceProvider = (*Provider)(nil)

// NewProvider creates a new Generic TOTP provider
func NewProvider(
	keychain keychain.Provider,
	totp internalTotp.Provider,
) *Provider {
	return &Provider{
		keychain: keychain,
		totp:     totp,
	}
}

// Name returns the provider name
func (p *Provider) Name() string {
	return "totp"
}

// Description returns the provider description
func (p *Provider) Description() string {
	return "Generic TOTP provider for any service"
}

// SetupFlags adds provider-specific flags to the given FlagSet
func (p *Provider) SetupFlags(fs provider.FlagSet) error {
	fs.StringVar(&p.serviceName, "service-name", "", "Name of the service to authenticate with")
	fs.StringVar(&p.label, "label", "", "Label to identify this TOTP entry")
	fs.StringVar(&p.profile, "profile", "", "Profile name for the service (for multiple accounts)")
	
	// Get current user like AWS provider does
	defaultKeyUser, err := env.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}
	p.keyUser = defaultKeyUser
	return nil
}

// GetSetupHandler returns a setup handler for TOTP
func (p *Provider) GetSetupHandler() interface{} {
	return setup.NewTOTPSetupHandler(p.keychain)
}

// GetCredentials generates a TOTP code
func (p *Provider) GetCredentials() (provider.Credentials, error) {
	if p.serviceName == "" {
		return provider.Credentials{}, fmt.Errorf("service name is required, use --service-name flag")
	}

	// Get TOTP secret from keychain using secure methods
	serviceKey := buildServiceKey(constants.TOTPServicePrefix, p.serviceName, p.profile)

	fmt.Fprintf(os.Stderr, "🔑 Retrieving TOTP secret for %s\n", p.serviceName)

	// Get secret bytes from keychain provider (no direct security command)
	secretBytes, err := p.keychain.GetSecret(p.keyUser, serviceKey)
	if err != nil {
		return provider.Credentials{}, fmt.Errorf("failed to retrieve TOTP secret for %s: %w", p.serviceName, err)
	}

	// Make defensive copy for secure handling
	secretCopy := make([]byte, len(secretBytes))
	copy(secretCopy, secretBytes)
	defer secure.SecureZeroBytes(secretCopy)

	// Zero original immediately after copying
	secure.SecureZeroBytes(secretBytes)

	// Generate TOTP codes using secure byte methods
	currentCode, nextCode, err := p.totp.GenerateConsecutiveCodesBytes(secretCopy)
	if err != nil {
		return provider.Credentials{}, fmt.Errorf("could not generate TOTP codes: %w", err)
	}

	// Calculate time left in current window
	now := time.Now().Unix()
	secondsLeft := 30 - (now % 30)

	// Format service description using TOTP pattern
	serviceDesc := p.serviceName
	if p.profile != "" {
		serviceDesc = fmt.Sprintf("%s (%s)", p.serviceName, p.profile)
	}

	// Show warning for non-clip usage and suggest clip mode
	fmt.Fprintf(os.Stderr, "⚠️  TOTP codes are typically used with clipboard mode for easy copying.\n")
	fmt.Fprintf(os.Stderr, "💡 Recommended: sesh --service totp --service-name %s", p.serviceName)
	if p.profile != "" {
		fmt.Fprintf(os.Stderr, " --profile %s", p.profile)
	}
	fmt.Fprintf(os.Stderr, " --clip\n\n")

	// Use shared clipboard function since TOTP should always show timing info
	return provider.CreateClipboardCredentials(p.Name(), currentCode, nextCode, secondsLeft,
		"TOTP code", serviceDesc), nil
}

// GetClipboardValue implements the ServiceProvider interface for clipboard mode
// For TOTP, clipboard mode is the same as normal credentials
func (p *Provider) GetClipboardValue() (provider.Credentials, error) {
	// TOTP is always optimized for clipboard, so just call GetCredentials
	return p.GetCredentials()
}

// ListEntries returns all TOTP entries in the keychain
func (p *Provider) ListEntries() ([]provider.ProviderEntry, error) {
	entries, err := p.keychain.ListEntries(constants.TOTPServicePrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list TOTP entries: %w", err)
	}

	result := make([]provider.ProviderEntry, 0, len(entries))
	for _, entry := range entries {
		// Extract service name from the service key
		serviceName, profile := parseServiceKey(entry.Service)

		// Skip entries that don't match our prefix pattern
		if !strings.HasPrefix(entry.Service, constants.TOTPServicePrefix) {
			continue
		}

		// Format name based on whether a profile exists
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

// DeleteEntry deletes a TOTP entry from the keychain
func (p *Provider) DeleteEntry(id string) error {
	// ID is formatted as "service:account"
	parts := strings.SplitN(id, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid entry ID format: expected 'service:account', got %q", id)
	}

	service, account := parts[0], parts[1]

	if account == "" {
		account = p.keyUser
	}

	if err := p.keychain.DeleteEntry(account, service); err != nil {
		return fmt.Errorf("failed to delete TOTP entry: %w", err)
	}

	return nil
}


// buildServiceKey creates a service key for the keychain
// Format: sesh-totp-{service}-{profile}
func buildServiceKey(prefix, service, profile string) string {
	if profile == "" {
		return fmt.Sprintf("%s-%s", prefix, service)
	}
	return fmt.Sprintf("%s-%s-%s", prefix, service, profile)
}

// parseServiceKey extracts service name and profile from a service key
// Format: sesh-totp-{service}-{profile}
func parseServiceKey(serviceKey string) (serviceName, profile string) {
	// Remove prefix
	if !strings.HasPrefix(serviceKey, constants.TOTPServicePrefix+"-") {
		return serviceKey, ""
	}

	parts := strings.SplitN(serviceKey, constants.TOTPServicePrefix+"-", 2)
	if len(parts) != 2 {
		return serviceKey, ""
	}

	remainder := parts[1]

	// Check if there's a profile (additional hyphen)
	profileParts := strings.Split(remainder, "-")
	if len(profileParts) == 1 {
		// No profile
		return remainder, ""
	}

	// Last part is the profile, the rest is the service name
	serviceName = strings.Join(profileParts[:len(profileParts)-1], "-")
	profile = profileParts[len(profileParts)-1]

	return serviceName, profile
}
