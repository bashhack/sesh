package totp

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/setup"
	internalTotp "github.com/bashhack/sesh/internal/totp"
)

const (
	defaultServicePrefix = "sesh-totp"
)

// Provider implements ServiceProvider for generic TOTP
type Provider struct {
	keychain    keychain.Provider
	totp        internalTotp.Provider
	setupWizard setup.WizardRunner
	
	// Flags
	serviceName string
	keyUser     string
	keyName     string
	label       string
	profile     string // Used for multiple profiles for the same service
}

// Ensure Provider implements ServiceProvider interface
var _ provider.ServiceProvider = (*Provider)(nil)

// NewProvider creates a new Generic TOTP provider
func NewProvider(
	keychain keychain.Provider,
	totp internalTotp.Provider,
	setupWizard setup.WizardRunner,
) *Provider {
	return &Provider{
		keychain:    keychain,
		totp:        totp,
		setupWizard: setupWizard,
		keyName:     defaultServicePrefix,
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
func (p *Provider) SetupFlags(fs *flag.FlagSet) {
	fs.StringVar(&p.serviceName, "service-name", "", "Name of the service to authenticate with")
	fs.StringVar(&p.keyUser, "keychain-user", os.Getenv("SESH_KEYCHAIN_USER"), "macOS Keychain username (optional)")
	fs.StringVar(&p.label, "label", "", "Label to identify this TOTP entry")
	fs.StringVar(&p.profile, "profile", "", "Profile name for the service (for multiple accounts)")
	
	defaultKeyName := os.Getenv("SESH_TOTP_KEYCHAIN_NAME")
	if defaultKeyName == "" {
		defaultKeyName = defaultServicePrefix
	}
	fs.StringVar(&p.keyName, "keychain-name", defaultKeyName, "macOS Keychain service name prefix")
}

// Setup runs the setup wizard for TOTP
func (p *Provider) Setup() error {
	return p.setupWizard.RunForService(p.Name())
}

// GetCredentials generates a TOTP code
func (p *Provider) GetCredentials() (provider.Credentials, error) {
	if p.serviceName == "" {
		return provider.Credentials{}, fmt.Errorf("service name is required, use --service-name flag")
	}
	
	// Get TOTP secret from keychain
	serviceKey := buildServiceKey(p.keyName, p.serviceName, p.profile)
	
	fmt.Fprintf(os.Stderr, "DEBUG: Accessing TOTP service '%s' with user '%s'\n", serviceKey, p.keyUser)
	
	// Try direct keychain access first
	cmd := exec.Command("security", "find-generic-password", 
		"-a", p.keyUser, 
		"-s", serviceKey,
		"-w")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	var secret string
	var err error
	
	if cmd.Run() == nil {
		secret = strings.TrimSpace(stdout.String())
	} else {
		// Fall back to provider method
		secret, err = p.keychain.GetSecret(p.keyUser, serviceKey)
		if err != nil {
			return provider.Credentials{}, fmt.Errorf("could not retrieve TOTP secret for %s: %w", p.serviceName, err)
		}
	}
	
	// Generate TOTP code
	code, err := p.totp.Generate(secret)
	if err != nil {
		return provider.Credentials{}, fmt.Errorf("could not generate TOTP code: %w", err)
	}
	
	// Generate next code for display
	_, next, err := p.totp.GenerateConsecutiveCodes(secret)
	
	// Calculate when this code expires (30 seconds from now, rounded to nearest 30s boundary)
	now := time.Now().Unix()
	validUntil := time.Unix(((now/30)+1)*30, 0)

	// Format display name based on whether a profile is specified
	displayName := p.serviceName
	if p.profile != "" {
		displayName = fmt.Sprintf("%s (%s)", p.serviceName, p.profile)
	}
	
	// Create credentials object
	return provider.Credentials{
		Provider:    p.Name(),
		Expiry:      validUntil,
		Variables:   map[string]string{"TOTP_CODE": code},
		DisplayInfo: fmt.Sprintf("TOTP code for %s: %s (Next: %s)", displayName, code, next),
		CopyValue:   code,
	}, nil
}

// ListEntries returns all TOTP entries in the keychain
func (p *Provider) ListEntries() ([]provider.ProviderEntry, error) {
	entries, err := p.keychain.ListEntries(p.keyName)
	if err != nil {
		return nil, fmt.Errorf("failed to list TOTP entries: %w", err)
	}
	
	result := make([]provider.ProviderEntry, 0, len(entries))
	for _, entry := range entries {
		// Extract service name from the service key
		serviceName, profile := parseServiceKey(entry.Service)
		
		// Skip entries that don't match our prefix pattern
		if !strings.HasPrefix(entry.Service, p.keyName) {
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
		var err error
		account, err = getCurrentUser()
		if err != nil {
			return fmt.Errorf("could not determine current user: %w", err)
		}
	}
	
	if err := p.keychain.DeleteEntry(account, service); err != nil {
		return fmt.Errorf("failed to delete TOTP entry: %w", err)
	}
	
	return nil
}

// getCurrentUser gets the current system user
func getCurrentUser() (string, error) {
	cmd := os.Getenv("USER")
	if cmd != "" {
		return cmd, nil
	}
	
	return "", fmt.Errorf("could not determine current user")
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
	if !strings.HasPrefix(serviceKey, defaultServicePrefix+"-") {
		return serviceKey, ""
	}
	
	parts := strings.SplitN(serviceKey, defaultServicePrefix+"-", 2)
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