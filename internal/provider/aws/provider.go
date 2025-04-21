package aws

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	awsInternal "github.com/bashhack/sesh/internal/aws"
	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/setup"
	"github.com/bashhack/sesh/internal/totp"
)

const (
	// Service name constants
	defaultKeyName = "sesh-mfa"
	mfaSerialService = "sesh-mfa-serial"
)

// Provider implements ServiceProvider for AWS
type Provider struct {
	aws         awsInternal.Provider
	keychain    keychain.Provider
	totp        totp.Provider
	setupWizard setup.WizardRunner
	
	// Flags
	profile  string
	serial   string
	keyUser  string
	keyName  string
}

// Ensure Provider implements ServiceProvider interface
var _ provider.ServiceProvider = (*Provider)(nil)

// NewProvider creates a new AWS provider
func NewProvider(
	aws awsInternal.Provider,
	keychain keychain.Provider,
	totp totp.Provider,
	setupWizard setup.WizardRunner,
) *Provider {
	return &Provider{
		aws:         aws,
		keychain:    keychain,
		totp:        totp,
		setupWizard: setupWizard,
		keyName:     defaultKeyName,
	}
}

// Name returns the provider name
func (p *Provider) Name() string {
	return "aws"
}

// Description returns the provider description
func (p *Provider) Description() string {
	return "Amazon Web Services CLI authentication"
}

// SetupFlags adds provider-specific flags to the given FlagSet
func (p *Provider) SetupFlags(fs *flag.FlagSet) {
	fs.StringVar(&p.profile, "profile", os.Getenv("AWS_PROFILE"), "AWS CLI profile to use")
	fs.StringVar(&p.serial, "serial", os.Getenv("SESH_MFA_SERIAL"), "MFA device serial number (optional)")
	fs.StringVar(&p.keyUser, "keychain-user", os.Getenv("SESH_KEYCHAIN_USER"), "macOS Keychain username (optional)")
	
	defaultKeyName := os.Getenv("SESH_KEYCHAIN_NAME")
	if defaultKeyName == "" {
		defaultKeyName = "sesh-mfa"
	}
	fs.StringVar(&p.keyName, "keychain-name", defaultKeyName, "macOS Keychain service name")
}

// Setup runs the setup wizard for AWS
func (p *Provider) Setup() error {
	return p.setupWizard.RunForService(p.Name())
}

// GetCredentials retrieves AWS credentials using TOTP
func (p *Provider) GetCredentials() (provider.Credentials, error) {
	// Get MFA serial
	serial, err := p.getMFASerial()
	if err != nil {
		return provider.Credentials{}, err
	}

	// Get TOTP secret - account for profile-specific secrets
	keyName := p.keyName
	
	if p.profile != "" {
		keyName = fmt.Sprintf("%s-%s", p.keyName, p.profile)
	}
	
	fmt.Fprintf(os.Stderr, "DEBUG: Accessing keychain service '%s' with user '%s'\n", keyName, p.keyUser)
	
	// Try to directly access the keychain with security command first
	// This approach may avoid some of the security prompts
	cmd := exec.Command("security", "find-generic-password", 
		"-a", p.keyUser, 
		"-s", keyName,
		"-w")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmdErr := cmd.Run()
	
	var secret string
	if cmdErr == nil {
		secret = strings.TrimSpace(stdout.String())
	} else {
		// Fall back to the provider method if direct access fails
		secret, err = p.keychain.GetSecret(p.keyUser, keyName)
		if err != nil {
			return provider.Credentials{}, fmt.Errorf("could not retrieve TOTP secret: %w", err)
		}
	}

	// Generate TOTP code
	code, err := p.totp.Generate(secret)
	if err != nil {
		return provider.Credentials{}, fmt.Errorf("could not generate TOTP code: %w", err)
	}

	// Get AWS credentials
	awsCreds, err := p.aws.GetSessionToken(p.profile, serial, code)
	if err != nil {
		return provider.Credentials{}, fmt.Errorf("failed to get session token: %w", err)
	}

	// Parse expiration time
	expiryTime, err := time.Parse(time.RFC3339, awsCreds.Expiration)
	if err != nil {
		expiryTime = time.Now().Add(12 * time.Hour) // Default to 12h if we can't parse
	}

	// Create environment variable map
	envVars := map[string]string{
		"AWS_ACCESS_KEY_ID":     awsCreds.AccessKeyId,
		"AWS_SECRET_ACCESS_KEY": awsCreds.SecretAccessKey,
		"AWS_SESSION_TOKEN":     awsCreds.SessionToken,
	}

	// Format display info
	displayInfo := fmt.Sprintf("AWS credentials for profile %s", p.profile)
	if p.profile == "" {
		displayInfo = "AWS credentials for default profile"
	}

	return provider.Credentials{
		Provider:    p.Name(),
		Expiry:      expiryTime,
		Variables:   envVars,
		DisplayInfo: displayInfo,
		CopyValue:   awsCreds.SessionToken, // Set session token as copy value
	}, nil
}

// ListEntries returns all AWS entries in the keychain
func (p *Provider) ListEntries() ([]provider.ProviderEntry, error) {
	// List both regular entries and serial entries
	entries, err := p.keychain.ListEntries("sesh-mfa")
	if err != nil {
		return nil, fmt.Errorf("failed to list AWS entries: %w", err)
	}
	
	result := make([]provider.ProviderEntry, 0, len(entries))
	for _, entry := range entries {
		// Extract profile name if present
		profile := ""
		serviceName := entry.Service
		
		// Handle profile-specific keys (sesh-mfa-profile)
		if strings.HasPrefix(serviceName, "sesh-mfa-") {
			profile = strings.TrimPrefix(serviceName, "sesh-mfa-")
		}
		
		// Create descriptive name and description
		name := "AWS"
		description := "AWS MFA"
		
		if profile != "" {
			name = fmt.Sprintf("AWS (%s)", profile)
			description = fmt.Sprintf("AWS MFA for profile %s", profile)
		}
		
		// Create a unique ID that contains both the service and account
		id := fmt.Sprintf("%s:%s", entry.Service, entry.Account)
		
		result = append(result, provider.ProviderEntry{
			Name:        name,
			Description: description,
			ID:          id,
		})
	}
	
	return result, nil
}

// DeleteEntry deletes an AWS entry from the keychain
func (p *Provider) DeleteEntry(id string) error {
	// ID is formatted as "service:account"
	parts := strings.SplitN(id, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid entry ID format: expected 'service:account', got %q", id)
	}
	
	service, account := parts[0], parts[1]
	
	// Delete both the MFA secret and MFA serial entries
	if err := p.keychain.DeleteEntry(account, service); err != nil {
		return fmt.Errorf("failed to delete AWS entry: %w", err)
	}
	
	// If this was a sesh-mfa entry, also delete the corresponding serial entry
	if strings.HasPrefix(service, "sesh-mfa") {
		serialService := strings.Replace(service, "sesh-mfa", "sesh-mfa-serial", 1)
		if err := p.keychain.DeleteEntry(account, serialService); err != nil {
			// Log but don't fail if serial entry deletion fails
			fmt.Fprintf(os.Stderr, "Warning: Failed to delete serial entry %s: %v\n", serialService, err)
		}
	}
	
	return nil
}

// getMFASerial attempts to get an MFA serial from various sources
func (p *Provider) getMFASerial() (string, error) {
	// If serial is explicitly provided, use it
	if p.serial != "" {
		return p.serial, nil
	}
	
	// Service name for the MFA serial (account for profile)
	serialService := mfaSerialService
	if p.profile != "" {
		serialService = fmt.Sprintf("%s-%s", mfaSerialService, p.profile)
	}
	
	fmt.Fprintf(os.Stderr, "DEBUG: Accessing MFA serial from service '%s' with user '%s'\n", serialService, p.keyUser)
	
	// Try direct keychain access first
	cmd := exec.Command("security", "find-generic-password", 
		"-a", p.keyUser, 
		"-s", serialService,
		"-w")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err := cmd.Run()
	
	if err == nil {
		serialFromKeychain := strings.TrimSpace(stdout.String())
		return serialFromKeychain, nil
	}
	
	// Fall back to the provider method
	serialFromKeychain, err := p.keychain.GetSecret(p.keyUser, serialService)
	if err == nil {
		return serialFromKeychain, nil
	}
	
	// If not found in keychain, try to auto-detect from AWS
	serial, err := p.aws.GetFirstMFADevice(p.profile)
	if err != nil {
		return "", fmt.Errorf("could not detect MFA device: %w", err)
	}
	
	return serial, nil
}