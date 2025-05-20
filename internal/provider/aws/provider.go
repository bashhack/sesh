package aws

import (
	"flag"
	"fmt"
	"github.com/bashhack/sesh/internal/constants"
	"github.com/bashhack/sesh/internal/env"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/subshell"
	"os"
	"path/filepath"
	"strings"
	"time"

	awsInternal "github.com/bashhack/sesh/internal/aws"
	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/setup"
	internalTotp "github.com/bashhack/sesh/internal/totp"
)

// Provider implements ServiceProvider for AWS
type Provider struct {
	aws      awsInternal.Provider
	keychain keychain.Provider
	totp     internalTotp.Provider

	// Flags
	profile string
	keyUser string
	keyName string
}

// Ensure Provider implements ServiceProvider interface
var _ provider.ServiceProvider = (*Provider)(nil)

// NewProvider creates a new AWS provider
func NewProvider(
	aws awsInternal.Provider,
	keychain keychain.Provider,
	totp internalTotp.Provider,
) *Provider {
	return &Provider{
		aws:      aws,
		keychain: keychain,
		totp:     totp,
		keyName:  constants.AWSServicePrefix,
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
func (p *Provider) SetupFlags(fs provider.FlagSet) error {
	fs.StringVar(&p.profile, "profile", os.Getenv("AWS_PROFILE"), "AWS CLI profile to use")

	// Add a dummy service-name flag to detect invalid flag usage with AWS provider
	var dummyServiceName string
	fs.StringVar(&dummyServiceName, "service-name", "", "NOT USED - Only valid with TOTP provider")

	defaultKeyUser, err := env.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}
	p.keyUser = defaultKeyUser
	return nil
}

// GetSetupHandler returns a setup handler for AWS
func (p *Provider) GetSetupHandler() interface{} {
	return setup.NewAWSSetupHandler(p.keychain)
}

// GetTOTPCodes retrieves only TOTP codes without performing AWS authentication
// This is used specifically for the clipboard mode
func (p *Provider) GetTOTPCodes() (currentCode string, nextCode string, secondsLeft int64, err error) {
	// TODO: This check doesn't work???
	// Validate that service-name was not provided - it's not valid for AWS
	flag := flag.Lookup("service-name")
	if flag != nil && flag.Value.String() != "" {
		return "", "", 0, fmt.Errorf("the --service-name flag is only valid with the TOTP provider, not AWS")
	}

	// Get TOTP secret - account for profile-specific secrets
	var keyName string
	if p.profile == "" {
		// Use default for the default profile
		keyName = fmt.Sprintf("%s-default", p.keyName)
	} else {
		keyName = fmt.Sprintf("%s-%s", p.keyName, p.profile)
	}

	// Get TOTP secret from keychain using the provider interface
	secretBytes, err := p.keychain.GetSecret(p.keyUser, keyName)
	if err != nil {
		return "", "", 0, fmt.Errorf("could not retrieve TOTP secret: %w", err)
	}
	
	// Make defensive copy
	secretCopy := make([]byte, len(secretBytes))
	copy(secretCopy, secretBytes)
	defer secure.SecureZeroBytes(secretCopy)
	
	// Zero original immediately after copying
	secure.SecureZeroBytes(secretBytes)
	
	// Convert to string - this is necessary because the TOTP package expects a string
	// In the future, consider updating the TOTP package to work with byte slices directly
	secret := string(secretCopy)

	fmt.Fprintf(os.Stderr, "🔑 Retrieved secret from keychain\n")

	// Check if secret looks valid (base32 encoded)
	if len(secret) < 16 || len(secret) > 64 {
		fmt.Fprintf(os.Stderr, "⚠️ Warning: TOTP secret has unusual length: %d characters\n", len(secret))
	}

	// Generate consecutive TOTP codes
	currentCode, nextCode, err = p.totp.GenerateConsecutiveCodes(secret)
	if err != nil {
		return "", "", 0, fmt.Errorf("could not generate TOTP codes: %w", err)
	}

	// Get the seconds left in current time window
	secondsLeft = 30 - (time.Now().Unix() % 30)

	return currentCode, nextCode, secondsLeft, nil
}

// GetClipboardValue implements the ServiceProvider interface for clipboard mode
// It generates only TOTP codes without AWS authentication to avoid the double-use of TOTP codes
func (p *Provider) GetClipboardValue() (provider.Credentials, error) {
	currentCode, nextCode, secondsLeft, err := p.GetTOTPCodes()
	if err != nil {
		return provider.Credentials{}, err
	}

	fmt.Fprintf(os.Stderr, "🔑 Generating TOTP codes for clipboard mode\n")

	// Format display info
	var displayInfo string
	profileStr := "default profile"
	if p.profile != "" {
		profileStr = fmt.Sprintf("profile %s", p.profile)
	}
	displayInfo = fmt.Sprintf("Current: %s  |  Next: %s  |  Time left: %ds\n🔑 AWS MFA code for %s",
		currentCode, nextCode, secondsLeft, profileStr)

	// Calculate when this code expires
	now := time.Now().Unix()
	validUntil := time.Unix(((now/30)+1)*30, 0)

	// Return credentials with just the display info and copy value
	return provider.Credentials{
		Provider:         p.Name(),
		Expiry:           validUntil,
		Variables:        map[string]string{}, // Empty map as we're not generating AWS credentials
		DisplayInfo:      displayInfo,
		CopyValue:        currentCode, // This is what will be copied to clipboard
		MFAAuthenticated: false,       // For clipboard mode, we don't authenticate with AWS
	}, nil
}

// GetCredentials retrieves AWS credentials using TOTP
func (p *Provider) GetCredentials() (provider.Credentials, error) {
	// Validate that service-name was not provided - it's not valid for AWS
	flag := flag.Lookup("service-name")
	if flag != nil && flag.Value.String() != "" {
		return provider.Credentials{}, fmt.Errorf("the --service-name flag is only valid with the TOTP provider, not AWS")
	}

	// Get MFA serial as bytes
	serialBytes, err := p.GetMFASerialBytes()
	if err != nil {
		return provider.Credentials{}, err
	}
	
	// Convert to string for debug and API call, then zero out
	serial := string(serialBytes)
	defer secure.SecureZeroBytes(serialBytes)

	// Debug: Print the serial number to help diagnose issues
	fmt.Fprintf(os.Stderr, "🔍 Using MFA serial: %s\n", serial)

	// Get TOTP codes
	currentCode, nextCode, secondsLeft, err := p.GetTOTPCodes()
	if err != nil {
		return provider.Credentials{}, err
	}

	// First try with the current code
	code := currentCode

	// Try the first code
	codeBytes := []byte(code)
	awsCreds, err := p.aws.GetSessionToken(p.profile, serial, codeBytes)
	// Zero out the bytes after use
	secure.SecureZeroBytes(codeBytes)

	// Check if this is an "invalid MFA one time pass code" error, which could indicate a recently used code
	if err != nil {
		errStr := err.Error()
		isInvalidMFA := strings.Contains(errStr, "MultiFactorAuthentication failed with invalid MFA one time pass code")

		// If it's an invalid MFA code or if we're close to time boundary, try the next code
		if isInvalidMFA || secondsLeft < 5 {
			if isInvalidMFA {
				fmt.Fprintf(os.Stderr, "⚠️ AWS rejected the current time window's code (it may have been used recently)\n")
			} else {
				fmt.Fprintf(os.Stderr, "⚠️ Current code failed - time window nearly expired\n")
			}

			// Try with the next time window's code
			fmt.Fprintf(os.Stderr, "🔑 Trying with next time window's code: %s\n", nextCode)
			code = nextCode
			codeBytes = []byte(code)
			awsCreds, err = p.aws.GetSessionToken(p.profile, serial, codeBytes)
			secure.SecureZeroBytes(codeBytes)

			// If STILL failing and we're not close to boundary, and we have a "recently used" error,
			// we may need to wait for the next time window
			if err != nil && isInvalidMFA && secondsLeft > 10 {
				fmt.Fprintf(os.Stderr, "⚠️ Both current and next codes were rejected - may need to wait for next time window\n")

				// Get the secret again to generate a future code
				keyName := p.profile
				if keyName == "" {
					keyName = "default"
				}
				keyName = fmt.Sprintf("%s-%s", p.keyName, keyName)

				// Get the TOTP secret using the provider interface
				secretBytes, err := p.keychain.GetSecret(p.keyUser, keyName)
				if err != nil {
					return provider.Credentials{}, fmt.Errorf("could not retrieve TOTP secret: %w", err)
				}
				
				// Make defensive copy
				secretCopy := make([]byte, len(secretBytes))
				copy(secretCopy, secretBytes)
				defer secure.SecureZeroBytes(secretCopy)
				
				// Zero original immediately after copying 
				secure.SecureZeroBytes(secretBytes)
				
				// Convert to string - this is necessary because the TOTP package expects a string
				// In the future, consider updating the TOTP package to work with byte slices directly
				secret := string(secretCopy)

				// Generate a code for the window after next, in case AWS is far ahead of our clock
				futureCode, gErr := p.totp.GenerateForTime(secret, time.Now().Add(60*time.Second))
				if gErr == nil {
					fmt.Fprintf(os.Stderr, "🔑 Trying with future time window's code: %s\n", futureCode)
					code = futureCode
					codeBytes = []byte(code)
					awsCreds, err = p.aws.GetSessionToken(p.profile, serial, codeBytes)
					secure.SecureZeroBytes(codeBytes)
				}
			}
		}
	}

	// If still failing, return the error
	if err != nil {
		// Check if this looks like a "code already used" error
		if strings.Contains(err.Error(), "MultiFactorAuthentication failed with invalid MFA one time pass code") {
			// Add more context to the error message
			return provider.Credentials{}, fmt.Errorf("failed to get session token: %w\n\nThis may be because the TOTP code was recently used. Try waiting for the next time window (30-second interval) and try again.", err)
		}
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

	// Format basic display info
	var displayInfo string
	if p.profile == "" {
		displayInfo = "🔑 AWS credentials for default profile"
	} else {
		displayInfo = fmt.Sprintf("🔑 AWS credentials for profile %s", p.profile)
	}

	// For regular credential generation, just return the basic info
	return provider.Credentials{
		Provider:         p.Name(),
		Expiry:           expiryTime,
		Variables:        envVars,
		DisplayInfo:      displayInfo,
		MFAAuthenticated: true, // If we got this far, AWS STS accepted our MFA code
	}, nil
}

// ListEntries returns all AWS entries in the keychain
func (p *Provider) ListEntries() ([]provider.ProviderEntry, error) {
	// Simply get all entries with our AWS prefix
	allEntries, err := p.keychain.ListEntries(constants.AWSServicePrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list AWS entries: %w", err)
	}

	// Convert keychain entries to provider entries
	result := make([]provider.ProviderEntry, 0, len(allEntries))
	for _, entry := range allEntries {
		// Skip MFA serial entries - we don't want to show these to users
		// as they're implementation details and paired with the main entries
		if strings.HasPrefix(entry.Service, constants.AWSServiceMFAPrefix) {
			continue
		}

		// Extract profile name if present
		profile := ""
		serviceName := entry.Service

		// Handle profile-specific keys (sesh-aws-profile)
		if strings.HasPrefix(serviceName, constants.AWSServicePrefix) {
			profile = strings.TrimPrefix(serviceName, fmt.Sprintf("%s-", constants.AWSServicePrefix))
		}

		// Create descriptive name and description
		name := serviceName
		description := "AWS MFA"

		if profile != "" {
			name = fmt.Sprintf("AWS (%s)", profile)
			description = fmt.Sprintf("AWS MFA for profile %s", profile)
		}

		// Create a unique ID that contains both the service and account
		id := fmt.Sprintf("%s:%s", serviceName, entry.Account)

		result = append(result, provider.ProviderEntry{
			Name:        name,
			Description: description,
			ID:          id,
		})
	}

	return result, nil
}

// getAWSProfiles reads AWS profiles from ~/.aws/config
func (p *Provider) getAWSProfiles() ([]string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	configPath := filepath.Join(homeDir, ".aws", "config")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var profiles []string
	profiles = append(profiles, "default") // Always include default

	// Parse the config file to extract profile names
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[profile ") && strings.HasSuffix(line, "]") {
			profile := strings.TrimPrefix(line, "[profile ")
			profile = strings.TrimSuffix(profile, "]")
			profiles = append(profiles, strings.TrimSpace(profile))
		}
	}

	return profiles, nil
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
	if strings.HasPrefix(service, constants.AWSServicePrefix) {
		serialService := strings.Replace(service, constants.AWSServicePrefix, constants.AWSServiceMFAPrefix, 1)
		if err := p.keychain.DeleteEntry(account, serialService); err != nil {
			// Log but don't fail if serial entry deletion fails
			fmt.Fprintf(os.Stderr, "Warning: Failed to delete serial entry %s: %v\n", serialService, err)
		}
	}

	return nil
}

// GetProfile returns the current AWS profile
func (p *Provider) GetProfile() string {
	return p.profile
}

// GetTOTPKeyInfo returns the user and key name for TOTP generation
func (p *Provider) GetTOTPKeyInfo() (string, string, error) {
	// Get the current user if not already set
	if p.keyUser == "" {
		var err error
		p.keyUser, err = env.GetCurrentUser()
		if err != nil {
			return "", "", fmt.Errorf("could not determine current user: %w", err)
		}
	}

	// Determine the keychain key name based on profile
	var keyName string
	if p.profile == "" {
		// Use default for the default profile
		keyName = fmt.Sprintf("%s-default", p.keyName)
	} else {
		keyName = fmt.Sprintf("%s-%s", p.keyName, p.profile)
	}

	return p.keyUser, keyName, nil
}

// GetMFASerialBytes returns the MFA device serial as bytes
func (p *Provider) GetMFASerialBytes() ([]byte, error) {
	// Use the same logic as in GetCredentials but just return the serial
	// Service name for the MFA serial (account for profile)
	var serialService string

	// Get current user if not set
	if p.keyUser == "" {
		var err error
		p.keyUser, err = env.GetCurrentUser()
		if err != nil {
			return nil, fmt.Errorf("could not determine current user: %w", err)
		}
	}

	if p.profile == "" {
		// Use default for the default profile
		serialService = fmt.Sprintf("%s-default", constants.AWSServiceMFAPrefix)
	} else {
		serialService = fmt.Sprintf("%s-%s", constants.AWSServiceMFAPrefix, p.profile)
	}

	// Get MFA serial using the provider interface
	serialBytes, err := p.keychain.GetSecret(p.keyUser, serialService)
	if err == nil {
		// Make defensive copy
		result := make([]byte, len(serialBytes))
		copy(result, serialBytes)
		secure.SecureZeroBytes(serialBytes)
		return result, nil
	}

	// If not found in keychain, try to auto-detect from AWS
	serial, err := p.aws.GetFirstMFADevice(p.profile)
	if err != nil {
		return nil, fmt.Errorf("could not detect MFA device: %w", err)
	}

	// Convert string to bytes - in this case, we're returning a new allocation
	// so no need to worry about cleanup of the original
	return []byte(serial), nil
}

// GetMFASerial returns the MFA device serial as a string
// This is a compatibility method that uses GetMFASerialBytes internally
func (p *Provider) GetMFASerial() (string, error) {
	serialBytes, err := p.GetMFASerialBytes()
	if err != nil {
		return "", err
	}
	
	// Convert to string and zero the bytes
	serial := string(serialBytes)
	secure.SecureZeroBytes(serialBytes)
	return serial, nil
}

// NewSubshellConfig creates a subshell configuration for AWS credentials
func (p *Provider) NewSubshellConfig(creds provider.Credentials) interface{} {
	return subshell.Config{
		ServiceName:     p.Name(),
		Variables:       creds.Variables,
		Expiry:          creds.Expiry,
		ShellCustomizer: awsInternal.NewCustomizer(),
	}
}