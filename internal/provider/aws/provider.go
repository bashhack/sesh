package aws

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	awsInternal "github.com/bashhack/sesh/internal/aws"
	"github.com/bashhack/sesh/internal/constants"
	"github.com/bashhack/sesh/internal/env"
	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/keyformat"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/setup"
	"github.com/bashhack/sesh/internal/subshell"
	internalTotp "github.com/bashhack/sesh/internal/totp"
)

// Provider implements ServiceProvider for AWS.
type Provider struct {
	aws      awsInternal.Provider
	keychain keychain.Provider
	totp     internalTotp.Provider

	provider.Clock
	provider.KeyUser

	profile    string
	keyName    string
	noSubshell bool
}

var _ provider.ServiceProvider = (*Provider)(nil)

// NewProvider creates a new AWS provider.
func NewProvider(
	aws awsInternal.Provider,
	kc keychain.Provider,
	totp internalTotp.Provider,
) *Provider {
	return &Provider{
		aws:      aws,
		keychain: kc,
		totp:     totp,
		keyName:  constants.AWSServicePrefix,
	}
}

// Name returns the provider name.
func (p *Provider) Name() string {
	return "aws"
}

// Description returns the provider description.
func (p *Provider) Description() string {
	return "Amazon Web Services CLI authentication"
}

// SetupFlags adds provider-specific flags to the given FlagSet
func (p *Provider) SetupFlags(fs provider.FlagSet) error {
	fs.StringVar(&p.profile, "profile", os.Getenv("AWS_PROFILE"), "AWS CLI profile to use")
	fs.BoolVar(&p.noSubshell, "no-subshell", false, "Print environment variables instead of launching subshell")

	defaultKeyUser, err := env.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}
	p.User = defaultKeyUser
	return nil
}

// GetSetupHandler returns a setup handler for AWS
func (p *Provider) GetSetupHandler() any {
	return setup.NewAWSSetupHandler(p.keychain)
}

// GetTOTPCodes retrieves TOTP codes without performing AWS authentication
func (p *Provider) GetTOTPCodes() (currentCode, nextCode string, secondsLeft int64, err error) {
	if err := p.EnsureUser(); err != nil {
		return "", "", 0, err
	}

	keyName, err := buildServiceKey(p.keyName, p.profile)
	if err != nil {
		return "", "", 0, fmt.Errorf("failed to build service key: %w", err)
	}

	secretBytes, err := p.keychain.GetSecret(p.User, keyName)
	if err != nil {
		return "", "", 0, fmt.Errorf("failed to retrieve TOTP secret for AWS %s: %w", formatProfile(p.profile), err)
	}

	secretCopy := make([]byte, len(secretBytes))
	copy(secretCopy, secretBytes)
	defer secure.SecureZeroBytes(secretCopy)

	secure.SecureZeroBytes(secretBytes)

	fmt.Fprintf(os.Stderr, "🔑 Retrieved secret from keychain\n")

	// Check if secret looks valid (base32 encoded)
	secretLen := len(secretCopy)
	if secretLen < 16 || secretLen > 64 {
		fmt.Fprintf(os.Stderr, "⚠️ Warning: TOTP secret has unusual length: %d characters\n", secretLen)
	}

	currentCode, nextCode, err = p.totp.GenerateConsecutiveCodesBytes(secretCopy)
	if err != nil {
		return "", "", 0, fmt.Errorf("could not generate TOTP codes: %w", err)
	}

	secondsLeft = p.SecondsLeftInWindow()

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

	profileStr := formatProfile(p.profile)

	return provider.CreateClipboardCredentials(p.Name(), currentCode, nextCode, secondsLeft,
		"AWS MFA code", profileStr), nil
}

// GetCredentials retrieves AWS credentials using TOTP
func (p *Provider) GetCredentials() (provider.Credentials, error) {
	serialBytes, err := p.GetMFASerialBytes()
	if err != nil {
		return provider.Credentials{}, err
	}

	serial := string(serialBytes)
	defer secure.SecureZeroBytes(serialBytes)

	fmt.Fprintf(os.Stderr, "🔍 Using MFA serial: %s\n", serial)

	currentCode, nextCode, secondsLeft, err := p.GetTOTPCodes()
	if err != nil {
		return provider.Credentials{}, err
	}

	code := currentCode

	codeBytes := []byte(code)
	awsCreds, err := p.aws.GetSessionToken(p.profile, serial, codeBytes)
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
			fmt.Fprintf(os.Stderr, "🔑 Trying with next time window's code\n")
			code = nextCode
			codeBytes = []byte(code)
			awsCreds, err = p.aws.GetSessionToken(p.profile, serial, codeBytes)
			secure.SecureZeroBytes(codeBytes)

			// Re-evaluate whether the second attempt also failed with an invalid MFA error
			secondInvalidMFA := err != nil &&
				strings.Contains(err.Error(), "MultiFactorAuthentication failed with invalid MFA one time pass code")

			// If STILL failing with invalid MFA and we're not close to boundary,
			// we may need to wait for the next time window
			freshSecondsLeft := p.SecondsLeftInWindow()
			if secondInvalidMFA && freshSecondsLeft > 10 {
				fmt.Fprintf(os.Stderr, "⚠️ Both current and next codes were rejected - may need to wait for next time window\n")

				keyName, kErr := buildServiceKey(p.keyName, p.profile)
				if kErr != nil {
					return provider.Credentials{}, fmt.Errorf("failed to build service key: %w", kErr)
				}

				secretBytes, fetchErr := p.keychain.GetSecret(p.User, keyName)
				if fetchErr != nil {
					return provider.Credentials{}, fmt.Errorf("failed to retrieve TOTP secret for AWS %s: %w", formatProfile(p.profile), fetchErr)
				}

				secretCopy := make([]byte, len(secretBytes))
				copy(secretCopy, secretBytes)
				defer secure.SecureZeroBytes(secretCopy)

				secure.SecureZeroBytes(secretBytes)

				// Generate a code for the window after next, in case AWS is far ahead of our clock
				futureCode, gErr := p.totp.GenerateForTimeBytes(secretCopy, p.TimeNow().Add(60*time.Second))
				if gErr == nil {
					fmt.Fprintf(os.Stderr, "🔑 Trying with future time window's code\n")
					code = futureCode
					codeBytes = []byte(code)
					awsCreds, err = p.aws.GetSessionToken(p.profile, serial, codeBytes)
					secure.SecureZeroBytes(codeBytes)
				}
			}
		}
	}

	if err != nil {
		// Check if this looks like a "code already used" error
		if strings.Contains(err.Error(), "MultiFactorAuthentication failed with invalid MFA one time pass code") {
			// Add more context to the error message
			return provider.Credentials{}, fmt.Errorf("failed to get session token (this may be because the TOTP code was recently used; try waiting for the next time window): %w", err)
		}
		return provider.Credentials{}, fmt.Errorf("failed to get session token: %w", err)
	}

	defer awsCreds.ZeroSecrets()

	expiryTime, err := time.Parse(time.RFC3339, awsCreds.Expiration)
	if err != nil {
		expiryTime = p.TimeNow().Add(12 * time.Hour) // Default to 12h if we can't parse
	}

	envVars := map[string]string{
		"AWS_ACCESS_KEY_ID":     awsCreds.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY": awsCreds.SecretAccessKey,
		"AWS_SESSION_TOKEN":     awsCreds.SessionToken,
	}

	profileStr := formatProfile(p.profile)

	return provider.Credentials{
		Provider:         p.Name(),
		Expiry:           expiryTime,
		Variables:        envVars,
		DisplayInfo:      provider.FormatRegularDisplayInfo("AWS credentials", profileStr),
		MFAAuthenticated: true, // If we got this far, AWS STS accepted our MFA code
	}, nil
}

// ListEntries returns all AWS entries in the keychain
func (p *Provider) ListEntries() ([]provider.ProviderEntry, error) {
	allEntries, err := p.keychain.ListEntries(constants.AWSServicePrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list AWS entries: %w", err)
	}

	result := make([]provider.ProviderEntry, 0, len(allEntries))
	for _, entry := range allEntries {
		// Skip MFA serial entries - we don't want to show these to users
		// as they're implementation details and paired with the main entries
		if strings.HasPrefix(entry.Service, constants.AWSServiceMFAPrefix) {
			continue
		}

		serviceName := entry.Service
		profile := parseServiceKey(serviceName)

		name := fmt.Sprintf("AWS (%s)", profile)
		description := fmt.Sprintf("AWS MFA for %s", formatProfile(profile))

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
	data, err := os.ReadFile(configPath) //nolint:gosec // path is constructed from os.UserHomeDir() + hardcoded suffix
	if err != nil {
		return nil, err
	}

	var profiles []string
	profiles = append(profiles, "default") // Always include default

	for line := range strings.SplitSeq(string(data), "\n") {
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
	service, account, err := provider.ParseEntryID(id)
	if err != nil {
		return err
	}

	if err := p.keychain.DeleteEntry(account, service); err != nil {
		return fmt.Errorf("failed to delete AWS entry: %w", err)
	}

	// If this was an AWS entry, also delete the corresponding serial entry
	segments, parseErr := keyformat.Parse(service, constants.AWSServicePrefix)
	if parseErr == nil && len(segments) > 0 {
		serialService, buildErr := keyformat.Build(constants.AWSServiceMFAPrefix, segments...)
		if buildErr == nil {
			if err := p.keychain.DeleteEntry(account, serialService); err != nil {
				// Log but don't fail if serial entry deletion fails
				fmt.Fprintf(os.Stderr, "Warning: Failed to delete serial entry %s: %v\n", serialService, err)
			}
		}
	}

	return nil
}

// GetProfile returns the current AWS profile
func (p *Provider) GetProfile() string {
	return p.profile
}

// GetTOTPKeyInfo returns the user and key name for TOTP generation.
func (p *Provider) GetTOTPKeyInfo() (string, string, error) {
	if err := p.EnsureUser(); err != nil {
		return "", "", err
	}

	keyName, err := buildServiceKey(p.keyName, p.profile)
	if err != nil {
		return "", "", fmt.Errorf("failed to build service key: %w", err)
	}

	return p.User, keyName, nil
}

// GetMFASerialBytes returns the MFA device serial as bytes
func (p *Provider) GetMFASerialBytes() ([]byte, error) {
	if err := p.EnsureUser(); err != nil {
		return nil, err
	}

	var serialService string
	var err error
	serialService, err = buildServiceKey(constants.AWSServiceMFAPrefix, p.profile)
	if err != nil {
		return nil, fmt.Errorf("failed to build MFA service key: %w", err)
	}

	serialBytes, err := p.keychain.GetSecret(p.User, serialService)
	if err == nil {
		result := make([]byte, len(serialBytes))
		copy(result, serialBytes)
		secure.SecureZeroBytes(serialBytes)
		return result, nil
	}

	// Only fall back to auto-detection on "not found" — surface real errors
	if !errors.Is(err, keychain.ErrNotFound) {
		return nil, fmt.Errorf("failed to read MFA serial from keychain: %w", err)
	}

	serial, autoErr := p.aws.GetFirstMFADevice(p.profile)
	if autoErr != nil {
		return nil, fmt.Errorf("failed to detect MFA device: %w", autoErr)
	}

	return []byte(serial), nil
}

// NewSubshellConfig creates a subshell configuration for AWS credentials
func (p *Provider) NewSubshellConfig(creds *provider.Credentials) any {
	return subshell.Config{
		ServiceName:     p.Name(),
		Variables:       creds.Variables,
		Expiry:          creds.Expiry,
		ShellCustomizer: awsInternal.NewCustomizer(),
	}
}

// ValidateRequest performs early validation before any AWS operations.
func (p *Provider) ValidateRequest() error {
	if err := p.EnsureUser(); err != nil {
		return err
	}

	// Check if we have required keychain entries for this profile
	// This prevents slow AWS API calls when no entry exists
	totpKey, err := buildServiceKey(p.keyName, p.profile)
	if err != nil {
		return fmt.Errorf("failed to build service key: %w", err)
	}
	mfaKey, err := buildServiceKey(constants.AWSServiceMFAPrefix, p.profile)
	if err != nil {
		return fmt.Errorf("failed to build MFA service key: %w", err)
	}

	totpSecret, err := p.keychain.GetSecret(p.User, totpKey)
	if err != nil {
		if !errors.Is(err, keychain.ErrNotFound) {
			return fmt.Errorf("failed to read TOTP secret from keychain: %w", err)
		}
		profileDesc := p.profile
		if profileDesc == "" {
			profileDesc = "default"
		}
		return fmt.Errorf("no AWS entry found for profile '%s'. Run 'sesh --service aws --setup' first", profileDesc)
	}
	secure.SecureZeroBytes(totpSecret)

	// Check if MFA serial exists (not critical but helps with better error messages)
	mfaSecret, err := p.keychain.GetSecret(p.User, mfaKey)
	if err != nil {
		if !errors.Is(err, keychain.ErrNotFound) {
			return fmt.Errorf("failed to read MFA serial from keychain: %w", err)
		}
		// Not found is not fatal — we can try to auto-detect, but warn the user
		fmt.Fprintf(os.Stderr, "⚠️  MFA serial not found in keychain for profile '%s', will attempt auto-detection\n", p.profile)
	} else {
		secure.SecureZeroBytes(mfaSecret)
	}

	return nil
}

// GetFlagInfo returns information about AWS provider-specific flags
func (p *Provider) GetFlagInfo() []provider.FlagInfo {
	return []provider.FlagInfo{
		{
			Name:        "profile",
			Type:        "string",
			Description: "AWS CLI profile to use",
			Required:    false,
		},
		{
			Name:        "no-subshell",
			Type:        "bool",
			Description: "Print environment variables instead of launching subshell",
			Required:    false,
		},
	}
}

// ShouldUseSubshell returns whether to use subshell mode
func (p *Provider) ShouldUseSubshell() bool {
	return !p.noSubshell
}

// buildServiceKey creates a service key for the keychain using keyformat.Build.
// Format: {prefix}/{profile} — defaults empty profile to "default".
func buildServiceKey(prefix, profile string) (string, error) {
	if profile == "" {
		profile = "default"
	}
	return keyformat.Build(prefix, profile)
}

// formatProfile returns a formatted profile description
// Returns "profile (default)" or "profile (name)"
func formatProfile(profile string) string {
	name := profile
	if name == "" {
		name = "default"
	}
	return fmt.Sprintf("profile (%s)", name)
}

// parseServiceKey extracts the profile from a service key using keyformat.Parse.
// For "sesh-aws/default" returns "default".
func parseServiceKey(serviceKey string) string {
	segments, err := keyformat.Parse(serviceKey, constants.AWSServicePrefix)
	if err != nil || len(segments) == 0 {
		return ""
	}
	return segments[0]
}
