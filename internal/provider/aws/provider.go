// Package aws implements the AWS provider for sesh, handling MFA-based session credentials.
package aws

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	awsInternal "github.com/bashhack/sesh/internal/aws"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/setup"
	"github.com/bashhack/sesh/internal/subshell"
	internalTotp "github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// Provider implements ServiceProvider for AWS.
type Provider struct {
	aws   awsInternal.Provider
	store vault.Store
	totp  internalTotp.Provider

	provider.Clock

	profile    string
	noSubshell bool
}

var _ provider.ServiceProvider = (*Provider)(nil)

// NewProvider creates a new AWS provider.
func NewProvider(aws awsInternal.Provider, store vault.Store, totp internalTotp.Provider) *Provider {
	return &Provider{aws: aws, store: store, totp: totp}
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
	return nil
}

// GetSetupHandler returns a setup handler for AWS
func (p *Provider) GetSetupHandler() any {
	return setup.NewAWSSetupHandler(p.store)
}

// GetTOTPCodes retrieves TOTP codes without performing AWS authentication
func (p *Provider) GetTOTPCodes() (currentCode, nextCode string, secondsLeft int64, err error) {
	secretBytes, err := p.store.Get(vault.AWSKey(p.profile))
	if err != nil {
		return "", "", 0, fmt.Errorf("failed to retrieve TOTP secret for AWS %s: %w", formatProfile(p.profile), err)
	}

	secretCopy := make([]byte, len(secretBytes))
	copy(secretCopy, secretBytes)
	defer secure.SecureZeroBytes(secretCopy)

	secure.SecureZeroBytes(secretBytes)

	fmt.Fprintf(os.Stderr, "🔑 Retrieved secret from the vault\n")

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

				secretBytes, fetchErr := p.store.Get(vault.AWSKey(p.profile))
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

// ListEntries returns an entry for each AWS profile set up; its ID is its key.
func (p *Provider) ListEntries() ([]provider.ProviderEntry, error) {
	entries, err := p.store.List(vault.Filter{Kind: vault.KindTOTP, Service: vault.AWSKey("").Service})
	if err != nil {
		return nil, fmt.Errorf("failed to list AWS entries: %w", err)
	}
	result := make([]provider.ProviderEntry, 0, len(entries))
	for i := range entries {
		e := &entries[i]
		result = append(result, provider.ProviderEntry{
			Name:        fmt.Sprintf("AWS (%s)", e.Username),
			Description: fmt.Sprintf("AWS MFA for %s", formatProfile(e.Username)),
			ID:          e.Key.String(),
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

// DeleteEntry deletes the AWS profile's entry id names.
func (p *Provider) DeleteEntry(id string) error {
	k, err := vault.ParseKey(id)
	if err != nil {
		return err
	}
	if k != vault.AWSKey(k.Username) {
		return fmt.Errorf("%s isn't an AWS entry; delete it with --service password", id)
	}
	if err := p.store.Delete(k); err != nil {
		return fmt.Errorf("failed to delete AWS entry: %w", err)
	}
	return nil
}

// GetProfile returns the current AWS profile
func (p *Provider) GetProfile() string {
	return p.profile
}

// GetMFASerialBytes returns the profile's MFA device, from its entry's
// settings, or else the first device AWS lists for the profile.
func (p *Provider) GetMFASerialBytes() ([]byte, error) {
	e, err := p.store.Lookup(vault.AWSKey(p.profile))
	if err != nil && !errors.Is(err, vault.ErrNotFound) {
		return nil, fmt.Errorf("failed to read the MFA device: %w", err)
	}
	if err == nil && e.Settings.AWSMFADevice != "" {
		return []byte(e.Settings.AWSMFADevice), nil
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

// ValidateRequest checks the profile is set up before any AWS call, which
// would otherwise be slow to fail.
func (p *Provider) ValidateRequest() error {
	e, err := p.store.Lookup(vault.AWSKey(p.profile))
	if err != nil {
		if !errors.Is(err, vault.ErrNotFound) {
			return fmt.Errorf("failed to look up the AWS entry: %w", err)
		}
		return fmt.Errorf("no AWS entry found for %s. Run 'sesh --service aws --setup' first", formatProfile(p.profile))
	}
	if err := checkAWSCodes(e.Settings.TOTP); err != nil {
		return fmt.Errorf("the AWS entry for %s %w; set it up again with 'sesh --service aws --setup'", formatProfile(p.profile), err)
	}
	if e.Settings.AWSMFADevice == "" {
		// Not fatal: GetMFASerialBytes asks AWS for the profile's device.
		fmt.Fprintf(os.Stderr, "⚠️  No MFA device stored for %s; asking AWS for it\n", formatProfile(p.profile))
	}
	return nil
}

// checkAWSCodes refuses code settings other than AWS's (SHA-1, 6 digits,
// 30 seconds), which the entry can hold when it was set up through the
// TOTP provider: codes made with them would never match.
func checkAWSCodes(params internalTotp.Params) error {
	alg, digits, period := strings.ToUpper(params.Algorithm), params.Digits, params.Period
	if alg == "" {
		alg = "SHA1"
	}
	if digits == 0 {
		digits = 6
	}
	if period == 0 {
		period = 30
	}
	if alg == "SHA1" && digits == 6 && period == 30 {
		return nil
	}
	return fmt.Errorf("has code settings AWS doesn't use (%s, %d digits, %ds)", alg, digits, period)
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

// formatProfile returns a formatted profile description
// Returns "profile (default)" or "profile (name)"
func formatProfile(profile string) string {
	name := profile
	if name == "" {
		name = "default"
	}
	return fmt.Sprintf("profile (%s)", name)
}
