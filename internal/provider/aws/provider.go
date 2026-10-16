// Package aws implements the AWS provider for sesh, handling MFA-based session credentials.
package aws

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	awsInternal "github.com/bashhack/sesh/internal/aws"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/secure"
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

	// Sleep waits between tries; nil is time.Sleep. Tests replace it.
	Sleep func(time.Duration)

	profile    string
	filing     provider.FilingFlags
	noSubshell bool
}

var _ provider.ServiceProvider = (*Provider)(nil)

// NewProvider creates a new AWS provider.
func NewProvider(aws awsInternal.Provider, store vault.Store, totp internalTotp.Provider) *Provider {
	return &Provider{aws: aws, store: store, totp: totp}
}

// WithStore is p over store: its flags are parsed first, so a mistake in
// them is said before the vault is unlocked.
func (p *Provider) WithStore(store vault.Store) *Provider {
	p.store = store
	return p
}

// Name returns the provider name.
func (p *Provider) Name() string {
	return "aws"
}

// SetupFlags adds provider-specific flags to the given FlagSet
func (p *Provider) SetupFlags(fs provider.FlagSet) error {
	fs.StringVar(&p.profile, "profile", envProfile(), "AWS CLI profile to use")
	fs.BoolVar(&p.noSubshell, "no-subshell", false, "Print environment variables instead of launching subshell")
	p.filing.Register(fs)
	return nil
}

// readSecret is the profile's MFA key, from the vault; the caller zeroes it.
func (p *Provider) readSecret() ([]byte, error) {
	secret, err := p.store.Get(vault.AWSKey(p.profile))
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve TOTP secret for AWS %s: %w", formatProfile(p.profile), err)
	}
	fmt.Fprintf(os.Stderr, "🔑 Retrieved secret from the vault\n")
	return secret, nil
}

// GetTOTPCodes retrieves TOTP codes without performing AWS authentication
func (p *Provider) GetTOTPCodes() (currentCode, nextCode string, secondsLeft int64, err error) {
	secret, err := p.readSecret()
	if err != nil {
		return "", "", 0, err
	}
	defer secure.SecureZeroBytes(secret)
	currentCode, nextCode, err = p.totp.GenerateConsecutiveCodesBytes(secret)
	if err != nil {
		return "", "", 0, fmt.Errorf("could not generate TOTP codes: %w", err)
	}
	return currentCode, nextCode, p.SecondsLeftInWindow(), nil
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

// sessionToken asks AWS for a session with the current code made from
// secret.
func (p *Provider) sessionToken(serial string, secret []byte) (awsInternal.Credentials, error) {
	code, err := p.totp.GenerateForTimeBytes(secret, p.TimeNow())
	if err != nil {
		return awsInternal.Credentials{}, fmt.Errorf("could not generate a TOTP code: %w", err)
	}
	codeBytes := []byte(code)
	defer secure.SecureZeroBytes(codeBytes)
	return p.aws.GetSessionToken(p.profile, serial, codeBytes)
}

// GetCredentials asks AWS for a session with the current MFA code. AWS
// refuses a code it has already accepted (sesh aws run twice within its 30
// seconds, say), so when it refuses one, sesh waits for the next code and
// tries once more with it.
func (p *Provider) GetCredentials() (provider.Credentials, error) {
	serialBytes, err := p.GetMFASerialBytes()
	if err != nil {
		return provider.Credentials{}, err
	}

	serial := string(serialBytes)
	defer secure.SecureZeroBytes(serialBytes)

	fmt.Fprintf(os.Stderr, "🔍 Using MFA serial: %s\n", serial)

	secret, err := p.readSecret()
	if err != nil {
		return provider.Credentials{}, err
	}
	defer secure.SecureZeroBytes(secret)

	awsCreds, err := p.sessionToken(serial, secret)
	if err != nil && strings.Contains(err.Error(), awsInternal.SessionCredentialsMessage) {
		return provider.Credentials{}, fmt.Errorf("%s signs in with temporary credentials (aws login, SSO or a role), and AWS gives MFA sessions only to an IAM user's own access keys: use a profile with those for sesh aws: %w", formatProfile(p.profile), err)
	}
	if err != nil && strings.Contains(err.Error(), awsInternal.InvalidMFAMessage) {
		wait := time.Duration(p.SecondsLeftInWindow()+1) * time.Second
		fmt.Fprintf(os.Stderr, "⚠️  AWS refused the code; it may have been used in the last 30 seconds. Waiting %s for the next one...\n", wait)
		p.sleep(wait)
		awsCreds, err = p.sessionToken(serial, secret)
		if err != nil && strings.Contains(err.Error(), awsInternal.InvalidMFAMessage) {
			return provider.Credentials{}, fmt.Errorf("AWS refused the next code too. Just after sesh aws setup, AWS has used that code too: wait 30 seconds and try again. Otherwise check this computer's clock is right, and that %s's MFA device is the one this key was set up for (sesh aws setup sets it up again): %w", formatProfile(p.profile), err)
		}
	}
	if err != nil {
		return provider.Credentials{}, fmt.Errorf("failed to get session token: %w", err)
	}

	defer awsCreds.Clear()

	expiryTime, err := time.Parse(time.RFC3339, awsCreds.Expiration)
	if err != nil {
		expiryTime = p.TimeNow().Add(12 * time.Hour) // AWS's default session length for an IAM user
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

// sleep waits d; tests replace it.
func (p *Provider) sleep(d time.Duration) {
	if p.Sleep != nil {
		p.Sleep(d)
		return
	}
	time.Sleep(d)
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
		return fmt.Errorf("no AWS entry found for %s. Run 'sesh aws setup' first", formatProfile(p.profile))
	}
	if err := checkAWSCodes(e.Settings.TOTP); err != nil {
		return fmt.Errorf("the AWS entry for %s %w; set it up again with 'sesh aws setup'", formatProfile(p.profile), err)
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
	return append([]provider.FlagInfo{
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
	}, p.filing.FlagInfo()...)
}

// Filing is what --folder and --tag say, for sesh aws setup.
func (p *Provider) Filing() vault.Filing { return p.filing.Filing() }

// ShouldUseSubshell returns whether to use subshell mode
func (p *Provider) ShouldUseSubshell() bool {
	return !p.noSubshell
}

// envProfile is the profile the environment names, as the AWS CLI reads
// it: AWS_PROFILE, or else AWS_DEFAULT_PROFILE.
func envProfile() string {
	if p := os.Getenv("AWS_PROFILE"); p != "" {
		return p
	}
	return os.Getenv("AWS_DEFAULT_PROFILE")
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

// CheckArgs refuses a profile name no entry can have, without the vault,
// so the CLI can stop before opening it. The profile can come from
// AWS_PROFILE rather than --profile; the error says so.
func (p *Provider) CheckArgs() error {
	err := vault.CheckName("AWS profile", p.profile)
	if err != nil && p.profile == os.Getenv("AWS_PROFILE") {
		return fmt.Errorf("AWS_PROFILE: %w", err)
	}
	return err
}
