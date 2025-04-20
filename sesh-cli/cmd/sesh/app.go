package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/bashhack/sesh/internal/aws"
	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/setup"
	"github.com/bashhack/sesh/internal/totp"
)

// ExecLookPathFunc is a function type for looking up executables in PATH
type ExecLookPathFunc func(file string) (string, error)

// ExitFunc is a function type for exiting the program
type ExitFunc func(code int)

// App represents the main application
type App struct {
	AWS          aws.Provider
	Keychain     keychain.Provider
	TOTP         totp.Provider
	SetupWizard  setup.WizardRunner
	ExecLookPath ExecLookPathFunc
	Exit         ExitFunc
	Stdout       io.Writer
	Stderr       io.Writer
	VersionInfo  VersionInfo
}

// VersionInfo contains version information
type VersionInfo struct {
	Version string
	Commit  string
	Date    string
}

// NewDefaultApp creates a new App with default dependencies
func NewDefaultApp() *App {
	return &App{
		AWS:          aws.NewDefaultProvider(),
		Keychain:     keychain.NewDefaultProvider(),
		TOTP:         totp.NewDefaultProvider(),
		SetupWizard:  setup.DefaultWizardRunner{},
		ExecLookPath: exec.LookPath,
		Exit:         os.Exit,
		Stdout:       os.Stdout,
		Stderr:       os.Stderr,
		VersionInfo: VersionInfo{
			Version: version,
			Commit:  commit,
			Date:    date,
		},
	}
}

// ShowVersion displays version information
func (a *App) ShowVersion() {
	fmt.Fprintf(a.Stdout, "sesh version %s (%s) built on %s\n",
		a.VersionInfo.Version, a.VersionInfo.Commit, a.VersionInfo.Date)
}

// CheckAwsCliInstalled checks if AWS CLI is installed
func (a *App) CheckAwsCliInstalled() bool {
	_, err := a.ExecLookPath("aws")
	if err != nil {
		fmt.Fprintf(a.Stderr, "❌ AWS CLI not found. Please install it first: https://aws.amazon.com/cli/\n")
		a.Exit(1)
		return false
	}
	return true
}

// GetMFASerial attempts to get an MFA serial from keychain or AWS
func (a *App) GetMFASerial(profile, user, providedSerial string) (string, error) {
	if providedSerial != "" {
		return providedSerial, nil
	}

	serialFromKeychain, err := a.Keychain.GetMFASerial(user)
	if err == nil {
		return serialFromKeychain, nil
	}

	serial, err := a.AWS.GetFirstMFADevice(profile)
	if err != nil {
		return "", fmt.Errorf("could not detect MFA device: %w", err)
	}

	return serial, nil
}

// GetTOTPSecret retrieves the TOTP secret from keychain
func (a *App) GetTOTPSecret(user, keyName string) (string, error) {
	secret, err := a.Keychain.GetSecret(user, keyName)
	if err != nil {
		return "", err
	}
	return secret, nil
}

// GenerateCredentials generates AWS credentials using the TOTP code
func (a *App) GenerateCredentials(profile, serial, secret string) (aws.Credentials, time.Duration, error) {
	startTime := time.Now()

	code, err := a.TOTP.Generate(secret)
	if err != nil {
		return aws.Credentials{}, 0, fmt.Errorf("could not generate TOTP code: %w", err)
	}

	fmt.Fprintf(a.Stderr, "🔐 Generating temporary credentials with MFA...\n")
	creds, err := a.AWS.GetSessionToken(profile, serial, code)
	if err != nil {
		return aws.Credentials{}, 0, fmt.Errorf("failed to get session token: %w", err)
	}

	elapsedTime := time.Since(startTime)
	return creds, elapsedTime, nil
}

// FormatExpiryTime formats the expiry time of credentials
func (a *App) FormatExpiryTime(expirationStr string) string {
	expiryDisplay := expirationStr
	expiryTime, err := time.Parse(time.RFC3339, expirationStr)
	if err == nil {
		duration := time.Until(expiryTime)
		hours := int(duration.Hours())
		minutes := int(duration.Minutes()) % 60
		expiryDisplay = fmt.Sprintf("%s (valid for %dh%dm)",
			expiryTime.Local().Format("2006-01-02 15:04:05"), hours, minutes)
	}
	return expiryDisplay
}

// PrintCredentials outputs the credentials in a format that can be eval'd
func (a *App) PrintCredentials(creds aws.Credentials) {
	expiryDisplay := a.FormatExpiryTime(creds.Expiration)
	fmt.Fprintf(a.Stdout, "export AWS_ACCESS_KEY_ID=%s\n", creds.AccessKeyId)
	fmt.Fprintf(a.Stdout, "export AWS_SECRET_ACCESS_KEY=%s\n", creds.SecretAccessKey)
	fmt.Fprintf(a.Stdout, "export AWS_SESSION_TOKEN=%s\n", creds.SessionToken)
	fmt.Fprintf(a.Stdout, "# ⏳ Expires at: %s\n", expiryDisplay)
}

// PrintMFAError prints suggestions for resolving MFA detection errors
func (a *App) PrintMFAError(err error) {
	fmt.Fprintf(a.Stderr, "❌ %v\n", err)
	fmt.Fprintln(a.Stderr, "\nPossible solutions:")
	fmt.Fprintln(a.Stderr, "  1. Provide your MFA ARN explicitly:")
	fmt.Fprintln(a.Stderr, "     - Use --serial arn:aws:iam::ACCOUNT_ID:mfa/YOUR_USERNAME")
	fmt.Fprintln(a.Stderr, "     - Or set the SESH_MFA_SERIAL environment variable")
	fmt.Fprintln(a.Stderr, "  2. Check your AWS credentials are configured correctly:")
	fmt.Fprintln(a.Stderr, "     - Run 'aws configure' to set up your access keys")
	fmt.Fprintln(a.Stderr, "     - Make sure MFA is enabled for your IAM user")
	fmt.Fprintln(a.Stderr, "     - Check that you can run 'aws iam list-mfa-devices'")
}

// PrintKeychainError prints suggestions for resolving keychain errors
func (a *App) PrintKeychainError(err error, user, keyName string) {
	fmt.Fprintf(a.Stderr, "❌ Could not retrieve TOTP secret from Keychain: %v\n", err)
	fmt.Fprintln(a.Stderr, "\nTo fix this:")
	fmt.Fprintln(a.Stderr, "  1. Run the setup wizard to configure your TOTP secret:")
	fmt.Fprintln(a.Stderr, "     - Run 'sesh --setup'")
	fmt.Fprintln(a.Stderr, "  2. If you've already run setup, check your keychain settings:")
	fmt.Fprintln(a.Stderr, "     - Make sure you're using the correct keychain username with --keychain-user")
	fmt.Fprintln(a.Stderr, "     - Make sure you're using the correct keychain service name with --keychain-name")
	fmt.Fprintln(a.Stderr, "     - Default values: username="+user+", service="+keyName)
}

// PrintSessionTokenError prints suggestions for resolving session token errors
func (a *App) PrintSessionTokenError(err error) {
	fmt.Fprintf(a.Stderr, "❌ %v\n", err)
	fmt.Fprintln(a.Stderr, "\nTroubleshooting tips:")
	fmt.Fprintln(a.Stderr, "  1. Verify your AWS credentials are correctly configured:")
	fmt.Fprintln(a.Stderr, "     - Run 'aws configure' to set up your access keys")
	fmt.Fprintln(a.Stderr, "     - Check that the AWS_PROFILE environment variable is set correctly")
	fmt.Fprintln(a.Stderr, "  2. Verify your MFA serial ARN is correct:")
	fmt.Fprintln(a.Stderr, "     - Specify it with --serial arn:aws:iam::ACCOUNT_ID:mfa/YOUR_USERNAME")
	fmt.Fprintln(a.Stderr, "     - Or set the SESH_MFA_SERIAL environment variable")
	fmt.Fprintln(a.Stderr, "  3. Check AWS CLI installation and connectivity:")
	fmt.Fprintln(a.Stderr, "     - Ensure you can run 'aws sts get-caller-identity'")
}
