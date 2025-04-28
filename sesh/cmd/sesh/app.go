package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/bashhack/sesh/internal/aws"
	"github.com/bashhack/sesh/internal/clipboard"
	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/provider"
	awsProvider "github.com/bashhack/sesh/internal/provider/aws"
	totpProvider "github.com/bashhack/sesh/internal/provider/totp"
	"github.com/bashhack/sesh/internal/setup"
	"github.com/bashhack/sesh/internal/totp"
)

// ExecLookPathFunc is a function type for looking up executables in PATH
type ExecLookPathFunc func(file string) (string, error)

// ExitFunc is a function type for exiting the program
type ExitFunc func(code int)

// App represents the main application
type App struct {
	Registry    *provider.Registry
	AWS         aws.Provider
	Keychain    keychain.Provider
	TOTP        totp.Provider
	SetupWizard setup.WizardRunner
	ExecLookPath ExecLookPathFunc
	Exit        ExitFunc
	Stdout      io.Writer
	Stderr      io.Writer
	VersionInfo VersionInfo
}

// VersionInfo contains version information
type VersionInfo struct {
	Version string
	Commit  string
	Date    string
}

// initializeBinaryPath is kept for compatibility but is now a no-op
// since binary path is determined at the time of keychain access
func initializeBinaryPath() {
	// Binary path is now determined dynamically at the time of each keychain access
	// This ensures the correct path is always used regardless of initialization order
}

// NewDefaultApp creates a new App with default dependencies
func NewDefaultApp() *App {
	// Initialize binary path for keychain security
	initializeBinaryPath()
	
	app := &App{
		Registry:    provider.NewRegistry(),
		AWS:         aws.NewDefaultProvider(),
		Keychain:    keychain.NewDefaultProvider(),
		TOTP:        totp.NewDefaultProvider(),
		SetupWizard: setup.DefaultWizardRunner{},
		ExecLookPath: exec.LookPath,
		Exit:        os.Exit,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		VersionInfo: VersionInfo{
			Version: version,
			Commit:  commit,
			Date:    date,
		},
	}
	
	// Register providers
	app.registerProviders()
	
	return app
}

// registerProviders registers all available service providers
func (a *App) registerProviders() {
	// Register AWS provider
	a.Registry.RegisterProvider(awsProvider.NewProvider(
		a.AWS,
		a.Keychain,
		a.TOTP,
		a.SetupWizard,
	))
	
	// Register generic TOTP provider
	a.Registry.RegisterProvider(totpProvider.NewProvider(
		a.Keychain,
		a.TOTP,
		a.SetupWizard,
	))
}

// ShowVersion displays version information
func (a *App) ShowVersion() {
	fmt.Fprintf(a.Stdout, "sesh version %s (%s) built on %s\n",
		a.VersionInfo.Version, a.VersionInfo.Commit, a.VersionInfo.Date)
}

// ListProviders lists all available service providers
func (a *App) ListProviders() {
	fmt.Fprintln(a.Stdout, "Available service providers:")
	
	for _, p := range a.Registry.ListProviders() {
		fmt.Fprintf(a.Stdout, "  %-10s %s\n", p.Name(), p.Description())
	}
}

// ListEntries lists all entries for a service
func (a *App) ListEntries(serviceName string) error {
	p, err := a.Registry.GetProvider(serviceName)
	if err != nil {
		return fmt.Errorf("provider not found: %w", err)
	}
	
	entries, err := p.ListEntries()
	if err != nil {
		return fmt.Errorf("failed to list entries: %w", err)
	}
	
	fmt.Fprintf(a.Stdout, "Entries for %s:\n", serviceName)
	if len(entries) == 0 {
		fmt.Fprintln(a.Stdout, "  No entries found")
		return nil
	}
	
	for _, entry := range entries {
		fmt.Fprintf(a.Stdout, "  %-20s %s [ID: %s]\n", 
			entry.Name, entry.Description, entry.ID)
	}
	
	return nil
}

// DeleteEntry deletes an entry from the keychain
func (a *App) DeleteEntry(serviceName, entryID string) error {
	p, err := a.Registry.GetProvider(serviceName)
	if err != nil {
		return fmt.Errorf("provider not found: %w", err)
	}
	
	if err := p.DeleteEntry(entryID); err != nil {
		return fmt.Errorf("failed to delete entry: %w", err)
	}
	
	fmt.Fprintf(a.Stdout, "✅ Entry deleted successfully\n")
	return nil
}

// RunSetup runs the setup wizard for a provider
func (a *App) RunSetup(serviceName string) error {
	p, err := a.Registry.GetProvider(serviceName)
	if err != nil {
		return fmt.Errorf("provider not found: %w", err)
	}
	
	return p.Setup()
}

// GenerateCredentials gets credentials from a provider
func (a *App) GenerateCredentials(serviceName string) error {
	p, err := a.Registry.GetProvider(serviceName)
	if err != nil {
		return fmt.Errorf("provider not found: %w", err)
	}
	
	fmt.Fprintf(a.Stderr, "🔐 Generating credentials for %s...\n", serviceName)
	startTime := time.Now()
	
	creds, err := p.GetCredentials()
	if err != nil {
		return fmt.Errorf("failed to generate credentials: %w", err)
	}
	
	elapsedTime := time.Since(startTime)
	fmt.Fprintf(a.Stderr, "✅ Credentials acquired in %.2fs\n", elapsedTime.Seconds())
	
	a.PrintCredentials(creds)
	return nil
}

// CopyToClipboard copies a value to the system clipboard
func (a *App) CopyToClipboard(serviceName string) error {
	p, err := a.Registry.GetProvider(serviceName)
	if err != nil {
		return fmt.Errorf("provider not found: %w", err)
	}
	
	// Special handling for AWS service to bypass credential generation when using -clip
	if serviceName == "aws" {
		return a.copyAWSTotp(p)
	}
	
	// Standard flow for non-AWS services
	fmt.Fprintf(a.Stderr, "🔐 Generating credentials for %s...\n", serviceName)
	startTime := time.Now()
	
	creds, err := p.GetCredentials()
	if err != nil {
		return fmt.Errorf("failed to generate credentials: %w", err)
	}
	
	elapsedTime := time.Since(startTime)
	
	// Make sure we have a valid copy value
	var copyValue string
	if creds.CopyValue != "" {
		copyValue = creds.CopyValue
	} else if serviceName == "totp" && len(creds.Variables) > 0 {
		// Fallback for TOTP providers - try to get TOTP_CODE from Variables
		if code, exists := creds.Variables["TOTP_CODE"]; exists {
			copyValue = code
		}
	} else if serviceName == "aws" && len(creds.Variables) > 0 {
		// For AWS, if CopyValue is missing, create a shell export script
		var exports string
		for key, value := range creds.Variables {
			exports += fmt.Sprintf("export %s=\"%s\"\n", key, value)
		}
		copyValue = exports
	}
	
	// Validate that we have something to copy
	if copyValue == "" {
		return fmt.Errorf("no content available to copy to clipboard")
	}
	
	// Copy to clipboard
	if err := clipboard.Copy(copyValue); err != nil {
		return fmt.Errorf("failed to copy to clipboard: %w", err)
	}
	
	// Show what was copied
	var clipboardDesc string
	switch serviceName {
	case "totp":
		clipboardDesc = "TOTP code"
	default:
		clipboardDesc = "value"
	}
	
	fmt.Fprintf(a.Stderr, "✅ %s copied to clipboard in %.2fs\n", clipboardDesc, elapsedTime.Seconds())
	fmt.Fprintf(a.Stdout, "%s\n", creds.DisplayInfo)
	
	return nil
}

// copyAWSTotp is a special handler for copying AWS TOTP codes to clipboard
// that bypasses the AWS API authentication to avoid time-sync issues
func (a *App) copyAWSTotp(p provider.ServiceProvider) error {
	fmt.Fprintf(a.Stderr, "🔐 Generating AWS TOTP code...\n")
	startTime := time.Now()
	
	// We need to access AWS provider's specific properties to get the profile
	awsProvider, ok := p.(*awsProvider.Provider)
	if !ok {
		return fmt.Errorf("failed to convert to AWS provider")
	}
	
	// Access the AWS provider's TOTP generator and keychain
	profile := awsProvider.GetProfile()
	keyUser, keyName, err := awsProvider.GetTOTPKeyInfo()
	if err != nil {
		return fmt.Errorf("failed to get TOTP key info: %w", err)
	}
	
	// Get the secret directly using the keychain provider
	secret, err := a.Keychain.GetSecret(keyUser, keyName)
	if err != nil {
		return fmt.Errorf("could not retrieve TOTP secret: %w", err)
	}
	
	// Generate codes directly using the TOTP provider
	currentCode, nextCode, err := a.TOTP.GenerateConsecutiveCodes(secret)
	if err != nil {
		return fmt.Errorf("could not generate TOTP codes: %w", err)
	}
	
	// Get MFA serial for display purposes
	serial, err := awsProvider.GetMFASerial()
	if err != nil {
		serial = "unknown MFA device"
	}
	
	// Copy the current code to clipboard
	if err := clipboard.Copy(currentCode); err != nil {
		return fmt.Errorf("failed to copy to clipboard: %w", err)
	}
	
	// Calculate seconds left
	secondsLeft := 30 - (time.Now().Unix() % 30)
	elapsedTime := time.Since(startTime)
	
	// Format display information
	var title string
	if profile == "" {
		title = "🔑 AWS web console login code (default profile)"
	} else {
		title = fmt.Sprintf("🔑 AWS web console login code (profile: %s)", profile)
	}
	
	// Print to stdout
	fmt.Fprintf(a.Stderr, "✅ Web console login code '%s' copied to clipboard in %.2fs\n", currentCode, elapsedTime.Seconds())
	fmt.Fprintf(a.Stdout, "%s\n\n", title)
	fmt.Fprintf(a.Stdout, "Current code: %s\n", currentCode)
	fmt.Fprintf(a.Stdout, "Next code: %s\n", nextCode)
	fmt.Fprintf(a.Stdout, "MFA device: %s\n", serial)
	fmt.Fprintf(a.Stdout, "Time remaining: %d seconds\n", secondsLeft)
	
	// Add warning if we're close to expiry
	if secondsLeft < 5 {
		fmt.Fprintln(a.Stdout, "⚠️  Warning: Current TOTP code will expire in less than 5 seconds!")
	}
	
	return nil
}

// PrintCredentials outputs the credentials
func (a *App) PrintCredentials(creds provider.Credentials) {
	// Format expiry time
	expiryDisplay := "unknown"
	if !creds.Expiry.IsZero() {
		duration := time.Until(creds.Expiry)
		hours := int(duration.Hours())
		minutes := int(duration.Minutes()) % 60
		expiryDisplay = fmt.Sprintf("%s (valid for %dh%dm)",
			creds.Expiry.Local().Format("2006-01-02 15:04:05"), hours, minutes)
	}
	
	// First show human-readable information
	fmt.Fprintf(a.Stdout, "⏳ Expires at: %s\n", expiryDisplay)
	
	if creds.DisplayInfo != "" {
		fmt.Fprintf(a.Stdout, "%s\n", creds.DisplayInfo)
	}
	
	// Then add a separator before environment variables 
	fmt.Fprintf(a.Stdout, "\n# --------- ENVIRONMENT VARIABLES ---------\n")
	
	// Output export commands
	for key, value := range creds.Variables {
		fmt.Fprintf(a.Stdout, "export %s=%s\n", key, value)
	}
	
	// Add a separator after environment variables
	fmt.Fprintf(a.Stdout, "# ----------------------------------------\n")
}