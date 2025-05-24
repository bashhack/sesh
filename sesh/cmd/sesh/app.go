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
	Registry     *provider.Registry
	AWS          aws.Provider
	Keychain     keychain.Provider
	TOTP         totp.Provider
	SetupService setup.SetupService
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
	keychainProvider := keychain.NewDefaultProvider()

	setupService := setup.NewSetupService(keychainProvider)

	app := &App{
		Registry:     provider.NewRegistry(),
		AWS:          aws.NewDefaultProvider(),
		Keychain:     keychainProvider,
		TOTP:         totp.NewDefaultProvider(),
		SetupService: setupService,
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

	app.registerProviders()

	return app
}

// registerProviders registers all available service providers and their setup handlers
func (a *App) registerProviders() {
	// Create AWS provider
	awsP := awsProvider.NewProvider(
		a.AWS,
		a.Keychain,
		a.TOTP,
	)

	// Register AWS provider
	a.Registry.RegisterProvider(awsP)

	// Register AWS setup handler
	a.SetupService.RegisterHandler(setup.NewAWSSetupHandler(a.Keychain))

	// Create TOTP provider
	totpP := totpProvider.NewProvider(
		a.Keychain,
		a.TOTP,
	)

	// Register TOTP provider
	a.Registry.RegisterProvider(totpP)

	// Register TOTP setup handler
	a.SetupService.RegisterHandler(setup.NewTOTPSetupHandler(a.Keychain))
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
	return a.SetupService.SetupService(serviceName)
}

// GenerateCredentials gets credentials from a provider
func (a *App) GenerateCredentials(serviceName string) error {
	p, err := a.Registry.GetProvider(serviceName)
	if err != nil {
		return fmt.Errorf("provider not found: %w", err)
	}

	// Validate request early to fail fast
	if err := p.ValidateRequest(); err != nil {
		return err
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
// TODO: Do I hit this still?
func (a *App) CopyToClipboard(serviceName string) error {
	p, err := a.Registry.GetProvider(serviceName)
	if err != nil {
		return fmt.Errorf("provider not found: %w", err)
	}

	// Validate request early to fail fast
	if err := p.ValidateRequest(); err != nil {
		return err
	}

	// Use the provider's clipboard-specific method
	fmt.Fprintf(a.Stderr, "🔐 Generating credentials for %s...\n", serviceName)
	startTime := time.Now()

	creds, err := p.GetClipboardValue()
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

// PrintCredentials outputs the credentials
// TODO: How much of this is used anymore
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

	// Show MFA authentication status for AWS provider
	if creds.Provider == "aws" && creds.MFAAuthenticated {
		fmt.Fprintf(a.Stdout, "✅ MFA-authenticated session established\n")
	}

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
