package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
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

// validEnvVarName matches POSIX-compliant environment variable names.
var validEnvVarName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// ExecLookPathFunc is a function type for looking up executables in PATH
type ExecLookPathFunc func(file string) (string, error)

// ExitFunc is a function type for exiting the program
type ExitFunc func(code int)

// App represents the main application
type App struct {
	Registry     *provider.Registry
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
func NewDefaultApp(versionInfo VersionInfo) *App {
	kc := keychain.NewDefaultProvider()
	totpSvc := totp.NewDefaultProvider()
	awsSvc := aws.NewDefaultProvider()

	registry := provider.NewRegistry()
	registry.RegisterProvider(awsProvider.NewProvider(awsSvc, kc, totpSvc))
	registry.RegisterProvider(totpProvider.NewProvider(kc, totpSvc))

	setupSvc := setup.NewSetupService(kc)
	setupSvc.RegisterHandler(setup.NewAWSSetupHandler(kc))
	setupSvc.RegisterHandler(setup.NewTOTPSetupHandler(kc))

	return &App{
		Registry:     registry,
		SetupService: setupSvc,
		ExecLookPath: exec.LookPath,
		Exit:         os.Exit,
		Stdout:       os.Stdout,
		Stderr:       os.Stderr,
		VersionInfo:  versionInfo,
	}
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
func (a *App) CopyToClipboard(serviceName string) error {
	p, err := a.Registry.GetProvider(serviceName)
	if err != nil {
		return fmt.Errorf("provider not found: %w", err)
	}

	if err := p.ValidateRequest(); err != nil {
		return err
	}

	fmt.Fprintf(a.Stderr, "🔐 Generating credentials for %s...\n", serviceName)
	startTime := time.Now()

	creds, err := p.GetClipboardValue()
	if err != nil {
		return fmt.Errorf("failed to generate credentials: %w", err)
	}

	elapsedTime := time.Since(startTime)

	if creds.CopyValue == "" {
		return fmt.Errorf("no content available to copy to clipboard")
	}

	if err := clipboard.Copy(creds.CopyValue); err != nil {
		return fmt.Errorf("failed to copy to clipboard: %w", err)
	}

	clipboardDesc := creds.ClipboardDescription
	if clipboardDesc == "" {
		clipboardDesc = "value"
	}

	fmt.Fprintf(a.Stderr, "✅ %s copied to clipboard in %.2fs\n", clipboardDesc, elapsedTime.Seconds())
	fmt.Fprintf(a.Stderr, "%s\n", creds.DisplayInfo)

	return nil
}

// PrintCredentials outputs the credentials
func (a *App) PrintCredentials(creds provider.Credentials) {
	// Format expiry time
	expiryDisplay := "unknown"
	if !creds.Expiry.IsZero() {
		duration := time.Until(creds.Expiry)
		formatted := creds.Expiry.Local().Format("2006-01-02 15:04:05")
		if duration <= 0 {
			expiryDisplay = fmt.Sprintf("%s (expired)", formatted)
		} else {
			total := int(duration.Seconds())
			hours := total / 3600
			minutes := (total % 3600) / 60
			seconds := total % 60

			var validFor string
			if hours > 0 {
				validFor = fmt.Sprintf("%dh%dm", hours, minutes)
			} else if minutes > 0 {
				validFor = fmt.Sprintf("%dm%ds", minutes, seconds)
			} else {
				validFor = fmt.Sprintf("%ds", seconds)
			}
			expiryDisplay = fmt.Sprintf("%s (valid for %s)", formatted, validFor)
		}
	}

	// Human-readable info goes to stderr so stdout remains eval-safe
	fmt.Fprintf(a.Stderr, "⏳ Expires at: %s\n", expiryDisplay)

	if creds.MFAAuthenticated {
		fmt.Fprintf(a.Stderr, "✅ MFA-authenticated session established\n")
	}

	if creds.DisplayInfo != "" {
		fmt.Fprintf(a.Stderr, "%s\n", creds.DisplayInfo)
	}

	// Shell-safe export commands go to stdout for eval/source
	if len(creds.Variables) > 0 {
		fmt.Fprintf(a.Stdout, "# --------- ENVIRONMENT VARIABLES ---------\n")
		for key, value := range creds.Variables {
			if !validEnvVarName.MatchString(key) {
				fmt.Fprintf(a.Stderr, "⚠️  Skipping invalid variable name: %q\n", key)
				continue
			}
			fmt.Fprintf(a.Stdout, "export %s='%s'\n", key, strings.ReplaceAll(value, "'", "'\\''"))
		}
		fmt.Fprintf(a.Stdout, "# ----------------------------------------\n")
	}
}
