package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/migration"
	"github.com/bashhack/sesh/internal/provider"
)

// Version information (set by ldflags during build)
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

// main is the entry point for the sesh CLI.
func main() {
	versionInfo := VersionInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	}

	kc, closer, err := buildProvider()
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ %v\n", err)
		os.Exit(1)
	}
	if closer != nil {
		defer func() {
			if err := closer.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to close provider: %v\n", err)
			}
		}()
	}

	app := NewDefaultApp(versionInfo, kc)
	run(app, os.Args)
}

// buildProvider constructs the credential store.
// When SESH_BACKEND=sqlite it returns a SQLite-backed store (caller must
// close it). Otherwise it returns the system keychain with no closer.
func buildProvider() (keychain.Provider, io.Closer, error) {
	if os.Getenv("SESH_BACKEND") != "sqlite" {
		return keychain.NewDefaultProvider(), nil, nil
	}

	u, err := user.Current()
	if err != nil {
		return nil, nil, fmt.Errorf("determine current user: %w", err)
	}

	dbPath, err := database.DefaultDBPath()
	if err != nil {
		return nil, nil, fmt.Errorf("resolve database path: %w", err)
	}

	kcRaw := keychain.NewDefaultProvider()
	ks := database.NewKeychainSource(kcRaw, u.Username)

	// On first run the encryption key won't exist — generate and store it.
	// Any other keychain error (locked, permission denied) must be surfaced
	// immediately to avoid generating a new key that orphans existing data.
	// NOTE: If two sesh processes race on first run, each may generate a
	// different key. The last writer wins and the other's data is lost.
	// Acceptable for a single-user CLI; add a file lock if this changes.
	if _, err := ks.GetEncryptionKey(); err != nil {
		if !errors.Is(err, keychain.ErrNotFound) {
			return nil, nil, fmt.Errorf("retrieve encryption key: %w", err)
		}
		key, genErr := database.GenerateEncryptionKey()
		if genErr != nil {
			return nil, nil, fmt.Errorf("generate encryption key: %w", genErr)
		}
		if storeErr := ks.StoreEncryptionKey(key); storeErr != nil {
			return nil, nil, fmt.Errorf("store encryption key: %w", storeErr)
		}
	}

	store, err := database.Open(dbPath, ks)
	if err != nil {
		return nil, nil, fmt.Errorf("open database: %w", err)
	}

	if err := store.InitKeyMetadata(); err != nil {
		if closeErr := store.Close(); closeErr != nil {
			return nil, nil, fmt.Errorf("init key metadata: %w (close also failed: %v)", err, closeErr)
		}
		return nil, nil, fmt.Errorf("init key metadata: %w", err)
	}

	return store, store, nil
}

// runMigrate copies all sesh entries from the macOS Keychain to the SQLite store.
// Requires SESH_BACKEND=sqlite.
func runMigrate(app *App) error {
	if os.Getenv("SESH_BACKEND") != "sqlite" {
		return fmt.Errorf("migration requires SESH_BACKEND=sqlite")
	}

	source := keychain.NewDefaultProvider()

	u, err := user.Current()
	if err != nil {
		return fmt.Errorf("determine current user: %w", err)
	}

	dbPath, err := database.DefaultDBPath()
	if err != nil {
		return fmt.Errorf("resolve database path: %w", err)
	}

	ks := database.NewKeychainSource(source, u.Username)
	if _, err := ks.GetEncryptionKey(); err != nil {
		if !errors.Is(err, keychain.ErrNotFound) {
			return fmt.Errorf("retrieve encryption key: %w", err)
		}
		key, genErr := database.GenerateEncryptionKey()
		if genErr != nil {
			return fmt.Errorf("generate encryption key: %w", genErr)
		}
		if storeErr := ks.StoreEncryptionKey(key); storeErr != nil {
			return fmt.Errorf("store encryption key: %w", storeErr)
		}
	}

	dest, err := database.Open(dbPath, ks)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() {
		if cerr := dest.Close(); cerr != nil {
			if _, printErr := fmt.Fprintf(app.Stderr, "warning: failed to close database: %v\n", cerr); printErr != nil {
				return
			}
		}
	}()

	if err := dest.InitKeyMetadata(); err != nil {
		return fmt.Errorf("init key metadata: %w", err)
	}

	plan, err := migration.Plan(source)
	if err != nil {
		return fmt.Errorf("scan keychain: %w", err)
	}

	if len(plan) == 0 {
		if _, err := fmt.Fprintln(app.Stderr, "No sesh entries found in keychain. Nothing to migrate."); err != nil {
			return err
		}
		return nil
	}

	if _, err := fmt.Fprintf(app.Stderr, "Found %d entries to migrate:\n", len(plan)); err != nil {
		return err
	}
	for _, e := range plan {
		desc := e.Description
		if desc == "" {
			desc = "(no description)"
		}
		if _, err := fmt.Fprintf(app.Stderr, "  %s — %s\n", e.Service, desc); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintf(app.Stderr, "\nMigrate these entries to SQLite? [y/N]: "); err != nil {
		return err
	}
	var answer string
	if _, err := fmt.Scanln(&answer); err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}
	if answer != "y" && answer != "Y" {
		if _, err := fmt.Fprintln(app.Stderr, "Migration cancelled."); err != nil {
			return err
		}
		return nil
	}

	result, err := migration.Migrate(source, dest)
	if err != nil {
		return err
	}

	if _, err := fmt.Fprintf(app.Stderr, "\nMigrated %d entries", result.Migrated); err != nil {
		return err
	}
	if result.Skipped > 0 {
		if _, err := fmt.Fprintf(app.Stderr, ", skipped %d (already exist)", result.Skipped); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(app.Stderr); err != nil {
		return err
	}

	if len(result.Errors) > 0 {
		if _, err := fmt.Fprintf(app.Stderr, "%d errors:\n", len(result.Errors)); err != nil {
			return err
		}
		for _, e := range result.Errors {
			if _, err := fmt.Fprintf(app.Stderr, "  %s\n", e); err != nil {
				return err
			}
		}
	}

	return nil
}

// fatal prints an error to stderr and exits
func fatal(app *App, err error) {
	if _, printErr := fmt.Fprintf(app.Stderr, "❌ %v\n", err); printErr != nil {
		app.Exit(2)
		return
	}
	app.Exit(1)
}

// run is the testable entrypoint for the application
func run(app *App, args []string) {
	// Early exit for version/list-services that don't need service
	for _, arg := range args[1:] {
		switch arg {
		case "--version", "-version":
			if err := app.ShowVersion(); err != nil {
				fatal(app, err)
			}
			return
		case "--list-services", "-list-services":
			if err := app.ListProviders(); err != nil {
				fatal(app, err)
			}
			return
		case "--migrate", "-migrate":
			if err := runMigrate(app); err != nil {
				fatal(app, err)
			}
			return
		}
	}

	// Check if help is requested without a service
	hasHelp := false
	for _, arg := range args[1:] {
		if arg == "--help" || arg == "-help" || arg == "-h" {
			hasHelp = true
			break
		}
	}

	// Extract service name from args
	serviceName := extractServiceName(args)
	if serviceName == "" {
		if hasHelp {
			if err := app.PrintUsage(); err != nil {
				fatal(app, err)
			}
			return
		}
		if err := app.ListProviders(); err != nil {
			fatal(app, err)
			return
		}
		fatal(app, fmt.Errorf("no service provider specified. Use -service to select a provider"))
		return
	}

	// Validate service exists
	svcProvider, err := app.Registry.GetProvider(serviceName)
	if err != nil {
		if listErr := app.ListProviders(); listErr != nil {
			fatal(app, listErr)
			return
		}
		fatal(app, err)
		return
	}

	// Now create flagset with provider-specific flags
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(app.Stderr)

	// Set custom usage that includes provider info
	fs.Usage = func() {
		if err := app.PrintProviderUsage(serviceName, svcProvider); err != nil {
			fatal(app, err)
		}
	}

	// Register common flags
	serviceFlag := fs.String("service", serviceName, "Service provider to use")
	showVersion := fs.Bool("version", false, "Show version information")
	showHelp := fs.Bool("help", false, "Show usage")
	listServices := fs.Bool("list-services", false, "List available service providers")
	listEntries := fs.Bool("list", false, "List entries for selected service")
	deleteEntry := fs.String("delete", "", "Delete entry for selected service")
	runSetup := fs.Bool("setup", false, "Run setup wizard for selected service")
	copyClipboard := fs.Bool("clip", false, "Copy code to clipboard")

	// Register provider-specific flags
	if err := svcProvider.SetupFlags(fs); err != nil {
		fatal(app, fmt.Errorf("error setting up provider flags: %w", err))
		return
	}

	// Parse all flags
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fatal(app, fmt.Errorf("error parsing arguments: %w", err))
		return
	}

	// Verify service wasn't changed
	if *serviceFlag != serviceName {
		fatal(app, fmt.Errorf("service provider cannot be changed after initial selection"))
		return
	}

	// Handle commands that were re-parsed
	if *showVersion {
		if err := app.ShowVersion(); err != nil {
			fatal(app, err)
		}
		return
	}
	if *showHelp {
		if err := app.PrintProviderUsage(serviceName, svcProvider); err != nil {
			fatal(app, err)
		}
		return
	}
	if *listServices {
		if err := app.ListProviders(); err != nil {
			fatal(app, err)
		}
		return
	}

	// Provider-specific operations
	if *listEntries {
		if err := app.ListEntries(serviceName); err != nil {
			fatal(app, err)
		}
		return
	}
	if *deleteEntry != "" {
		if err := app.DeleteEntry(serviceName, *deleteEntry); err != nil {
			fatal(app, err)
		}
		return
	}
	if *runSetup {
		if err := app.RunSetup(serviceName); err != nil {
			fatal(app, fmt.Errorf("setup failed: %w", err))
		}
		return
	}

	// Main operation - generate credentials
	if *copyClipboard {
		if err := app.CopyToClipboard(serviceName); err != nil {
			fatal(app, err)
		}
	} else if sd, ok := svcProvider.(provider.SubshellDecider); ok && sd.ShouldUseSubshell() {
		if err := app.LaunchSubshell(serviceName); err != nil {
			fatal(app, err)
		}
	} else {
		if err := app.GenerateCredentials(serviceName); err != nil {
			fatal(app, err)
		}
	}
}

// extractServiceName manually parses args to find --service value
func extractServiceName(args []string) string {
	for i := 1; i < len(args); i++ {
		// Handle --service <value>
		if args[i] == "--service" || args[i] == "-service" {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				return args[i+1]
			}
		}
		// Handle --service=<value>
		if v, ok := strings.CutPrefix(args[i], "--service="); ok {
			return v
		}
		if v, ok := strings.CutPrefix(args[i], "-service="); ok {
			return v
		}
	}
	return ""
}

// PrintUsage displays general usage information
func (a *App) PrintUsage() error {
	w := a.Stdout
	lines := []string{
		"Usage: sesh [options]",
		"\nCommon options:",
		"  --service, -service           Service provider to use (aws, totp) [REQUIRED]",
		"  --list, -list                 List entries for selected service",
		"  --delete, -delete string      Delete entry for selected service",
		"  --setup, -setup               Run setup wizard for selected service",
		"  --clip, -clip                 Copy code to clipboard",
		"  --list-services, -list-services  List available service providers",
		"  --version, -version           Show version information",
		"  --help, -help                 Show usage",
		"\nExamples:",
		"  sesh --service aws                     Generate AWS credentials",
		"  sesh --service totp --service-name github   Generate TOTP code for GitHub",
		"  sesh --list-services                   List available providers",
		"\nFor provider-specific help:",
		"  sesh --service <provider> --help",
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

// PrintProviderUsage prints usage for a specific provider
func (a *App) PrintProviderUsage(serviceName string, p provider.ServiceProvider) error {
	w := a.Stdout
	if _, err := fmt.Fprintf(w, "Usage: sesh --service %s [options]\n\n", serviceName); err != nil {
		return err
	}

	commonLines := []string{
		"Common options:",
		"  --service string              Service provider to use",
		"  --list                        List entries for selected service",
		"  --delete string               Delete entry for selected service",
		"  --setup                       Run setup wizard for selected service",
		"  --clip                        Copy code to clipboard",
		"  --help                        Show this help",
		"  --version                     Show version information",
	}
	for _, line := range commonLines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}

	// Provider-specific flags
	flagInfo := p.GetFlagInfo()
	if len(flagInfo) > 0 {
		if _, err := fmt.Fprintf(w, "\n%s provider options:\n", strings.ToUpper(serviceName[:1])+serviceName[1:]); err != nil {
			return err
		}
		for _, f := range flagInfo {
			required := ""
			if f.Required {
				required = " [REQUIRED]"
			}
			if _, err := fmt.Fprintf(w, "  --%s %s%s\n    %s\n", f.Name, f.Type, required, f.Description); err != nil {
				return err
			}
		}
	}

	// Examples
	if _, err := fmt.Fprintln(w, "\nExamples:"); err != nil {
		return err
	}
	var examples []string
	switch serviceName {
	case "aws":
		examples = []string{
			"  sesh --service aws                     Generate AWS credentials (subshell)",
			"  sesh --service aws --no-subshell       Print AWS credentials",
			"  sesh --service aws --profile dev       Use 'dev' AWS profile",
			"  sesh --service aws --setup             Set up AWS credentials",
		}
	case "totp":
		examples = []string{
			"  sesh --service totp --service-name github     Generate TOTP for GitHub",
			"  sesh --service totp --service-name github --clip   Copy TOTP to clipboard",
			"  sesh --service totp --setup            Set up new TOTP service",
			"  sesh --service totp --list             List all TOTP services",
		}
	case "password":
		examples = []string{
			"  sesh --service password --action generate --service-name github --username user1 --clip",
			"  sesh --service password --action generate --service-name stripe --no-symbols --length 32",
			"  sesh --service password --action store --service-name github --username user1",
			"  sesh --service password --action get --service-name github --username user1 --show",
			"  sesh --service password --action get --service-name github --clip",
			"  sesh --service password --action search --query github",
			"  sesh --service password --action export --file backup.json",
			"  sesh --service password --action import --file backup.json --on-conflict skip",
			"  sesh --service password --list",
			"  sesh --service password --delete <entry-id>",
		}
	}
	for _, line := range examples {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}
