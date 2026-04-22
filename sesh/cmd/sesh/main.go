package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/migration"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/secure"
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

	// Only open the credential store if the command will actually use it.
	// --version, --help, --list-services, and --migrate either just print
	// information or open their own store internally. Skipping buildProvider
	// here means SESH_BACKEND=sqlite doesn't pointlessly open the DB (or
	// acquire the key-init flock on first run) for those commands.
	var (
		kc     keychain.Provider
		closer io.Closer
	)
	if needsCredentialStore(os.Args) {
		var err error
		kc, closer, err = buildProvider()
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
	} else {
		kc = noopCredentialStore{}
	}

	app := NewDefaultApp(versionInfo, kc)
	run(app, os.Args)
}

// needsCredentialStore reports whether the given command-line invocation
// will touch the credential store. Commands that just print information
// (--help/--version/--list-services) or open their own store internally
// (--migrate) return false.
func needsCredentialStore(args []string) bool {
	if len(args) <= 1 {
		return false
	}
	for _, a := range args[1:] {
		switch a {
		case "--help", "-help", "-h",
			"--version", "-version",
			"--list-services", "-list-services",
			"--migrate", "-migrate":
			return false
		}
	}
	return true
}

// noopCredentialStore is a keychain.Provider stand-in used for commands
// that don't touch the credential store. Every method returns an error so
// that a routing bug (e.g. a command that should have needed the store
// being classified as lightweight) surfaces loudly instead of silently
// succeeding.
type noopCredentialStore struct{}

var errNoStore = fmt.Errorf("no credential store opened for this command")

func (noopCredentialStore) GetSecret(_, _ string) ([]byte, error) { return nil, errNoStore }
func (noopCredentialStore) SetSecret(_, _ string, _ []byte) error { return errNoStore }
func (noopCredentialStore) GetSecretString(_, _ string) (string, error) {
	return "", errNoStore
}
func (noopCredentialStore) SetSecretString(_, _, _ string) error { return errNoStore }
func (noopCredentialStore) GetMFASerialBytes(_, _ string) ([]byte, error) {
	return nil, errNoStore
}
func (noopCredentialStore) ListEntries(_ string) ([]keychain.KeychainEntry, error) {
	return nil, errNoStore
}
func (noopCredentialStore) DeleteEntry(_, _ string) error       { return errNoStore }
func (noopCredentialStore) SetDescription(_, _, _ string) error { return errNoStore }

// buildProvider constructs the credential store.
// When SESH_BACKEND=sqlite it returns a SQLite-backed store (caller must
// close it). Otherwise it returns the system keychain with no closer.
func buildProvider() (keychain.Provider, io.Closer, error) {
	if os.Getenv("SESH_BACKEND") != "sqlite" {
		return keychain.NewDefaultProvider(), nil, nil
	}
	store, err := openSQLiteStore()
	if err != nil {
		return nil, nil, err
	}
	return store, store, nil
}

// openSQLiteStore bootstraps the master encryption key (generating one on
// first run) and returns an opened, schema-initialized SQLite store. The
// caller must Close it.
func openSQLiteStore() (*database.Store, error) {
	dbPath, err := database.DefaultDBPath()
	if err != nil {
		return nil, fmt.Errorf("resolve database path: %w", err)
	}

	ks, err := buildKeySource(filepath.Dir(dbPath))
	if err != nil {
		return nil, err
	}

	store, err := database.Open(dbPath, ks)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	if err := store.InitKeyMetadata(); err != nil {
		if closeErr := store.Close(); closeErr != nil {
			return nil, fmt.Errorf("init key metadata: %w (close also failed: %v)", err, closeErr)
		}
		return nil, fmt.Errorf("init key metadata: %w", err)
	}

	return store, nil
}

// buildKeySource selects the KeySource based on SESH_KEY_SOURCE.
// Defaults to the macOS Keychain. "password" selects MasterPasswordSource,
// which stores its KDF salt in a sidecar file alongside the DB.
func buildKeySource(dataDir string) (database.KeySource, error) {
	switch os.Getenv("SESH_KEY_SOURCE") {
	case "password":
		mps := database.NewMasterPasswordSource(dataDir, promptMasterPassword)
		return mps, nil
	case "", "keychain":
		u, err := user.Current()
		if err != nil {
			return nil, fmt.Errorf("determine current user: %w", err)
		}
		ks := database.NewKeychainSource(keychain.NewDefaultProvider(), u.Username)
		if err := ensureMasterKey(ks, dataDir); err != nil {
			return nil, err
		}
		return ks, nil
	default:
		return nil, fmt.Errorf("unknown SESH_KEY_SOURCE %q (valid: keychain, password)", os.Getenv("SESH_KEY_SOURCE"))
	}
}

// promptMasterPassword reads a password from the terminal without echo.
// Checks SESH_MASTER_PASSWORD env var first to support non-interactive use.
func promptMasterPassword(prompt string) ([]byte, error) {
	if envPw := os.Getenv("SESH_MASTER_PASSWORD"); envPw != "" {
		return []byte(envPw), nil
	}

	if _, err := fmt.Fprint(os.Stderr, prompt); err != nil {
		return nil, err
	}
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	// Best-effort newline after the hidden input. Don't let a stderr write
	// error mask a real read error.
	fmt.Fprintln(os.Stderr) //nolint:errcheck // see comment above
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}
	return pw, nil
}

// ensureMasterKey verifies a master encryption key exists in the keychain,
// generating and storing one on first run. Zeros any retrieved/generated
// key bytes before returning.
//
// Concurrent first-run invocations are serialized via an advisory flock on
// <dataDir>/.key-init.lock so two sesh processes can't each generate a
// different key and orphan each other's data. The flock is auto-released
// when the holding process exits, so crashes don't leave stale locks.
func ensureMasterKey(ks *database.KeychainSource, dataDir string) error {
	// Fast path: key already present.
	if existing, err := ks.GetEncryptionKey(); err == nil {
		secure.SecureZeroBytes(existing)
		return nil
	} else if !errors.Is(err, keychain.ErrNotFound) {
		// Any non-ErrNotFound failure (locked, permission denied) must be
		// surfaced immediately — otherwise we'd generate a new key and
		// orphan the existing one.
		return fmt.Errorf("retrieve encryption key: %w", err)
	}

	// Slow path: acquire the init lock before generating so we don't race
	// a concurrent first-run invocation.
	sentinel := filepath.Join(dataDir, ".key-init.lock")
	lockFile, err := os.OpenFile(sentinel, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // path is <dataDir>/.key-init.lock; dataDir comes from our own DefaultDBPath
	if err != nil {
		return fmt.Errorf("open key-init sentinel: %w", err)
	}
	defer func() {
		// Closing the fd releases the advisory flock.
		if cerr := lockFile.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "warning: release key-init lock: %v\n", cerr)
		}
	}()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("acquire key-init lock: %w", err)
	}

	// Double-check under the lock — a concurrent process may have generated
	// and stored the key while we were blocking on flock.
	if existing, err := ks.GetEncryptionKey(); err == nil {
		secure.SecureZeroBytes(existing)
		return nil
	} else if !errors.Is(err, keychain.ErrNotFound) {
		return fmt.Errorf("retrieve encryption key (post-lock): %w", err)
	}

	key, err := database.GenerateEncryptionKey()
	if err != nil {
		return fmt.Errorf("generate encryption key: %w", err)
	}
	defer secure.SecureZeroBytes(key)
	if err := ks.StoreEncryptionKey(key); err != nil {
		return fmt.Errorf("store encryption key: %w", err)
	}
	return nil
}

// runMigrate copies all sesh entries from the macOS Keychain to the SQLite store.
// Requires SESH_BACKEND=sqlite.
func runMigrate(app *App) error {
	if os.Getenv("SESH_BACKEND") != "sqlite" {
		return fmt.Errorf("migration requires SESH_BACKEND=sqlite")
	}

	source := keychain.NewDefaultProvider()

	dest, err := openSQLiteStore()
	if err != nil {
		return err
	}
	defer func() {
		if cerr := dest.Close(); cerr != nil {
			// Best-effort warning — app.Stderr is io.Writer so errcheck
			// wants the return checked, but there's nothing useful to
			// do from inside a deferred void func if the write fails.
			_, _ = fmt.Fprintf(app.Stderr, "warning: failed to close database: %v\n", cerr) //nolint:errcheck // see comment above
		}
	}()

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
	// Use bufio so a bare Enter (the canonical "No" for [y/N]) is read
	// as an empty line rather than surfacing "unexpected newline" from
	// fmt.Scanln and aborting.
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("failed to read input: %w", err)
	}
	answer := strings.TrimSpace(line)
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
		"  --service, -service           Service provider to use (aws, totp, password) [REQUIRED]",
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
