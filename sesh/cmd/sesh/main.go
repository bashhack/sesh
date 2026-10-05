package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/bashhack/sesh/internal/agent"
	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/recovery"
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

	// Shell completion runs on every Tab, so it answers before the setting
	// flags, the config, or the store are looked at.
	if len(os.Args) > 1 && os.Args[1] == completeCmd {
		app := NewDefaultApp(versionInfo, unavailableStore{err: errNoStore}, config.DefaultClipboardTimeout)
		if err := writeCompletions(app.Stdout, app.Registry, os.Args[2:]); err != nil {
			os.Exit(1)
		}
		return
	}

	// Only open the credential store if the command will actually use it.
	// --version, --help, --list-services, and --rekey either just print
	// information or open their own store internally. Skipping buildProvider
	// here means the SQLite backend doesn't pointlessly open the DB (or
	// acquire the key-init flock on first run) for those commands.
	args, overrides, err := takeSettingFlags(os.Args)
	if err == nil {
		err = overrides.Validate()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ %v\n", err)
		os.Exit(2)
	}
	cliOverrides = overrides

	// A broken config only stops commands that use the store; the rest,
	// including `sesh config`, which reports the problem, still run.
	cfg, cfgErr := settings()
	clipboardTimeout := config.DefaultClipboardTimeout
	if cfgErr == nil {
		clipboardTimeout = cfg.ClipboardTimeout.Value
	}

	var (
		kc     keychain.Provider
		closer io.Closer
	)
	// A command that doesn't parse (an unknown flag, no or an unknown
	// provider, --help) never opens the vault: run reports the mistake, and a
	// typo can't create a vault on the way.
	if needsCredentialStore(args) && argsParse(args) {
		if cfgErr != nil {
			fmt.Fprintf(os.Stderr, "❌ %v\n", cfgErr)
			os.Exit(1)
		}
		var err error
		kc, closer, err = buildProvider(cfg)
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
		kc = unavailableStore{err: errNoStore}
	}

	app := NewDefaultApp(versionInfo, kc, clipboardTimeout)
	run(app, args)
}

// serviceFlags is the flag set for a command using provider p: the common
// flags, then p's own, with p's usage on -help.
func serviceFlags(app *App, cmd, serviceName string, p provider.ServiceProvider) (*flag.FlagSet, commonFlags, error) {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	fs.Usage = func() {
		if err := app.PrintProviderUsage(serviceName, p); err != nil {
			fatal(app, err)
		}
	}
	common := addCommonFlags(fs, serviceName)
	if err := p.SetupFlags(fs); err != nil {
		return nil, common, fmt.Errorf("error setting up provider flags: %w", err)
	}
	return fs, common, nil
}

// argsParse reports whether args name a provider and parse cleanly with
// its flags. It's checked before the vault is opened, with a store that
// can't open anything, so a mistyped command can't open or create the
// vault. -help, -version and -list-services don't count, since they only
// print, and neither does a second -service naming another provider.
func argsParse(args []string) bool {
	serviceName := extractServiceName(args)
	if serviceName == "" {
		return false
	}
	app := NewDefaultApp(VersionInfo{}, unavailableStore{err: errNoStore}, config.DefaultClipboardTimeout)
	app.Stdout, app.Stderr = io.Discard, io.Discard
	p, err := app.Registry.GetProvider(serviceName)
	if err != nil {
		return false
	}
	fs, common, err := serviceFlags(app, args[0], serviceName, p)
	if err != nil {
		return false
	}
	fs.Usage = func() {}
	return fs.Parse(args[1:]) == nil && *common.service == serviceName &&
		!*common.help && !*common.version && !*common.listServices
}

// needsCredentialStore reports whether the given command-line invocation
// will touch the credential store. Commands that just print information
// (--help/--version/--list-services) or open their own store internally
// (--rekey) return false.
func needsCredentialStore(args []string) bool {
	if name, _ := subcommand(args); len(args) <= 1 || name != "" {
		return false
	}
	for _, a := range args[1:] {
		switch a {
		case "--help", "-help", "-h",
			"--version", "-version",
			"--list-services", "-list-services",
			"--rekey", "-rekey":
			return false
		}
	}
	return true
}

// subcommands are the commands named by sesh's first argument.
var subcommands = []candidate{
	{"agent", "Control the sesh agent"},
	{"audit", "Show the vault's audit log, or prune it"},
	{"completion", "Print a shell completion script (bash, zsh, fish)"},
	{"config", "Show settings and where each comes from"},
	{"init", "Choose where and how sesh stores secrets"},
	{"recover", "Set a new master password with the vault's recovery key"},
	{"recovery", "Make, remove, or check this vault's recovery key"},
	{"touchid", "Unlock with Touch ID (macOS)"},
}

// subcommand returns the subcommand args name (one of subcommands) and the
// arguments after it, or "" and nil. Only the first argument counts, so an
// entry that happens to be named "agent" (-service-name agent) is never
// mistaken for one.
func subcommand(args []string) (name string, rest []string) {
	if len(args) < 2 {
		return "", nil
	}
	for _, c := range subcommands {
		if c.value == args[1] {
			return args[1], args[2:]
		}
	}
	return "", nil
}

// unavailableStore is a keychain.Provider whose every call fails with err.
// It stands in for the store in commands that don't open one, so a routing
// bug (a command that needs the store classified as one that doesn't)
// fails loudly instead of silently succeeding. It also stands in for the
// macOS Keychain on other systems.
type unavailableStore struct{ err error }

var errNoStore = fmt.Errorf("no credential store opened for this command")

func (u unavailableStore) GetSecret(_, _ string) ([]byte, error)         { return nil, u.err }
func (u unavailableStore) SetSecret(_, _ string, _ []byte) error         { return u.err }
func (u unavailableStore) GetSecretString(_, _ string) (string, error)   { return "", u.err }
func (u unavailableStore) SetSecretString(_, _, _ string) error          { return u.err }
func (u unavailableStore) GetMFASerialBytes(_, _ string) ([]byte, error) { return nil, u.err }
func (u unavailableStore) ListEntries(_ string) ([]keychain.KeychainEntry, error) {
	return nil, u.err
}
func (u unavailableStore) DeleteEntry(_, _ string) error       { return u.err }
func (u unavailableStore) SetDescription(_, _, _ string) error { return u.err }

// goos is runtime.GOOS. Tests replace it to check the behaviour on other
// systems.
var goos = runtime.GOOS

// systemKeychain returns the macOS Keychain, or elsewhere a stand-in whose
// every call says the Keychain isn't available.
func systemKeychain() keychain.Provider {
	if goos == "darwin" {
		return keychain.NewDefaultProvider()
	}
	return unavailableStore{err: fmt.Errorf("the macOS Keychain isn't available on %s", goos)}
}

// requireMacOSKeychain refuses a setting that asks for the macOS Keychain
// on another system, naming where the setting came from.
func requireMacOSKeychain(s config.Setting[string], key string) error {
	if goos == "darwin" {
		return nil
	}
	return fmt.Errorf("%s asks for the macOS Keychain (%s = %q), which isn't available on %s. "+
		"Use the defaults instead: backend = \"sqlite\" with key_source = \"password\"",
		s.Origin, key, s.Value, goos)
}

// cliOverrides holds setting flags given on the command line.
var cliOverrides config.Overrides

// settings resolves this run's settings: flags, then env, then the config
// file, then defaults.
func settings() (*config.Config, error) {
	return config.Load(cliOverrides)
}

// buildProvider constructs the credential store for cfg's backend: a
// SQLite-backed store (caller must close it) or the system keychain with
// no closer.
func buildProvider(cfg *config.Config) (keychain.Provider, io.Closer, error) {
	if cfg.Backend.Value != config.BackendSQLite {
		if err := requireMacOSKeychain(cfg.Backend, "backend"); err != nil {
			return nil, nil, err
		}
		return systemKeychain(), nil, nil
	}
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		return nil, nil, err
	}
	return store, store, nil
}

// openSQLiteStore opens the SQLite store with this run's settings.
func openSQLiteStore() (*database.Store, error) {
	cfg, err := settings()
	if err != nil {
		return nil, err
	}
	return openSQLiteStoreWith(cfg)
}

// openSQLiteStoreWith bootstraps the master encryption key (generating one
// on first run) and returns an opened, schema-initialized SQLite store at
// cfg's vault location. The caller must Close it.
func openSQLiteStoreWith(cfg *config.Config) (*database.Store, error) {
	dbPath := cfg.DBPath.Value
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil { //nolint:gosec // vault dir from the user's own settings
		return nil, fmt.Errorf("create vault directory: %w", err)
	}

	source := cfg.KeySource.Value
	if source == config.KeySourceKeychain {
		if err := requireMacOSKeychain(cfg.KeySource, "key_source"); err != nil {
			return nil, err
		}
	}
	if source == config.KeySourcePassword {
		if err := refuseNewKeyForExistingVault(dbPath); err != nil {
			return nil, err
		}
	}
	ks, err := buildKeySource(dbPath, source)
	if err != nil {
		return nil, err
	}
	store, err := openStoreWith(dbPath, ks, source)
	if err != nil {
		return nil, err
	}
	pruneAuditLog(store, cfg)
	warnAuditSize(store, cfg)
	return store, nil
}

// openStoreWith opens the store at dbPath over oracle and confirms oracle
// holds the vault's key (source names the key source) before returning, so
// nothing is read or written with the wrong key. The store owns oracle once
// opened; if opening fails, oracle is closed here so an agent connection or
// a cached master key doesn't outlive the failure.
func openStoreWith(dbPath string, oracle database.CryptoOracle, source string) (*database.Store, error) {
	store, err := database.Open(dbPath, oracle)
	if err != nil {
		if c, ok := oracle.(interface{ Close() }); ok {
			c.Close()
		}
		return nil, fmt.Errorf("open database: %w", err)
	}

	if err := store.CheckKey(source); err != nil {
		err = withKeyHint(err)
		if closeErr := store.Close(); closeErr != nil {
			return nil, fmt.Errorf("%w (close also failed: %v)", err, closeErr)
		}
		return nil, err
	}

	if err := store.InitKeyMetadata(); err != nil {
		if closeErr := store.Close(); closeErr != nil {
			return nil, fmt.Errorf("init key metadata: %w (close also failed: %v)", err, closeErr)
		}
		return nil, fmt.Errorf("init key metadata: %w", err)
	}

	return store, nil
}

// refuseNewKeyForExistingVault stops password mode from creating a new
// master key next to a vault that already exists without passwords.key:
// entries written under a new key would be unreadable with the vault's
// real one.
func refuseNewKeyForExistingVault(dbPath string) error {
	sidecar := filepath.Join(filepath.Dir(dbPath), sidecarFile)
	switch _, err := os.Stat(sidecar); {
	case err == nil:
		return nil
	case !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("check for the vault's key file %s: %w", sidecar, err)
	}
	switch _, err := os.Stat(dbPath); {
	case errors.Is(err, os.ErrNotExist):
		return nil // no vault yet: the first run creates both
	case err != nil:
		return fmt.Errorf("check for an existing vault at %s: %w", dbPath, err)
	}
	// A vault switched to the Keychain key has no key file by design; it
	// records that, so the setting can be named instead of guessed at.
	if src, rerr := database.RecordedKeySource(dbPath); rerr == nil && src == config.KeySourceKeychain {
		return withKeyHint(&database.WrongKeyError{VaultSource: src, Source: config.KeySourcePassword})
	}
	return fmt.Errorf("a vault exists at %s, but its key file %s is missing. "+
		"If passwords.key was lost, restore it from a backup. "+
		"If this vault uses the Keychain key, set key_source = \"keychain\" in the config file. "+
		"To switch it to a master password, run: sesh --key-source keychain --rekey --to password",
		dbPath, sidecar)
}

// errNeedsSQLite reports a command that only works on the sqlite backend.
func errNeedsSQLite(what string) error {
	return fmt.Errorf("%s requires the sqlite backend: set backend = \"sqlite\" in the config file, or SESH_BACKEND=sqlite", what)
}

// sidecarMissing reports whether dataDir has no passwords.key yet: the
// next password-mode open creates the vault's key.
func sidecarMissing(dataDir string) bool {
	_, err := os.Stat(filepath.Join(dataDir, sidecarFile))
	return errors.Is(err, os.ErrNotExist)
}

// vaultCreationNotice is shown before the first "Create master password"
// prompt.
func vaultCreationNotice(dbPath string) string {
	return "Creating your sesh vault (first run)\n" +
		"  Location: " + tildePath(dbPath) + "\n" +
		"  Your master password encrypts everything in the vault. sesh can't\n" +
		"  reset it: if you forget it, only a recovery key opens the vault\n" +
		"  (sesh recovery new). Store the password somewhere safe, and back the\n" +
		"  vault up with an encrypted export\n" +
		"  (sesh -service password -action export --format encrypted --file <file>).\n"
}

// tildePath shows a path under the home directory as ~/...
func tildePath(p string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return p
	}
	if rest, ok := strings.CutPrefix(p, home+string(filepath.Separator)); ok {
		return "~/" + rest
	}
	return p
}

// unlockAgentWith gives a just-created vault's password to the agent, so
// the next command doesn't ask for it. pw is zeroed. A failure only warns:
// this command already has the key.
func unlockAgentWith(dataDir string, pw []byte) {
	defer secure.SecureZeroBytes(pw)
	mat, err := database.ReadUnlockMaterial(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: sesh agent not unlocked: %v\n", err) //nolint:errcheck // best-effort warning
		return
	}
	conn, err := agent.EnsureAgent()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: sesh agent unavailable: %v\n", err) //nolint:errcheck // best-effort warning
		return
	}
	defer closeAgentConn(conn)
	// agent.Unlock zeroes the slice it's given.
	if err := agent.Unlock(conn, bytes.Clone(pw), mat.Salt, mat.Verify, mat.Params); err != nil {
		fmt.Fprintf(os.Stderr, "warning: sesh agent unlock failed: %v\n", err) //nolint:errcheck // best-effort warning
	}
}

// withForgottenPasswordHint adds what a person can do after failing every
// interactive master password attempt. Scripts get the plain error.
func withForgottenPasswordHint(err error, cfg passwordPromptConfig, dataDir string) error {
	if !cfg.interactive || !errors.Is(err, database.ErrWrongPassword) {
		return err
	}
	if _, serr := os.Stat(filepath.Join(dataDir, recovery.FileName)); serr == nil {
		return fmt.Errorf("%w.\n   If you've forgotten it, set a new one with your recovery key: sesh recover", err)
	}
	return fmt.Errorf("%w.\n   If you've forgotten it, the vault can't be opened. To start over, or to restore\n"+
		"   from an encrypted export, see \"Forgotten master password\" in the usage docs", err)
}

// withKeyHint adds what to do next to a database.WrongKeyError.
func withKeyHint(err error) error {
	var wk *database.WrongKeyError
	if !errors.As(err, &wk) {
		return err
	}
	switch {
	case wk.VaultSource != "" && wk.VaultSource != wk.Source:
		return fmt.Errorf("%w. Set key_source = %q in the config file (or SESH_KEY_SOURCE=%s) to use this vault, or switch it with: sesh --key-source %s --rekey --to %s",
			err, wk.VaultSource, wk.VaultSource, wk.VaultSource, wk.Source)
	case wk.Source == "password":
		return fmt.Errorf("%w. If passwords.key was replaced, restore the original. If you switched key sources with sesh --rekey, set key_source to the new one", err)
	default:
		return fmt.Errorf("%w. If the Keychain entry %q was replaced, restore the original. If you switched key sources with sesh --rekey, set key_source to the new one", err, encKeyService)
	}
}

// buildKeySource returns the CryptoOracle the store encrypts through for
// source ("keychain" or "password"). "password"
// uses the agent when it can serve this data directory, so later
// commands do not prompt again. A missing sidecar, or an agent that
// cannot be reached or fails to unlock, falls back to
// MasterPasswordSource, reusing a password already typed. A wrong
// password is retried against the agent and is returned to the caller
// when the attempt budget is spent. With SESH_MASTER_PASSWORD set, the
// agent is not used at all.
func buildKeySource(dbPath, source string) (database.CryptoOracle, error) {
	return buildKeySourceWith(dbPath, source, resolvePasswordPrompt())
}

// buildKeySourceWith is buildKeySource with the password prompt given, so
// tests can stand in for a person at a terminal.
func buildKeySourceWith(dbPath, source string, cfg passwordPromptConfig) (database.CryptoOracle, error) {
	dataDir := filepath.Dir(dbPath)
	switch source {
	case config.KeySourcePassword:
		if !cfg.fromEnv {
			oracle, typed, err := keySourceFromAgent(dataDir, cfg)
			if err != nil {
				return nil, withForgottenPasswordHint(err, cfg, dataDir)
			}
			if oracle != nil {
				return oracle, nil
			}
			if typed != nil {
				defer secure.SecureZeroBytes(typed)
				cfg = cfg.withTypedPassword(typed)
			}
		}
		// A person creating the vault is told what's happening before the
		// first prompt, and the agent gets the new password afterwards, so
		// the next command doesn't ask for it again.
		var created []byte
		firstRun := !cfg.fromEnv && sidecarMissing(dataDir)
		if firstRun {
			fmt.Fprint(os.Stderr, vaultCreationNotice(dbPath)) //nolint:errcheck // best-effort notice
			cfg = cfg.keepingLastPassword(&created)
		}
		defer func() { secure.SecureZeroBytes(created) }()

		mps := cfg.newSource(dataDir)
		// Eagerly unlock so every operation — including metadata-only reads
		// like --list and --delete — requires the master password. Without
		// this, the store would only prompt on decryption, letting an
		// attacker with filesystem access list and delete entries without
		// the password.
		key, err := mps.GetEncryptionKey()
		if err != nil {
			return nil, withForgottenPasswordHint(err, cfg, dataDir)
		}
		secure.SecureZeroBytes(key)
		if firstRun {
			unlockAgentWith(dataDir, created)
			offerRecovery(cfg, dataDir)
			offerTouchID(cfg, dataDir)
		}
		return database.NewKeySourceOracle(mps), nil
	case config.KeySourceKeychain:
		u, err := user.Current()
		if err != nil {
			return nil, fmt.Errorf("determine current user: %w", err)
		}
		ks := database.NewKeychainSource(systemKeychain(), u.Username)
		if err := ensureMasterKey(ks, dataDir); err != nil {
			return nil, err
		}
		return database.NewKeySourceOracle(ks), nil
	default:
		return nil, fmt.Errorf("unknown key source %q (valid: keychain, password)", source)
	}
}

// keySourceFromAgent connects to the agent and returns an oracle when the
// agent can serve crypto for this data directory.
//
// A nil oracle and nil error mean the caller should fall back to a direct
// master-password source: this data directory has no usable sidecar yet,
// or the agent could not be reached or failed during unlock. In the last
// case typed holds the password the user already entered, so the fallback
// can use it instead of prompting again; the caller must zero it. A
// non-nil error means the command should stop: the password attempt
// budget was spent, or the prompt itself failed. Wrong-password replies
// stay on the agent for every attempt.
func keySourceFromAgent(dataDir string, cfg passwordPromptConfig) (oracle database.CryptoOracle, typed []byte, err error) {
	// The sidecar is a local read. Without one (first run) or with a
	// corrupt one, the direct source takes over, so don't start an agent.
	mat, err := database.ReadUnlockMaterial(dataDir)
	if err != nil {
		return nil, nil, nil
	}
	conn, err := agent.EnsureAgent()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: sesh agent unavailable: %v\n", err) //nolint:errcheck // best-effort warning
		return nil, nil, nil
	}
	st, err := agent.Status(conn)
	if err != nil {
		closeAgentConn(conn)
		fmt.Fprintf(os.Stderr, "warning: sesh agent unavailable: %v\n", err) //nolint:errcheck // best-effort warning
		return nil, nil, nil
	}
	id := agent.UnlockID(mat.Verify)
	if st.Unlocked && st.UnlockID == id {
		return agent.NewOracle(conn, id), nil, nil
	}
	// A person at the terminal is asked for a fingerprint first, when this
	// vault has Touch ID unlock on; scripts never wait on one.
	if cfg.interactive {
		unlocked, terr := tryTouchID(conn, dataDir, id, mat.Verify)
		if unlocked {
			return agent.NewOracle(conn, id), nil, nil
		}
		if terr != nil {
			closeAgentConn(conn)
			fmt.Fprintf(os.Stderr, "warning: sesh agent unavailable: %v\n", terr) //nolint:errcheck // best-effort warning
			return nil, nil, nil
		}
	}

	attempts := 1
	if cfg.interactive {
		attempts = interactivePasswordAttempts
	}
	for i := range attempts {
		prompt := "Master password: "
		if i > 0 {
			prompt = fmt.Sprintf("Wrong password, try again (%d/%d). Master password: ", i+1, attempts)
		}
		pw, perr := cfg.prompt(prompt)
		if perr != nil {
			closeAgentConn(conn)
			return nil, nil, perr
		}
		// agent.Unlock zeroes pw; keep a copy in case the fallback needs it.
		kept := bytes.Clone(pw)
		uerr := agent.Unlock(conn, pw, mat.Salt, mat.Verify, mat.Params)
		if uerr == nil {
			secure.SecureZeroBytes(kept)
			return agent.NewOracle(conn, id), nil, nil
		}
		var pe *agent.ProtocolError
		if errors.As(uerr, &pe) && pe.Code == agent.ErrCodeWrongPassword {
			secure.SecureZeroBytes(kept)
			continue
		}
		closeAgentConn(conn)
		fmt.Fprintf(os.Stderr, "warning: sesh agent unlock failed: %v\n", uerr) //nolint:errcheck // best-effort warning
		return nil, kept, nil
	}
	closeAgentConn(conn)
	// Same wording as MasterPasswordSource, so the user sees one message
	// whichever path checked the password.
	if attempts == 1 {
		return nil, nil, database.ErrWrongPassword
	}
	return nil, nil, fmt.Errorf("%w (after %d attempts)", database.ErrWrongPassword, attempts)
}

func closeAgentConn(conn *agent.Conn) {
	if err := conn.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: close agent connection: %v\n", err) //nolint:errcheck // best-effort warning
	}
}

// interactivePasswordAttempts is the retry budget for an interactive TTY
// password prompt. Three is the conventional ssh/sudo limit — enough to
// recover from a typo without spending real CPU on Argon2id derivations
// against a clearly-wrong password.
const interactivePasswordAttempts = 3

// passwordPromptConfig pairs a prompt callback with a flag indicating
// whether the prompt represents a live human at a terminal. The two are
// resolved together so the retry-loop budget can never be applied to a
// constant-output prompt (e.g. one backed by SESH_MASTER_PASSWORD), which
// would just burn N × Argon2id deriving the same wrong key.
type passwordPromptConfig struct {
	prompt database.PasswordPromptFunc
	// confirm asks a [Y/n] question at the terminal; nil when nobody can
	// answer one.
	confirm func(prompt string) (bool, error)
	// readLine asks for a line of text at the terminal; nil when nobody can
	// answer one.
	readLine    func(prompt string) (string, error)
	interactive bool
	// fromEnv means the password came from SESH_MASTER_PASSWORD. Such
	// runs skip the agent: the value is checked every time, and a script
	// or CI job doesn't leave an unlocked agent running after it exits.
	fromEnv bool
}

// resolvePasswordPrompt picks the prompt callback based on the runtime
// environment, in priority order:
//   - SESH_MASTER_PASSWORD set → constant-bytes prompt, never interactive
//   - stdin is a TTY → terminal read, interactive
//   - otherwise (piped stdin, scripts) → terminal read, but not interactive
//     so retry stays disabled
//
// Reading the env var here is the single source of truth for "is the
// password input live human input?" — the answer feeds both the prompt
// itself and the retry budget.
func resolvePasswordPrompt() passwordPromptConfig {
	if envPw := os.Getenv("SESH_MASTER_PASSWORD"); envPw != "" {
		return passwordPromptConfig{
			prompt:      func(_ string) ([]byte, error) { return []byte(envPw), nil },
			interactive: false,
			fromEnv:     true,
		}
	}
	return passwordPromptConfig{
		prompt:      terminalPrompt,
		interactive: term.IsTerminal(int(os.Stdin.Fd())),
		confirm:     func(p string) (bool, error) { return askYes(os.Stdin, os.Stderr, p) },
		readLine:    func(p string) (string, error) { return readLine(os.Stdin, os.Stderr, p) },
	}
}

// newSource constructs a MasterPasswordSource using this config's prompt
// and only enables the retry budget when the prompt is interactive.
func (c passwordPromptConfig) newSource(dataDir string) *database.MasterPasswordSource {
	return database.NewMasterPasswordSource(dataDir, c.prompt, c.options()...)
}

// newSourceAtPath is the rotation-friendly variant: caller specifies the
// sidecar path explicitly so a "target" source can stage at e.g.
// passwords.key.new while the canonical source still reads passwords.key.
func (c passwordPromptConfig) newSourceAtPath(sidecarPath string) *database.MasterPasswordSource {
	return database.NewMasterPasswordSourceAtPath(sidecarPath, c.prompt, c.options()...)
}

func (c passwordPromptConfig) options() []database.Option {
	if c.interactive {
		return []database.Option{database.WithMaxAttempts(interactivePasswordAttempts)}
	}
	return nil
}

// keepingLastPassword returns a config whose prompt also keeps a copy of
// the last password it returned in *last, zeroing the copy it replaces.
// The caller zeroes *last.
func (c passwordPromptConfig) keepingLastPassword(last *[]byte) passwordPromptConfig {
	next := c.prompt
	c.prompt = func(p string) ([]byte, error) {
		pw, err := next(p)
		if err == nil {
			secure.SecureZeroBytes(*last)
			*last = bytes.Clone(pw)
		}
		return pw, err
	}
	return c
}

// withTypedPassword returns a config whose first prompt is answered with
// pw instead of asking the user again. Later prompts (retries) go to the
// original prompt.
func (c passwordPromptConfig) withTypedPassword(pw []byte) passwordPromptConfig {
	next := c.prompt
	used := false
	c.prompt = func(p string) ([]byte, error) {
		if !used {
			used = true
			return pw, nil
		}
		return next(p)
	}
	return c
}

// terminalPrompt reads a password from the controlling terminal without
// echo. Does not consult SESH_MASTER_PASSWORD — that decision belongs to
// resolvePasswordPrompt so the env-var policy lives in exactly one place.
func terminalPrompt(prompt string) ([]byte, error) {
	if _, err := fmt.Fprint(os.Stderr, prompt); err != nil {
		return nil, err
	}
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	// Best-effort newline after the hidden input. Don't let a stderr write
	// error mask a real read error.
	fmt.Fprintln(os.Stderr) //nolint:errcheck // see comment above
	if err != nil {
		// Don't re-wrap as "read password" — the caller (unlock) already
		// adds that prefix, and double-wrapping produced
		// "read password: read password: ..." in error output.
		return nil, err
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

// remainingArgs returns args following (but not including) the first
// occurrence of name. Used to forward sub-flags to handlers like runRekey
// without depending on a specific flag-package layout.
func remainingArgs(args []string, name string) []string {
	for i, a := range args {
		if a == name {
			return args[i+1:]
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
	switch name, rest := subcommand(args); name {
	case "agent":
		if err := runAgent(app, rest); err != nil {
			fatal(app, err)
		}
		return
	case "config":
		if err := runConfig(app, rest); err != nil {
			fatal(app, err)
		}
		return
	case "init":
		if err := runInit(app, rest); err != nil {
			fatal(app, err)
		}
		return
	case "touchid":
		if err := runTouchID(app, rest); err != nil {
			fatal(app, err)
		}
		return
	case "audit":
		if err := runAudit(app, rest); err != nil {
			fatal(app, err)
		}
		return
	case "recover":
		if err := runRecover(app, rest); err != nil {
			fatal(app, err)
		}
		return
	case "recovery":
		if err := runRecovery(app, rest); err != nil {
			fatal(app, err)
		}
		return
	case "completion":
		if err := runCompletion(app, rest); err != nil {
			fatal(app, err)
		}
		return
	}

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
		case "--rekey", "-rekey":
			rest := remainingArgs(args, arg)
			if err := runRekey(app, rest, systemKeychain()); err != nil {
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
		// Plain `sesh` asks what it can do; options without -service are a
		// mistake.
		if len(args) == 1 {
			if err := app.PrintGettingStarted(); err != nil {
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

	fs, common, err := serviceFlags(app, args[0], serviceName, svcProvider)
	if err != nil {
		fatal(app, err)
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
	if *common.service != serviceName {
		fatal(app, fmt.Errorf("service provider cannot be changed after initial selection"))
		return
	}

	// Handle commands that were re-parsed
	if *common.version {
		if err := app.ShowVersion(); err != nil {
			fatal(app, err)
		}
		return
	}
	if *common.help {
		if err := app.PrintProviderUsage(serviceName, svcProvider); err != nil {
			fatal(app, err)
		}
		return
	}
	if *common.listServices {
		if err := app.ListProviders(); err != nil {
			fatal(app, err)
		}
		return
	}

	// Provider-specific operations
	if *common.list {
		if err := app.ListEntries(serviceName); err != nil {
			fatal(app, err)
		}
		return
	}
	if *common.delete != "" {
		if err := app.DeleteEntry(serviceName, *common.delete); err != nil {
			fatal(app, err)
		}
		return
	}
	if *common.setup {
		if err := app.RunSetup(serviceName); err != nil {
			fatal(app, fmt.Errorf("setup failed: %w", err))
		}
		return
	}

	// Main operation - generate credentials
	if *common.clip {
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

// commonFlags are the flags every provider accepts.
type commonFlags struct {
	service, delete                                *string
	version, help, listServices, list, setup, clip *bool
}

func addCommonFlags(fs *flag.FlagSet, serviceName string) commonFlags {
	return commonFlags{
		service:      fs.String("service", serviceName, "Service provider to use"),
		version:      fs.Bool("version", false, "Show version information"),
		help:         fs.Bool("help", false, "Show usage"),
		listServices: fs.Bool("list-services", false, "List available service providers"),
		list:         fs.Bool("list", false, "List entries for selected service"),
		delete:       fs.String("delete", "", "Delete entry for selected service"),
		setup:        fs.Bool("setup", false, "Run setup wizard for selected service"),
		clip:         fs.Bool("clip", false, "Copy code to clipboard"),
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

// PrintGettingStarted prints what plain `sesh` shows: what sesh is for,
// the first commands to run, and the providers.
func (a *App) PrintGettingStarted() error {
	intro := []string{
		"sesh keeps your TOTP secrets and passwords in an encrypted vault.",
		"",
		"Get started:",
		"  sesh -service totp -setup       add a TOTP account",
		"  sesh -service aws -setup        set up AWS MFA",
		"  sesh -service password -help    store passwords, API keys, and notes",
		"  sesh init                       choose where and how sesh stores secrets (optional)",
		"  sesh --help                     all options",
		"",
	}
	for _, line := range intro {
		if _, err := fmt.Fprintln(a.Stdout, line); err != nil {
			return err
		}
	}
	return a.ListProviders()
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
		"\nSetting overrides (for this command only; see `sesh config`):",
		"  --backend keychain|sqlite     Storage backend",
		"  --key-source keychain|password  Key source for the sqlite backend",
		"  --db-path path                Vault location for the sqlite backend",
		"\nCommands:",
		"  sesh init                     Choose where and how sesh stores secrets",
		"  sesh config                   Show settings and where each comes from",
		"  sesh recovery new|remove|status    A recovery key, in case you forget your master password",
		"  sesh recover                  Forgot the master password? Set a new one with the recovery key",
		"  sesh touchid enable|disable|status  Unlock with Touch ID (macOS)",
		"  sesh agent [lock|status|stop] Control the sesh agent",
		"  sesh audit [prune]            Show the vault's audit log, or prune it",
		"  sesh completion bash|zsh|fish  Print a shell completion script",
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
