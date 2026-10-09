package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/term"

	"github.com/bashhack/sesh/internal/agent"
	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/kdf"
	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
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
		app := NewDefaultApp(versionInfo, unavailableStore{err: errNoStore}, AppSettings{ClipboardTimeout: config.DefaultClipboardTimeout})
		if err := writeCompletions(app.Stdout, app.Registry, os.Args[2:]); err != nil {
			os.Exit(1)
		}
		return
	}

	// Only open the credential store if the command will actually use it.
	// --version, --help, --list-services, and --rekey either just print
	// information or open their own store internally. Skipping buildProvider
	// here means sesh doesn't pointlessly open the vault for those
	// commands.
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
	appSettings := AppSettings{ClipboardTimeout: config.DefaultClipboardTimeout}
	if cfgErr == nil {
		appSettings = appSettingsFrom(cfg)
	}

	var (
		kc     vault.Store
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

	app := NewDefaultApp(versionInfo, kc, appSettings)
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
// print, and neither does a second -service naming another provider, or
// arguments the provider refuses.
func argsParse(args []string) bool {
	serviceName := extractServiceName(args)
	if serviceName == "" {
		return false
	}
	app := NewDefaultApp(VersionInfo{}, unavailableStore{err: errNoStore}, AppSettings{ClipboardTimeout: config.DefaultClipboardTimeout})
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
	if fs.Parse(args[1:]) != nil || *common.service != serviceName ||
		*common.help || *common.version || *common.listServices {
		return false
	}
	// Arguments that are wrong without the vault are refused before the
	// master password is asked for; run reports why.
	return earlyCheck(p, common, fs.Args(), app.StdinIsTerminal) == nil
}

// earlyCheck refuses arguments that are wrong without looking at the vault,
// for what the flags select: a --delete ID no entry can have (the first
// follows --delete, the rest are the arguments after the flags); for --list
// and --delete, the provider's paging flags; for any other command but
// --setup (whose wizard asks for its own names), all the provider's
// arguments. argsParse runs it before the vault opens, and run reports it
// before any path that would use the vault.
func earlyCheck(p provider.ServiceProvider, common commonFlags, args []string, stdinIsTerminal func() bool) error {
	if ids := deleteIDs(common, args); len(ids) > 0 {
		var bad []string
		for _, id := range ids {
			switch _, err := vault.ParseKey(id); {
			case strings.HasPrefix(id, "-"):
				// Flags stop at the first ID, so one after the IDs
				// arrives as an ID.
				bad = append(bad, fmt.Sprintf("%q looks like a flag: put flags before the entry IDs, as in: sesh --service %s --force --delete <id> <id>", id, p.Name()))
			case err != nil:
				bad = append(bad, err.Error())
			}
		}
		switch len(bad) {
		case 0:
		case 1:
			return errors.New(bad[0])
		default:
			return fmt.Errorf("nothing was deleted:\n  %s", strings.Join(bad, "\n  "))
		}
		// Asking needs a terminal; without one, say so before the vault is
		// unlocked for nothing.
		if f, ok := p.(interface{ DeleteForced() bool }); ok && !f.DeleteForced() && (stdinIsTerminal == nil || !stdinIsTerminal()) {
			return errDeleteNeedsForce
		}
	}
	if f, ok := p.(provider.Filer); ok {
		if filing := f.Filing(); !filing.IsZero() {
			uses, where := f.UsesFiling()
			switch {
			case *common.delete != "":
				return errors.New("--folder and --tag don't go with --delete: name the entries to delete by ID")
			case *common.list || *common.setup:
			case !uses:
				return fmt.Errorf("--folder and --tag file an entry as it's stored, or narrow a list: use them with %s", where)
			}
			if err := filing.Check(); err != nil {
				return err
			}
		}
	}
	switch {
	case *common.setup:
		return nil
	case *common.list || *common.delete != "":
		if c, ok := p.(interface{ CheckListArgs() error }); ok {
			return c.CheckListArgs()
		}
		return nil
	}
	if c, ok := p.(interface{ CheckArgs() error }); ok {
		return c.CheckArgs()
	}
	return nil
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
	{"backup", "Copy the vault now, into the backups folder or a file"},
	{"completion", "Print a shell completion script (bash, zsh, fish)"},
	{"config", "Show settings and where each comes from"},
	{"doctor", "Check sesh's setup, and that the vault can all be read"},
	{"edit", "Rename an entry, or change its username, kind, or secret"},
	{"folder", "Move entries between folders, rename folders, list them"},
	{"init", "Choose where sesh keeps the vault"},
	{"inject", "Fill a template's sesh:// references into a file"},
	{"recover", "Set a new master password with the vault's recovery key"},
	{"recovery", "Make, remove, or check this vault's recovery key"},
	{"restore", "List the backups, or replace the vault with one"},
	{"run", "Run a command with secrets from the vault in its environment"},
	{"show", "Show an entry: its URL, notes, fields, folder and tags"},
	{"tag", "Tag entries, take tags off, rename tags, list them"},
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

// unavailableStore is a credential store whose every call fails with err.
// It stands in for the store in commands that don't open one, so a routing
// bug (a command that needs the store classified as one that doesn't)
// fails loudly instead of silently succeeding.
type unavailableStore struct{ err error }

var errNoStore = fmt.Errorf("no credential store opened for this command")

func (u unavailableStore) Get(vault.Key) ([]byte, error)               { return nil, u.err }
func (u unavailableStore) Put(vault.Key, []byte) error                 { return u.err }
func (u unavailableStore) Save(*vault.Entry, []byte) error             { return u.err }
func (u unavailableStore) SetSettings(vault.Key, vault.Settings) error { return u.err }
func (u unavailableStore) Lookup(vault.Key) (vault.Entry, error)       { return vault.Entry{}, u.err }
func (u unavailableStore) Exists(vault.Key) error                      { return u.err }
func (u unavailableStore) List(*vault.Filter) ([]vault.Entry, error)   { return nil, u.err }
func (u unavailableStore) Delete(vault.Key) error                      { return u.err }
func (u unavailableStore) DeleteMany([]vault.Key) error                { return u.err }
func (u unavailableStore) Details(vault.Key, string) (vault.Details, error) {
	return vault.Details{}, u.err
}
func (u unavailableStore) SetDetails(vault.Key, *vault.Details) error { return u.err }
func (u unavailableStore) SaveWithDetails(*vault.Entry, []byte, *vault.Details) error {
	return u.err
}

// appSettingsFrom is the settings the app's commands use, from cfg.
func appSettingsFrom(cfg *config.Config) AppSettings {
	return AppSettings{ClipboardTimeout: cfg.ClipboardTimeout.Value, KDF: cfg.KDF()}
}

// cliOverrides holds setting flags given on the command line.
var cliOverrides config.Overrides

// settings resolves this run's settings: flags, then env, then the config
// file, then defaults.
func settings() (*config.Config, error) {
	return config.Load(cliOverrides)
}

// buildProvider opens the vault with cfg's settings; the caller closes it.
func buildProvider(cfg *config.Config) (vault.Store, io.Closer, error) {
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

	ks, err := buildKeySource(cfg)
	if err != nil {
		return nil, err
	}
	store, err := openStoreWith(dbPath, ks)
	if err != nil {
		return nil, err
	}
	pruneAuditLog(store, cfg)
	warnAuditSize(store, cfg)
	autoBackup(store, cfg)
	return store, nil
}

// openStoreWith opens the store at dbPath over oracle, and confirms the
// file it opened is the vault whose key record oracle's key was checked
// against. The store owns oracle once
// opened; if opening fails, oracle is closed here so an agent connection or
// a cached master key doesn't outlive the failure.
func openStoreWith(dbPath string, oracle database.CryptoOracle) (*database.Store, error) {
	store, err := database.Open(dbPath, oracle)
	if err != nil {
		if c, ok := oracle.(interface{ Close() }); ok {
			c.Close()
		}
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := store.CheckKey(); err != nil {
		if closeErr := store.Close(); closeErr != nil {
			return nil, fmt.Errorf("%w (close also failed: %v)", err, closeErr)
		}
		return nil, err
	}

	return store, nil
}

// requireVault returns nil when the vault at dbPath exists, missing as the
// error when it doesn't yet, or why its key record can't be read.
func requireVault(dbPath, missing string) error {
	_, err := database.ReadUnlockMaterial(dbPath)
	if errors.Is(err, database.ErrNoVault) {
		return errors.New(missing)
	}
	return err
}

// vaultMissing reports whether there's no vault at dbPath yet: the next
// open creates it.
func vaultMissing(dbPath string) bool {
	_, err := database.ReadUnlockMaterial(dbPath)
	return errors.Is(err, database.ErrNoVault)
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
func unlockAgentWith(dbPath string, pw []byte) {
	defer secure.SecureZeroBytes(pw)
	mat, err := database.ReadUnlockMaterial(dbPath)
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
func withForgottenPasswordHint(err error, cfg passwordPromptConfig, dbPath string) error {
	if !cfg.interactive || !errors.Is(err, database.ErrWrongPassword) {
		return err
	}
	if _, rerr := database.ReadRecovery(dbPath); rerr == nil {
		return fmt.Errorf("%w.\n   If you've forgotten it, set a new one with your recovery key: sesh recover", err)
	}
	return fmt.Errorf("%w.\n   If you've forgotten it, the vault can't be opened. To start over, or to restore\n"+
		"   from an encrypted export, see \"Forgotten master password\" in the usage docs", err)
}

// buildKeySource returns the CryptoOracle the store encrypts through. It
// uses the agent when it can serve this vault, so later commands do not
// prompt again. A vault not created yet, or an agent that cannot be
// reached or fails to unlock, falls back to MasterPasswordSource, reusing
// a password already typed. A wrong password is retried against the agent
// and is returned to the caller when the attempt budget is spent. With
// SESH_MASTER_PASSWORD set, the agent is not used at all.
func buildKeySource(cfg *config.Config) (database.CryptoOracle, error) {
	return buildKeySourceWith(cfg.DBPath.Value, resolvePasswordPrompt().withKDF(cfg.KDF()))
}

// buildKeySourceWith is buildKeySource with the password prompt given, so
// tests can stand in for a person at a terminal.
func buildKeySourceWith(dbPath string, cfg passwordPromptConfig) (database.CryptoOracle, error) {
	if !cfg.fromEnv {
		oracle, typed, err := keySourceFromAgent(dbPath, cfg)
		if err != nil {
			return nil, withForgottenPasswordHint(err, cfg, dbPath)
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
	firstRun := !cfg.fromEnv && vaultMissing(dbPath)
	if firstRun {
		fmt.Fprint(os.Stderr, vaultCreationNotice(dbPath)) //nolint:errcheck // best-effort notice
		cfg = cfg.keepingLastPassword(&created)
	}
	defer func() { secure.SecureZeroBytes(created) }()

	mps := cfg.newSource(dbPath)
	// Eagerly unlock so every operation — including metadata-only reads
	// like --list and --delete — requires the master password. Without
	// this, the store would only prompt on decryption, letting an
	// attacker with filesystem access list and delete entries without
	// the password.
	key, err := mps.GetEncryptionKey()
	if err != nil {
		return nil, withForgottenPasswordHint(err, cfg, dbPath)
	}
	secure.SecureZeroBytes(key)
	if firstRun {
		unlockAgentWith(dbPath, created)
		offerRecovery(cfg, dbPath)
		offerTouchID(cfg, dbPath)
	}
	return database.NewKeySourceOracle(mps), nil
}

// keySourceFromAgent connects to the agent and returns an oracle when the
// agent can serve crypto for the vault at dbPath.
//
// A nil oracle and nil error mean the caller should fall back to a direct
// master-password source: the vault has no usable key record yet,
// or the agent could not be reached or failed during unlock. In the last
// case typed holds the password the user already entered, so the fallback
// can use it instead of prompting again; the caller must zero it. A
// non-nil error means the command should stop: the password attempt
// budget was spent, or the prompt itself failed. Wrong-password replies
// stay on the agent for every attempt.
func keySourceFromAgent(dbPath string, cfg passwordPromptConfig) (oracle database.CryptoOracle, typed []byte, err error) {
	// The key record is a local read. Without one (first run) or with a
	// bad one, the direct source takes over, so don't start an agent.
	dataDir := filepath.Dir(dbPath)
	mat, err := database.ReadUnlockMaterial(dbPath)
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
	// kdf is the Argon2id settings a new key record (a new vault, or a
	// changed master password) gets: the configured ones, set by withKDF.
	kdf kdf.Params
}

// withKDF returns c with the Argon2id settings a new key record gets.
func (c passwordPromptConfig) withKDF(k kdf.Params) passwordPromptConfig {
	c.kdf = k
	return c
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
	return terminalPasswordPrompt()
}

// terminalPasswordPrompt reads passwords at the terminal, ignoring
// SESH_MASTER_PASSWORD; interactive says whether stdin is one. Tests
// replace it.
var terminalPasswordPrompt = func() passwordPromptConfig {
	return passwordPromptConfig{
		prompt:      terminalPrompt,
		interactive: term.IsTerminal(int(os.Stdin.Fd())),
		confirm:     func(p string) (bool, error) { return askYes(os.Stdin, os.Stderr, p) },
		readLine:    func(p string) (string, error) { return readLine(os.Stdin, os.Stderr, p) },
	}
}

// newSource constructs a MasterPasswordSource for the vault at dbPath
// using this config's prompt, and only enables the retry budget when the
// prompt is interactive.
func (c passwordPromptConfig) newSource(dbPath string) *database.MasterPasswordSource {
	return database.NewMasterPasswordSource(dbPath, c.prompt, c.options()...)
}

func (c passwordPromptConfig) options() []database.Option {
	opts := []database.Option{database.WithNewPasswordCheck(c.checkNewPassword)}
	if c.kdf != (kdf.Params{}) {
		opts = append(opts, database.WithKDFParams(c.kdf))
	}
	if c.interactive {
		opts = append(opts, database.WithMaxAttempts(interactivePasswordAttempts))
	}
	return opts
}

// checkNewPassword warns when a new master password is easy to guess. With
// someone at the terminal it asks whether to use it anyway, and a no (the
// default) asks for another; with nobody to ask, it only warns.
func (c passwordPromptConfig) checkNewPassword(pw []byte) error {
	if !password.IsWeak(pw) {
		return nil
	}
	fmt.Fprintln(os.Stderr, "⚠️  This master password is easy to guess: a cracking program would likely find it in under 100 million tries, and it protects every secret in the vault.") //nolint:errcheck // best-effort warning
	if !c.interactive || c.readLine == nil {
		return nil
	}
	answer, err := c.readLine("Use it anyway? [y/N]: ")
	if err != nil {
		return fmt.Errorf("read answer: %w", err)
	}
	if a := strings.ToLower(strings.TrimSpace(answer)); a == "y" || a == "yes" {
		return nil
	}
	return database.ErrTryAnotherPassword
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

// errReported is a failure the command has already reported in full; fatal
// only sets the exit code.
var errReported = errors.New("already reported")

// fatal prints an error to stderr and exits
func fatal(app *App, err error) {
	if errors.Is(err, errReported) {
		app.Exit(1)
		return
	}
	if status, ok := errors.AsType[exitStatus](err); ok {
		app.Exit(int(status))
		return
	}
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
	case "backup":
		if err := runBackup(app, rest); err != nil {
			fatal(app, err)
		}
		return
	case "edit":
		if err := runEdit(app, rest); err != nil {
			fatal(app, err)
		}
		return
	case "show":
		if err := runShow(app, rest); err != nil {
			fatal(app, err)
		}
		return
	case "run":
		if err := runRun(app, rest); err != nil {
			fatal(app, err)
		}
		return
	case "inject":
		if err := runInject(app, rest); err != nil {
			fatal(app, err)
		}
		return
	case "restore":
		if err := runRestore(app, rest); err != nil {
			fatal(app, err)
		}
		return
	case "doctor":
		if err := runDoctor(app, rest); err != nil {
			fatal(app, err)
		}
		return
	case "folder":
		if err := runFolder(app, rest); err != nil {
			fatal(app, err)
		}
		return
	case "tag":
		if err := runTag(app, rest); err != nil {
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
	for i, arg := range args[1:] {
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
			others := append(slices.Clone(args[1:i+1]), args[i+2:]...)
			if err := runRekey(app, others, resolvePasswordPrompt()); err != nil {
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

	// What argsParse refused before opening the vault is reported here,
	// before any path that would use the vault it didn't open.
	if err := earlyCheck(svcProvider, common, fs.Args(), app.StdinIsTerminal); err != nil {
		fatal(app, err)
		return
	}

	// Provider-specific operations
	if *common.list {
		if err := app.ListEntries(serviceName); err != nil {
			fatal(app, err)
		}
		return
	}
	if ids := deleteIDs(common, fs.Args()); len(ids) > 0 {
		if err := app.DeleteEntries(serviceName, ids); err != nil {
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

// deleteIDs are the entry IDs a --delete names: its value, then the
// arguments after the flags. Nil without --delete.
func deleteIDs(common commonFlags, args []string) []string {
	if *common.delete == "" {
		return nil
	}
	ids := []string{*common.delete}
	for _, a := range args {
		if a != "--" { // the end of the flags, not an ID
			ids = append(ids, a)
		}
	}
	return ids
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
		delete:       fs.String("delete", "", "Delete entries by ID: --delete <id> [<id> ...], all or none; asks first unless --force"),
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
		"  --delete, -delete <id> ...    Delete entries by ID, all or none; asks first unless --force",
		"  --setup, -setup               Run setup wizard for selected service",
		"  --clip, -clip                 Copy code to clipboard",
		"  --list-services, -list-services  List available service providers",
		"  --version, -version           Show version information",
		"  --help, -help                 Show usage",
		"\nSetting overrides (for this command only; see `sesh config`):",
		"  --db-path path                Vault location",
		"\nCommands:",
		"  sesh init                     Set up the vault: where it lives",
		"  sesh config                   Show settings and where each comes from",
		"  sesh --rekey                  Change your master password",
		"  sesh recovery new|remove|status    A recovery key, in case you forget your master password",
		"  sesh recover                  Forgot the master password? Set a new one with the recovery key",
		"  sesh touchid enable|disable|status  Unlock with Touch ID (macOS)",
		"  sesh agent [lock|status|stop] Control the sesh agent",
		"  sesh audit [prune]            Show the vault's audit log, or prune it",
		"  sesh doctor                   Check the setup, and that the vault can all be read",
		"  sesh backup [file]            Copy the vault now (sesh also does this automatically)",
		"  sesh restore [backup]         List the backups, or replace the vault with one",
		"  sesh show <id> [--reveal]     Show an entry: its URL, notes, fields, folder and tags",
		"  sesh run [--env N=<ref>] -- <cmd>  Run a command with secrets in its environment",
		"  sesh inject -i <tpl> -o <file>  Fill a template's sesh:// references",
		"  sesh edit <id>                Rename an entry, or change its username, kind, or secret",
		"  sesh folder move|rename|list  File entries in folders",
		"  sesh tag add|remove|rename|list  Tag entries",
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
		"  --delete <id> ...             Delete entries by ID, all or none; asks first unless --force",
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
