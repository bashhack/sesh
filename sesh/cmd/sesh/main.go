package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/bashhack/sesh/internal/agent"
	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/kdf"
	"github.com/bashhack/sesh/internal/password"
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
		if err := writeCompletions(os.Stdout, os.Args[2:]); err != nil {
			os.Exit(1)
		}
		return
	}

	args, overrides, err := takeSettingFlags(os.Args)
	if err == nil {
		err = overrides.Validate()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ %v\n", err)
		os.Exit(2)
	}
	cliOverrides = overrides
	if err := checkCommandWord(args); err != nil {
		fmt.Fprintf(os.Stderr, "❌ %v\n", err)
		os.Exit(2)
	}

	// A broken config only stops commands that use the vault, which each
	// open it themselves; the rest, including `sesh config`, which reports
	// the problem, still run.
	appSettings := AppSettings{ClipboardTimeout: config.DefaultClipboardTimeout}
	if cfg, err := settings(); err == nil {
		appSettings = appSettingsFrom(cfg)
	}
	run(NewDefaultApp(versionInfo, appSettings), args)
}

// subcommands are the commands named by sesh's first argument, in the
// order completion offers them.
var subcommands = []candidate{
	{"list", "List the entries, or those of a kind"},
	{"search", "Find entries by any part of their name or username"},
	{"copy", "Copy an entry's secret, or its TOTP code"},
	{"get", "Print an entry's secret, or its TOTP code"},
	{"code", "Print a TOTP entry's code, and how long it has"},
	{"show", "Show an entry: its URL, notes, fields, folder and tags"},
	{"open", "Open an entry's URL in the browser"},
	{"add", "Add a password, API key, note, TOTP entry, or file"},
	{"edit", "Rename an entry, or change its username, kind, secret, or details"},
	{"generate", "Print a new random password or passphrase, stored nowhere"},
	{"trash", "Move entries to the trash; list it, put one back, or empty it"},
	{"history", "An entry's earlier secrets: list, show, copy, restore, forget"},
	{"folder", "Move entries between folders, rename folders, list them"},
	{"tag", "Tag entries, take tags off, rename tags, list them"},
	{"ui", "Search every entry, and copy its secret or TOTP code"},
	{"import", "Bring entries over from another app, or a sesh export"},
	{"export", "Write the entries to an export: encrypted, or plain"},
	{"backup", "Copy the vault now, into the backups folder or a file; list or delete backups"},
	{"restore", "List the backups, or replace the vault with one"},
	{"health", "Find weak, reused and old passwords"},
	{"doctor", "Check sesh's setup, and that the vault can all be read"},
	{"audit", "Show the vault's audit log, or prune it"},
	{"lock", "Lock sesh: the next command asks for the master password"},
	{"passwd", "Change the master password"},
	{"recovery", "Make, remove, or check this vault's recovery key"},
	{"recover", "Set a new master password with the vault's recovery key"},
	{"touchid", "Unlock with Touch ID (macOS)"},
	{"config", "Show settings and where each comes from, or change one"},
	{"init", "Choose where sesh keeps the vault"},
	{"agent", "Control the sesh agent"},
	{"run", "Run a command with secrets from the vault in its environment"},
	{"inject", "Fill a template's sesh:// references into a file"},
	{"git-credential", "Give git a site's password from sesh, as its credential helper"},
	{"sync", "Sync the vault with your other computers, through a folder"},
	{"aws", "Sign in to AWS with your MFA code"},
	{"completion", "Print a shell completion script (bash, zsh, fish)"},
}

// commands run what sesh's first argument names.
var commands = map[string]func(*App, []string) error{
	"list": runList, "search": runSearch, "copy": runCopy, "get": runGet, "code": runCode,
	"show": runShow, "open": runOpen, "add": runAdd, "edit": runEdit, "generate": runGenerate,
	"trash": runTrash, "history": runHistory, "folder": runFolder, "tag": runTag, "ui": runUI,
	"import": runImport, "export": runExport, "backup": runBackup, "restore": runRestore,
	"health": runHealth, "doctor": runDoctor, "audit": runAudit, "lock": runLock, "passwd": runPasswd,
	"recovery": runRecovery, "recover": runRecover, "touchid": runTouchID, "config": runConfig,
	"init": runInit, "agent": runAgent, "run": runRun, "inject": runInject, "aws": runAWS,
	"git-credential": runGitCredential, "completion": runCompletion, "sync": runSync,
}

// movedFlags say, for a flag that named a command before sesh's commands
// were words, the command it's become.
var movedFlags = map[string]string{
	"service":       "every kind of entry is in the same commands: sesh list, sesh copy, sesh add …",
	"list":          "sesh list",
	"delete":        "sesh trash <entry>",
	"setup":         "sesh add totp, or sesh aws setup",
	"clip":          "sesh copy <entry>",
	"rekey":         "sesh passwd",
	"list-services": "every kind of entry is in the same commands: sesh --help lists them",
}

// checkCommandWord refuses a first word that isn't a command, or --help
// or --version, naming the command it's closest to, or the one an old flag
// became.
func checkCommandWord(args []string) error {
	if len(args) < 2 {
		return nil
	}
	if strings.HasPrefix(args[1], "-") {
		switch name := strings.TrimLeft(args[1], "-"); {
		case isHelp(args[1]), name == "version":
			return nil
		case movedFlags[name] != "":
			return fmt.Errorf("sesh has no --%s: %s", name, movedFlags[name])
		}
		return fmt.Errorf("sesh takes a command first, not %q; the commands are listed by: sesh --help", args[1])
	}
	if name, _ := subcommand(args); name != "" || args[1] == "help" {
		return nil
	}
	word := args[1]
	trimmed := strings.ToLower(strings.TrimRight(word, ".,;:!?"))
	// A typo is a slip or two in a word of some length: a short word is
	// suggested only when it's exactly a command.
	best, bestDist := "", min(len([]rune(trimmed))/3, 2)+1
	for _, c := range subcommands {
		if d := password.EditDistance(trimmed, c.value); d < bestDist {
			best, bestDist = c.value, d
		}
	}
	if best != "" {
		return fmt.Errorf("sesh has no command %q; did you mean: sesh %s", word, best)
	}
	return fmt.Errorf("sesh has no command %q; the commands are listed by: sesh --help", word)
}

// subcommand returns the subcommand args name (one of subcommands) and the
// arguments after it, or "" and nil. Only the first argument counts, so an
// entry that happens to be named "agent" (sesh copy agent) is never
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

// appSettingsFrom is the settings the app's commands use, from cfg.
func appSettingsFrom(cfg *config.Config) AppSettings {
	return AppSettings{ClipboardTimeout: cfg.ClipboardTimeout.Value, KDF: cfg.KDF(), VaultPath: cfg.DBPath.Value}
}

// cliOverrides holds setting flags given on the command line.
var cliOverrides config.Overrides

// settings resolves this run's settings: flags, then env, then the config
// file, then defaults.
func settings() (*config.Config, error) {
	return config.Load(cliOverrides)
}

// settingsOf is settings, for the vault at dbPath: what follows the
// vault's place (its backups' folder) follows it, when the config names
// another vault now. "" is the config's vault.
func settingsOf(dbPath string) (*config.Config, error) {
	cfg, err := settings()
	if err != nil || dbPath == "" || dbPath == cfg.DBPath.Value {
		return cfg, err
	}
	moved := *cfg
	moved.DBPath.Value = dbPath
	return &moved, nil
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
	return openSQLiteStoreWithPrompt(cfg, resolvePasswordPrompt().withKDF(cfg.KDF()))
}

// openSQLiteStoreWithPrompt is openSQLiteStoreWith with the password prompt
// given.
func openSQLiteStoreWithPrompt(cfg *config.Config, pc passwordPromptConfig) (*database.Store, error) {
	dbPath := cfg.DBPath.Value
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil { //nolint:gosec // vault dir from the user's own settings
		return nil, fmt.Errorf("create vault directory: %w", err)
	}

	ks, err := buildKeySourceWith(dbPath, pc)
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
	keepAsSet(store, cfg)
	pruneHistory(store, cfg)
	expireTrash(store, cfg)
	autoSyncOpened(cfg, store)
	return store, nil
}

// keepAsSet gives store cfg's trash and history settings: without them a
// store keeps no earlier secrets, and deleting is for good.
func keepAsSet(store *database.Store, cfg *config.Config) {
	store.SetTrashDays(cfg.TrashKeepDays.Value)
	store.SetHistoryKeep(cfg.HistoryKeep.Value)
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
		"  (sesh export --file <file>).\n"
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
	// like sesh list and sesh trash — requires the master password. Without
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
	if st.Unlocked && st.UnlockID == id && !cfg.alwaysCheck {
		return agent.NewOracle(conn, id), nil, nil
	}
	// A person at the terminal is asked for a fingerprint first, when this
	// vault has Touch ID unlock on; scripts never wait on one.
	if cfg.interactive {
		unlocked, terr := tryTouchID(conn, dataDir, id, mat.Verify, false, note)
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
		retry, stop := afterAgentUnlock(uerr)
		switch {
		case retry:
			secure.SecureZeroBytes(kept)
			continue
		case stop != nil:
			secure.SecureZeroBytes(kept)
			closeAgentConn(conn)
			return nil, nil, stop
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

// afterAgentUnlock is what an unlock the agent refused leads to: asking
// again (a wrong password), stopping with stop (the screen locked while it
// was under way: not a key to make outside the agent), or neither, when
// the agent can't do it and the key is derived here instead.
func afterAgentUnlock(err error) (retry bool, stop error) {
	var pe *agent.ProtocolError
	if !errors.As(err, &pe) {
		return false, nil
	}
	switch pe.Code {
	case agent.ErrCodeWrongPassword:
		return true, nil
	case agent.ErrCodeScreenLocked:
		return false, errors.New("the screen locked while sesh was unlocking: unlock it again")
	}
	return false, nil
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
	// alwaysCheck asks for the password, and checks it, even when the
	// agent is already unlocked: for an app unlocking again, where a
	// password typed must be the right one.
	alwaysCheck bool
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

// terminalIn is where passwords and answers are typed: stdin, or the
// terminal itself (/dev/tty) for a command whose stdin carries data, as a
// git credential helper's does.
var terminalIn = os.Stdin

// terminalPasswordPrompt reads passwords at the terminal, ignoring
// SESH_MASTER_PASSWORD; interactive says whether terminalIn is one. Tests
// replace it.
var terminalPasswordPrompt = func() passwordPromptConfig {
	in := terminalIn
	return passwordPromptConfig{
		prompt:      terminalPrompt,
		interactive: term.IsTerminal(int(in.Fd())),
		confirm:     func(p string) (bool, error) { return askYes(in, os.Stderr, p) },
		readLine:    func(p string) (string, error) { return readLine(in, os.Stderr, p) },
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

// terminalPrompt reads a password from terminalIn without
// echo. Does not consult SESH_MASTER_PASSWORD — that decision belongs to
// resolvePasswordPrompt so the env-var policy lives in exactly one place.
func terminalPrompt(prompt string) ([]byte, error) {
	in := terminalIn
	if !term.IsTerminal(int(in.Fd())) {
		return nil, noTerminalFor(prompt)
	}
	if _, err := fmt.Fprint(os.Stderr, prompt); err != nil {
		return nil, err
	}
	pw, err := term.ReadPassword(int(in.Fd()))
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

// noTerminalFor is the error for a password prompt with no terminal to
// type at: it says what was asked for, and for the master password, the
// ways that need none.
func noTerminalFor(prompt string) error {
	switch p := strings.ToLower(prompt); {
	case strings.Contains(p, "recovery key"):
		return errors.New("there's no terminal here to type the recovery key at")
	case strings.Contains(p, "create"), strings.Contains(p, "confirm"):
		return errors.New("there's no terminal here to choose the new vault's master password at: run sesh at one, or give the password in SESH_MASTER_PASSWORD")
	}
	return errors.New("there's no terminal here to type the master password at: run sesh at one first, after which its agent keeps the vault unlocked for a while, or give the password in SESH_MASTER_PASSWORD")
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
	if sig, ok := errors.AsType[killedBy](err); ok {
		endBy(app, syscall.Signal(sig))
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
	// sesh help <command> is sesh <command> --help.
	if len(args) > 2 && args[1] == "help" {
		if _, ok := commands[args[2]]; ok {
			args = []string{args[0], args[2], "--help"}
		}
	}
	if name, rest := subcommand(args); name != "" {
		// sesh run's command, after its flags, can take -h of its own.
		if name != "run" && askedForHelp(rest) {
			rest = []string{"--help"}
		}
		autoSyncNext = autoSyncCommands[name]
		if err := commands[name](app, rest); err != nil {
			fatal(app, err)
		}
		return
	}
	if len(args) < 2 {
		if err := app.PrintGettingStarted(); err != nil {
			fatal(app, err)
		}
		return
	}
	switch {
	case isHelp(args[1]):
		if err := app.PrintUsage(); err != nil {
			fatal(app, err)
		}
		return
	case args[1] == "--version" || args[1] == "-version":
		if err := app.ShowVersion(); err != nil {
			fatal(app, err)
		}
		return
	}
	if err := checkCommandWord(args); err != nil {
		fatal(app, err)
	}
}

// askedForHelp says whether -h or --help is among a command's words,
// before any "--" (after it, the words are another program's, as with sesh
// run): it shows the command's usage, wherever it's typed, and does nothing
// else. The word help alone can name an entry, so it counts only first.
func askedForHelp(args []string) bool {
	for i, a := range args {
		switch {
		case a == "--":
			return false
		case a == "-h" || a == "-help" || a == "--help", i == 0 && a == "help":
			return true
		}
	}
	return false
}

// runLock is sesh lock: sesh's agent forgets the key.
func runLock(app *App, args []string) error {
	if len(args) > 0 {
		if isHelp(args[0]) {
			_, err := fmt.Fprintln(app.Stdout, "Usage: sesh lock\n  Lock sesh: its agent forgets the vault's key, and the next command asks\n  for the master password (or Touch ID).")
			return err
		}
		return fmt.Errorf("sesh lock takes nothing more, not %q", args[0])
	}
	return runAgent(app, []string{"lock"})
}

// runPasswd is sesh passwd: a new master password.
func runPasswd(app *App, args []string) error {
	return runRekey(app, args, resolvePasswordPrompt())
}

// PrintGettingStarted prints what plain `sesh` shows: what sesh is for;
// the first commands to run when there's no vault yet, or what's wrong
// when the settings don't load; then every option and command, as --help
// does.
func (a *App) PrintGettingStarted() error {
	intro := []string{"sesh keeps your TOTP secrets and passwords in an encrypted vault.", ""}
	switch cfg, err := settings(); {
	case err != nil:
		// Not the same as no vault: say what's wrong, which every command
		// using the vault would stop at.
		intro = append(intro, "Your settings have a problem, which `sesh config` shows: "+err.Error(), "")
	case vaultMissing(cfg.DBPath.Value):
		intro = append(intro,
			"Get started:",
			"  sesh add password <name>          store a password (or a key, note, or totp)",
			"  sesh import --from <app> <file>   bring entries over from another app",
			"  sesh init                         choose where the vault lives (optional)",
			"",
		)
	}
	for _, line := range intro {
		if _, err := fmt.Fprintln(a.Stdout, line); err != nil {
			return err
		}
	}
	return a.PrintUsage()
}

// usage is sesh --help: what sesh does, and every command, grouped.
const usage = `Usage: sesh <command> [arguments]

An <entry> is a few words of its name or username, as sesh ui's search takes
them ("github alice"; a kind word such as totp or note narrows), or its ID.

Everyday:
  sesh ui                         Search every entry: Enter copies its secret or code
  sesh list [passwords|keys|notes|totp|files]  List the entries (--folder F, --tag T)
  sesh search <words>             Find entries by name, username, or site
  sesh copy <entry>               Copy its password, key or note, or its TOTP code
  sesh get <entry>                Print it, for a pipe
  sesh code <entry>               Print a TOTP code, and how long it has
  sesh show <entry> [--reveal]    Show its URL, notes, fields, folder and tags
  sesh open <entry>               Open its URL in the browser

Changing entries:
  sesh add password|key|note|totp|file <name>  Add an entry (--generate; --qr for TOTP; --from for a file)
  sesh edit <entry>               Rename it, or change its secret, URL, notes, or fields
  sesh generate                   Print a new random password (--words N: a passphrase), stored nowhere
  sesh trash <entry>…             Move entries to the trash (sesh trash lists it)
  sesh history <entry>            Its earlier secrets: show, copy, restore, forget
  sesh folder move|rename|list    File entries in folders
  sesh tag add|remove|rename|list Tag entries

The vault:
  sesh import --from <app> <file> Bring entries over from another app, or a sesh export
  sesh export [--file F]          Write an encrypted export (or --format json|csv)
  sesh backup [file|list|delete]  Copy the vault now (sesh also does this automatically), list or delete backups
  sesh restore [backup]           List the backups, or replace the vault with one
  sesh sync [init|join|status|leave]  Sync the vault with your other computers, through a folder
  sesh health                     Find weak, reused and old passwords
  sesh doctor                     Check the setup, and that the vault can all be read
  sesh audit [prune]              Show the vault's audit log, or prune it

Locking and keys:
  sesh lock                       Lock sesh: the next command asks for the master password
  sesh passwd                     Change the master password
  sesh recovery new|remove|status A recovery key, in case you forget the master password
  sesh recover                    Forgot the master password? Set a new one with the recovery key
  sesh touchid enable|disable|status  Unlock with Touch ID (macOS)
  sesh agent [lock|status|stop]   Control the sesh agent

Setup and more:
  sesh init                       Choose where the vault lives
  sesh config [set <key> <value>] Show settings and where each comes from, or change one
  sesh run [--env N=<ref>] -- <cmd>   Run a command with secrets in its environment
  sesh inject -i <tpl> -o <file>  Fill a template's sesh:// references
  sesh git-credential             Git's credential helper: a site's password from sesh
  sesh aws [setup]                Sign in to AWS with your MFA code
  sesh completion bash|zsh|fish   Print a shell completion script

Options:
  --db-path path                  The vault's location, for this command (see sesh config)
  --help, --version

Each command's own help: sesh <command> --help`

// PrintUsage prints sesh --help.
func (a *App) PrintUsage() error {
	_, err := fmt.Fprintln(a.Stdout, usage)
	return err
}
