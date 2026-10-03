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

	"github.com/bashhack/sesh/internal/agent"
	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/migration"
	"github.com/bashhack/sesh/internal/secure"
)

const (
	rekeyDestSuffix    = ".new"
	rekeyBackupSuffix  = ".pre-rekey"
	rotateBackupSuffix = ".pre-rotate"
	encKeyService      = "sesh-sqlite-encryption-key"
	sidecarFile        = "passwords.key"
)

// runRekey re-encrypts the SQLite store under a different KeySource and
// atomically swaps the result into place. The original DB is preserved at
// <dbPath>.pre-rekey for rollback. The old key state (sidecar or keychain
// entry) is left untouched; it becomes unused but is reported in the final
// summary so the user can clean it up via OS tools if desired.
//
// kc is the keychain provider used for keychain-mode key state checks and
// cleanup. Production passes keychain.NewDefaultProvider(); tests inject
// a mock. It can be nil if --to=password and the current source isn't
// keychain — keychain branches are only entered when the source or target
// is "keychain".
func runRekey(app *App, args []string, kc keychain.Provider) (err error) {
	st, err := settings()
	if err != nil {
		return err
	}
	if st.Backend.Value != config.BackendSQLite {
		return errNeedsSQLite("rekey")
	}

	fs := flag.NewFlagSet("rekey", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	target := fs.String("to", "", "Target key source: keychain or password")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *target != "keychain" && *target != "password" {
		return fmt.Errorf("--to must be 'keychain' or 'password', got %q", *target)
	}

	current := st.KeySource.Value
	if current == *target {
		// password → password is the in-place rotation case ("change my
		// master password"). Rotating the generated keychain key
		// (keychain → keychain) isn't supported.
		if current == "password" {
			return runRotateMasterPassword(app, resolvePasswordPrompt())
		}
		return fmt.Errorf("already using %s; nothing to do", *target)
	}

	dbPath := st.DBPath.Value
	dataDir := filepath.Dir(dbPath)

	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no database to rekey at %s", dbPath)
		}
		return fmt.Errorf("stat database: %w", err)
	}
	preBackupPath := dbPath + rekeyBackupSuffix
	if _, err := os.Stat(preBackupPath); err == nil {
		return fmt.Errorf("backup path %s already exists; remove it (or rename to preserve a prior backup) and retry", preBackupPath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat backup path: %w", err)
	}
	if err := checkTargetKeyStateClean(*target, dataDir, kc); err != nil {
		return err
	}

	srcKS, err := newKeySourceByName(current, dataDir, kc)
	if err != nil {
		return fmt.Errorf("build source key source: %w", err)
	}
	srcStore, err := database.Open(dbPath, database.NewKeySourceOracle(srcKS))
	if err != nil {
		return fmt.Errorf("open source database: %w", err)
	}

	// Rollback state — tracked through the function and consulted by a
	// deferred cleanup. Anything that's *true / non-empty when err != nil
	// gets unwound. On success commit, we zero them so cleanup is a no-op.
	var (
		destStore       *database.Store
		destPath        string
		targetCreated   bool
		srcStoreOpen    = true
		backupPath      string
		originalRenamed bool
	)

	defer func() {
		if srcStoreOpen {
			if cerr := srcStore.Close(); cerr != nil {
				err = appendErr(err, "close source store", cerr)
			}
		}
		if err == nil {
			return
		}
		if destStore != nil {
			if cerr := destStore.Close(); cerr != nil {
				err = appendErr(err, "rollback close destination store", cerr)
			}
		}
		if destPath != "" {
			if rerr := os.Remove(destPath); rerr != nil && !os.IsNotExist(rerr) {
				err = appendErr(err, "rollback remove destination DB", rerr)
			}
		}
		if targetCreated {
			if cerr := cleanupNewKeyState(*target, dataDir, kc); cerr != nil {
				err = appendErr(err, "rollback target key state", cerr)
			}
		}
		if originalRenamed {
			if rerr := os.Rename(backupPath, dbPath); rerr != nil {
				err = appendErr(err, fmt.Sprintf("restore original DB to %s", dbPath), rerr)
			}
		}
	}()

	// Surface a wrong-source-password error before doing anything destructive.
	srcKey, err := srcKS.GetEncryptionKey()
	if err != nil {
		return fmt.Errorf("unlock source: %w", err)
	}
	secure.SecureZeroBytes(srcKey)
	if err := srcStore.VerifyKey(current); err != nil {
		return fmt.Errorf("check source key: %w", withKeyHint(err))
	}

	plan, err := migration.Plan(srcStore)
	if err != nil {
		return fmt.Errorf("scan source: %w", err)
	}

	if _, perr := fmt.Fprintf(app.Stderr, "About to re-encrypt %d entries: %s → %s\n", len(plan), current, *target); perr != nil {
		return perr
	}
	if _, perr := fmt.Fprintf(app.Stderr, "  source DB:           %s\n", dbPath); perr != nil {
		return perr
	}
	if _, perr := fmt.Fprintf(app.Stderr, "  rollback file after: %s%s\n", dbPath, rekeyBackupSuffix); perr != nil {
		return perr
	}
	confirmed, err := promptYesNo(app.Stdin, app.Stderr, "\nProceed? [y/N]: ")
	if err != nil {
		return err
	}
	if !confirmed {
		if _, perr := fmt.Fprintln(app.Stderr, "Rekey cancelled."); perr != nil {
			return perr
		}
		return nil
	}

	destKS, err := newKeySourceByName(*target, dataDir, kc)
	if err != nil {
		return fmt.Errorf("build target key source: %w", err)
	}
	if err := initializeTargetKeySource(destKS, *target); err != nil {
		return fmt.Errorf("set up target key source: %w", err)
	}
	targetCreated = true

	destPath = dbPath + rekeyDestSuffix
	if _, err := os.Stat(destPath); err == nil {
		return fmt.Errorf("destination path %s already exists; remove it and retry", destPath)
	}

	destStore, err = database.Open(destPath, database.NewKeySourceOracle(destKS))
	if err != nil {
		return fmt.Errorf("open destination database: %w", err)
	}
	// Records the new key's check value in the new database, so it
	// becomes current in the same rename as the entries.
	if err := destStore.CheckKey(*target); err != nil {
		return fmt.Errorf("record destination key check: %w", err)
	}
	if err := destStore.InitKeyMetadata(); err != nil {
		return fmt.Errorf("init target key metadata: %w", err)
	}

	result, err := migration.Migrate(srcStore, destStore)
	if err != nil {
		return fmt.Errorf("copy entries: %w", err)
	}
	if len(result.Errors) > 0 {
		return fmt.Errorf("copy reported %d errors:\n  %s", len(result.Errors), strings.Join(result.Errors, "\n  "))
	}

	// Close stores BEFORE rename so SQLite checkpoints WAL and removes the
	// -wal/-shm sidecars; otherwise the rename leaves orphans.
	if err := destStore.Close(); err != nil {
		return fmt.Errorf("close destination store: %w", err)
	}
	destStore = nil // already closed; don't re-close in rollback
	if err := srcStore.Close(); err != nil {
		return fmt.Errorf("close source store: %w", err)
	}
	srcStoreOpen = false

	backupPath = preBackupPath
	// Brief window between these two renames where dbPath does not exist;
	// a concurrent open during this interval will fail with ENOENT. POSIX
	// has no portable atomic-two-file-swap, so we accept the window for
	// this single-user CLI.
	if err := os.Rename(dbPath, backupPath); err != nil {
		return fmt.Errorf("rename source DB to backup: %w", err)
	}
	originalRenamed = true
	if err := os.Rename(destPath, dbPath); err != nil {
		return fmt.Errorf("rename destination into place: %w", err)
	}

	// Commit: clear rollback state so the deferred cleanup is a no-op.
	destPath = ""
	targetCreated = false
	originalRenamed = false
	// Locked before any output, so a failed write below can't skip it.
	agentNote := lockAgentAfterRekey()

	if _, perr := fmt.Fprintf(app.Stderr, "\nRekeyed %d entries: %s → %s\n", result.Migrated, current, *target); perr != nil {
		return perr
	}
	if _, perr := fmt.Fprintf(app.Stderr, "Original DB preserved at %s\n", backupPath); perr != nil {
		return perr
	}
	if msg := unusedKeyStateNote(current, dataDir); msg != "" {
		if _, perr := fmt.Fprintln(app.Stderr, msg); perr != nil {
			return perr
		}
	}
	if _, perr := fmt.Fprintln(app.Stderr, updateKeySourceSetting(st, *target)); perr != nil {
		return perr
	}
	if msg := dropTouchID(dataDir); msg != "" {
		if _, perr := fmt.Fprintln(app.Stderr, msg); perr != nil {
			return perr
		}
	}
	if agentNote != "" {
		if _, perr := fmt.Fprintln(app.Stderr, agentNote); perr != nil {
			return perr
		}
	}
	return nil
}

// appendErr decorates a primary error with a secondary one from a cleanup or
// rollback path. Keeps the wrapped chain anchored on the first failure.
func appendErr(primary error, label string, secondary error) error {
	if primary == nil {
		return fmt.Errorf("%s: %w", label, secondary)
	}
	return fmt.Errorf("%w (%s also failed: %v)", primary, label, secondary)
}

// updateKeySourceSetting makes the key source setting match a vault just
// rekeyed to target, and returns a line saying what it did or what the user
// must change. The config file is edited in place (comments kept) when the
// setting came from it, or from the default when target isn't the default.
// An env var or flag can't be changed from here, so that's an instruction.
// If the setting is left stale, the vault's key check refuses the next
// command rather than letting it write with the old key.
func updateKeySourceSetting(st *config.Config, target string) string {
	ks := st.KeySource
	switch {
	case ks.Source == config.FromEnv:
		return fmt.Sprintf("Change %s to %q (or remove it) before the next command.", ks.Origin, target)
	case ks.Source == config.FromFlag:
		return fmt.Sprintf("Use --key-source %s from now on, or set key_source = %q in %s.", target, target, tildePath(st.Path))
	case ks.Source == config.FromDefault && target == config.KeySourcePassword:
		return "The key source is now the default, master password."
	}
	if err := config.SetTopLevel(st.Path, "key_source", target); err != nil {
		return fmt.Sprintf("warning: could not update %s (%v); set key_source = %q there yourself.", tildePath(st.Path), err, target)
	}
	return fmt.Sprintf("Set key_source = %q in %s.", target, tildePath(st.Path))
}

// newKeySourceByName constructs a KeySource without unlocking or initialising
// it — the caller decides when to call GetEncryptionKey (which is what
// triggers the master password prompt or keychain key generation).
func newKeySourceByName(name, dataDir string, kc keychain.Provider) (database.KeySource, error) {
	switch name {
	case "password":
		return resolvePasswordPrompt().newSource(dataDir), nil
	case "keychain":
		u, err := user.Current()
		if err != nil {
			return nil, fmt.Errorf("determine current user: %w", err)
		}
		return database.NewKeychainSource(kc, u.Username), nil
	default:
		return nil, fmt.Errorf("unknown key source %q (valid: keychain, password)", name)
	}
}

// initializeTargetKeySource persists fresh key state for ks. For password
// mode this means writing a new sidecar (via GetEncryptionKey, which also
// derives the key). For keychain mode it means generating a random 32-byte
// key and storing it under the canonical service name.
func initializeTargetKeySource(ks database.KeySource, target string) error {
	switch target {
	case "password":
		k, err := ks.GetEncryptionKey()
		if err != nil {
			return err
		}
		secure.SecureZeroBytes(k)
		return nil
	case "keychain":
		k, err := database.GenerateEncryptionKey()
		if err != nil {
			return err
		}
		defer secure.SecureZeroBytes(k)
		return ks.StoreEncryptionKey(k)
	default:
		return fmt.Errorf("unknown target %q", target)
	}
}

// checkTargetKeyStateClean refuses if the target's persistent state is
// already initialised. Refusing is safer than silently overwriting — the
// target sidecar's salt or the target keychain entry's stored key may be
// in use by something the user still needs.
func checkTargetKeyStateClean(target, dataDir string, kc keychain.Provider) error {
	switch target {
	case "password":
		path := filepath.Join(dataDir, sidecarFile)
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("target sidecar %s already exists; remove it manually before rekey", path)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("stat target sidecar: %w", err)
		}
		return nil
	case "keychain":
		u, err := user.Current()
		if err != nil {
			return fmt.Errorf("determine current user: %w", err)
		}
		existing, err := kc.GetSecret(u.Username, encKeyService)
		if err == nil {
			secure.SecureZeroBytes(existing)
			return fmt.Errorf("target keychain entry already exists for account %q; remove it via Keychain Access (or `security delete-generic-password -a %s -s %s`) before rekey", u.Username, u.Username, encKeyService)
		}
		if !errors.Is(err, keychain.ErrNotFound) {
			return fmt.Errorf("check target keychain entry: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unknown target %q", target)
	}
}

// cleanupNewKeyState removes the key state that initializeTargetKeySource
// created during rekey. Called only on failure paths after the target source
// successfully initialised.
func cleanupNewKeyState(target, dataDir string, kc keychain.Provider) error {
	switch target {
	case "password":
		path := filepath.Join(dataDir, sidecarFile)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove target sidecar: %w", err)
		}
		return nil
	case "keychain":
		u, err := user.Current()
		if err != nil {
			return fmt.Errorf("determine current user: %w", err)
		}
		if err := kc.DeleteEntry(u.Username, encKeyService); err != nil && !errors.Is(err, keychain.ErrNotFound) {
			return fmt.Errorf("delete target keychain entry: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unknown target %q", target)
	}
}

// unusedKeyStateNote returns a user-facing message about the now-unused old
// key state, or empty if there's nothing to say.
func unusedKeyStateNote(oldSource, dataDir string) string {
	switch oldSource {
	case "password":
		path := filepath.Join(dataDir, sidecarFile)
		if _, err := os.Stat(path); err == nil {
			return fmt.Sprintf("Note: old master-password sidecar at %s is now unused. Remove it manually if you want to clean up.", path)
		}
		return ""
	case "keychain":
		return "Note: old keychain entry '" + encKeyService + "' is now unused. Remove it via Keychain Access if you want to clean up."
	default:
		return ""
	}
}

// runRotateMasterPassword re-encrypts every entry under a freshly-derived
// key from a new master password. The old sidecar is preserved at
// passwords.key.pre-rotate and the old DB at <dbPath>.pre-rotate so the
// user has a recovery path if they later realize they typed the new
// password wrong (e.g. caps lock during the confirm step).
//
// Distinct from runRekey's source-switching path: source and target both
// use MasterPasswordSource; the only thing that changes is the salt and
// the derived key. The target source is constructed against a staging
// sidecar path (.new) so the canonical path keeps unlocking with the old
// password until the very end.
//
// cfg is the prompt configuration shared by source and target sources.
// Production passes resolvePasswordPrompt(); tests inject a sequenced
// prompt that returns the old password first, then the new one twice.
func runRotateMasterPassword(app *App, cfg passwordPromptConfig) (err error) {
	st, err := settings()
	if err != nil {
		return err
	}
	if st.Backend.Value != config.BackendSQLite {
		return errNeedsSQLite("rotate")
	}

	dbPath := st.DBPath.Value
	dataDir := filepath.Dir(dbPath)
	sidecarPath := filepath.Join(dataDir, sidecarFile)

	dbNewPath := dbPath + rekeyDestSuffix
	dbBackupPath := dbPath + rotateBackupSuffix
	sidecarNewPath := sidecarPath + rekeyDestSuffix
	sidecarBackupPath := sidecarPath + rotateBackupSuffix

	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no database to rotate at %s", dbPath)
		}
		return fmt.Errorf("stat database: %w", err)
	}
	if _, err := os.Stat(sidecarPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no sidecar to rotate at %s — is the master password key source actually in use?", sidecarPath)
		}
		return fmt.Errorf("stat sidecar: %w", err)
	}
	// Refuse if any staging or backup file from a prior attempt is still
	// around. Clobbering a prior backup would silently destroy a recovery
	// path; clobbering a prior staging file might silently mix old and
	// new state.
	for _, p := range []string{dbNewPath, dbBackupPath, sidecarNewPath, sidecarBackupPath} {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("path %s exists from a prior rotation; remove it (or rename to preserve a prior backup) and retry", p)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("stat %s: %w", p, err)
		}
	}

	srcKS := cfg.newSource(dataDir)
	srcStore, err := database.Open(dbPath, database.NewKeySourceOracle(srcKS))
	if err != nil {
		return fmt.Errorf("open source database: %w", err)
	}

	// Rollback state — same shape as runRekey. Anything *true / non-empty
	// when err != nil gets unwound; commit zeros them so cleanup no-ops.
	var (
		destStore      *database.Store
		destStoreOpen  bool
		destDBCreated  bool
		newSidecarMade bool
		srcStoreOpen   = true
		dbRenamed      bool
		sidecarRenamed bool
	)

	defer func() {
		if srcStoreOpen {
			if cerr := srcStore.Close(); cerr != nil {
				err = appendErr(err, "close source store", cerr)
			}
		}
		if err == nil {
			return
		}
		if destStoreOpen && destStore != nil {
			if cerr := destStore.Close(); cerr != nil {
				err = appendErr(err, "rollback close destination store", cerr)
			}
		}
		if destDBCreated {
			if rerr := os.Remove(dbNewPath); rerr != nil && !os.IsNotExist(rerr) {
				err = appendErr(err, "rollback remove staged DB", rerr)
			}
		}
		if newSidecarMade {
			if rerr := os.Remove(sidecarNewPath); rerr != nil && !os.IsNotExist(rerr) {
				err = appendErr(err, "rollback remove staged sidecar", rerr)
			}
		}
		// The lock-file sentinel (sidecarNewPath + ".lock") gets created
		// by initializeLocked the moment we open it with O_CREATE — that
		// happens before any password prompt, so it can be on disk even
		// when newSidecarMade is false (e.g. mismatched-confirm errors
		// thrown from initialize). Remove it unconditionally; IsNotExist
		// handles the never-created case.
		if rerr := os.Remove(sidecarNewPath + ".lock"); rerr != nil && !os.IsNotExist(rerr) {
			err = appendErr(err, "rollback remove staged sidecar lock", rerr)
		}
		// If only the DB rename succeeded, restore it. The sidecar is
		// still canonical at this point (rename happens after DB).
		if dbRenamed && !sidecarRenamed {
			if rerr := os.Rename(dbBackupPath, dbPath); rerr != nil {
				err = appendErr(err, fmt.Sprintf("restore original DB to %s", dbPath), rerr)
			}
		}
	}()

	// Surface "wrong current password" before we ask for the new one. The
	// retry loop in unlock() gives the user up to 3 tries on an interactive
	// TTY — driven by cfg.interactive.
	srcKey, err := srcKS.GetEncryptionKey()
	if err != nil {
		return fmt.Errorf("unlock current sidecar: %w", err)
	}
	secure.SecureZeroBytes(srcKey)
	if err := srcStore.VerifyKey("password"); err != nil {
		return fmt.Errorf("check current key: %w", withKeyHint(err))
	}

	plan, err := migration.Plan(srcStore)
	if err != nil {
		return fmt.Errorf("scan source: %w", err)
	}

	if _, perr := fmt.Fprintf(app.Stderr, "About to rotate master password and re-encrypt %d entries.\n", len(plan)); perr != nil {
		return perr
	}
	if _, perr := fmt.Fprintf(app.Stderr, "  source DB:           %s\n", dbPath); perr != nil {
		return perr
	}
	if _, perr := fmt.Fprintf(app.Stderr, "  rollback DB after:   %s\n", dbBackupPath); perr != nil {
		return perr
	}
	if _, perr := fmt.Fprintf(app.Stderr, "  rollback sidecar:    %s\n", sidecarBackupPath); perr != nil {
		return perr
	}
	confirmed, err := promptYesNo(app.Stdin, app.Stderr, "\nProceed? [y/N]: ")
	if err != nil {
		return err
	}
	if !confirmed {
		if _, perr := fmt.Fprintln(app.Stderr, "Rotation cancelled."); perr != nil {
			return perr
		}
		return nil
	}

	// Build the target source against the staged sidecar path. The first
	// GetEncryptionKey on this source triggers initialize() — i.e. the
	// "Create master password" + "Confirm master password" prompts that
	// generate the new salt and write the .new sidecar.
	destKS := cfg.newSourceAtPath(sidecarNewPath)
	destKey, err := destKS.GetEncryptionKey()
	if err != nil {
		return fmt.Errorf("create new sidecar: %w", err)
	}
	// Kept until the end: Touch ID unlock is re-wrapped with it after the
	// swap, when destKS's cache has been cleared by closing destStore.
	defer secure.SecureZeroBytes(destKey)
	newSidecarMade = true

	destStore, err = database.Open(dbNewPath, database.NewKeySourceOracle(destKS))
	if err != nil {
		return fmt.Errorf("open destination database: %w", err)
	}
	destStoreOpen = true
	destDBCreated = true
	if err := destStore.CheckKey("password"); err != nil {
		return fmt.Errorf("record new key check: %w", err)
	}
	if err := destStore.InitKeyMetadata(); err != nil {
		return fmt.Errorf("init target key metadata: %w", err)
	}

	result, err := migration.Migrate(srcStore, destStore)
	if err != nil {
		return fmt.Errorf("copy entries: %w", err)
	}
	if len(result.Errors) > 0 {
		return fmt.Errorf("copy reported %d errors:\n  %s", len(result.Errors), strings.Join(result.Errors, "\n  "))
	}

	// Close stores before rename so SQLite checkpoints WAL and removes
	// the -wal/-shm sidecars; otherwise the rename leaves orphans.
	if err := destStore.Close(); err != nil {
		return fmt.Errorf("close destination store: %w", err)
	}
	destStore = nil
	destStoreOpen = false
	if err := srcStore.Close(); err != nil {
		return fmt.Errorf("close source store: %w", err)
	}
	srcStoreOpen = false

	// Atomic swap. Order matters: rename DB first; if sidecar rename then
	// fails, the new DB sees the OLD sidecar — which can't decrypt it.
	// The rollback restores the DB rename. If the sidecar rename also
	// fails after we've already swapped DB+sidecar, we're committed —
	// surface both paths so the user can finish manually.
	if err := os.Rename(dbPath, dbBackupPath); err != nil {
		return fmt.Errorf("rename source DB to backup: %w", err)
	}
	dbRenamed = true
	if err := os.Rename(dbNewPath, dbPath); err != nil {
		return fmt.Errorf("rename destination DB into place: %w", err)
	}
	destDBCreated = false // canonical now; rollback no longer applies

	if err := os.Rename(sidecarPath, sidecarBackupPath); err != nil {
		return fmt.Errorf("rename source sidecar to backup: %w (DB is now at %s; restore manually if needed)", err, dbPath)
	}
	if err := os.Rename(sidecarNewPath, sidecarPath); err != nil {
		return fmt.Errorf("rename destination sidecar into place: %w (DB is at %s, old sidecar at %s, new sidecar at %s — finish the rename manually)", err, dbPath, sidecarBackupPath, sidecarNewPath)
	}
	sidecarRenamed = true
	newSidecarMade = false
	// Locked before any output, so a failed write below can't skip it.
	agentNote := lockAgentAfterRekey()
	// Touch ID unlock is re-wrapped for the new key, also before any output.
	touchNote := rewrapTouchID(dataDir, destKey)

	// The .new.lock sentinel was created when destKS first ran
	// initializeLocked. The .new sidecar it guarded has now been renamed
	// to the canonical path, so the lock file is genuinely orphaned —
	// nothing will ever flock against it again. Best-effort cleanup;
	// don't fail the rotation if remove fails.
	if rerr := os.Remove(sidecarNewPath + ".lock"); rerr != nil && !os.IsNotExist(rerr) {
		fmt.Fprintf(app.Stderr, "warning: remove staged sidecar lock %s: %v\n", sidecarNewPath+".lock", rerr) //nolint:errcheck // best-effort cleanup warning; failing to print it shouldn't fail the rotation
	}

	if _, perr := fmt.Fprintf(app.Stderr, "\nRotated %d entries under a new master password.\n", result.Migrated); perr != nil {
		return perr
	}
	if _, perr := fmt.Fprintf(app.Stderr, "Old DB preserved at %s\n", dbBackupPath); perr != nil {
		return perr
	}
	if _, perr := fmt.Fprintf(app.Stderr, "Old sidecar preserved at %s\n", sidecarBackupPath); perr != nil {
		return perr
	}
	if _, perr := fmt.Fprintln(app.Stderr, "Verify the new password works, then remove the .pre-rotate backups (use `shred -u` if available)."); perr != nil {
		return perr
	}
	if touchNote != "" {
		if _, perr := fmt.Fprintln(app.Stderr, touchNote); perr != nil {
			return perr
		}
	}
	if agentNote != "" {
		if _, perr := fmt.Fprintln(app.Stderr, agentNote); perr != nil {
			return perr
		}
	}
	return nil
}

// lockAgentAfterRekey locks a running, unlocked agent once the database is
// under a new key, and returns a line for the user ("" when there is
// nothing to say). The agent may still hold the old key, which opens the
// .pre-rekey or .pre-rotate backup without a password. No agent running is
// the normal case. The rekey has already succeeded, so a failure here is a
// warning that names the command to run instead.
func lockAgentAfterRekey() string {
	conn, err := agent.DialExisting()
	if err != nil {
		if agent.IsNotRunning(err) {
			return ""
		}
		return fmt.Sprintf("warning: could not reach the sesh agent to lock it (%v); run `sesh agent lock`", err)
	}
	defer closeAgentConn(conn)
	st, err := agent.Status(conn)
	if err == nil && !st.Unlocked {
		return ""
	}
	if err == nil {
		err = agent.Lock(conn)
	}
	if err != nil {
		return fmt.Sprintf("warning: could not lock the sesh agent (%v); run `sesh agent lock`", err)
	}
	return "Locked the sesh agent, which held the old key."
}

// promptYesNo reads a y/N answer from stdin. Empty input (bare Enter) is "No"
// to match runMigrate's behaviour. Returns true only on explicit "y" or "Y".
func promptYesNo(stdin io.Reader, stderr io.Writer, prompt string) (bool, error) {
	if _, err := fmt.Fprint(stderr, prompt); err != nil {
		return false, err
	}
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	answer := strings.TrimSpace(line)
	return answer == "y" || answer == "Y", nil
}
