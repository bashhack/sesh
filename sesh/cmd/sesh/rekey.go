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

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/migration"
	"github.com/bashhack/sesh/internal/secure"
)

const (
	rekeyDestSuffix   = ".new"
	rekeyBackupSuffix = ".pre-rekey"
	encKeyService     = "sesh-sqlite-encryption-key"
	sidecarFile       = "passwords.key"
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
	if os.Getenv("SESH_BACKEND") != "sqlite" {
		return fmt.Errorf("rekey requires SESH_BACKEND=sqlite")
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

	current := currentKeySourceName()
	if current == *target {
		return fmt.Errorf("already using %s; nothing to do", *target)
	}

	dbPath, err := database.DefaultDBPath()
	if err != nil {
		return fmt.Errorf("resolve database path: %w", err)
	}
	dataDir := filepath.Dir(dbPath)

	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no database to rekey at %s", dbPath)
		}
		return fmt.Errorf("stat database: %w", err)
	}
	if err := checkTargetKeyStateClean(*target, dataDir, kc); err != nil {
		return err
	}

	srcKS, err := newKeySourceByName(current, dataDir, kc)
	if err != nil {
		return fmt.Errorf("build source key source: %w", err)
	}
	srcStore, err := database.Open(dbPath, srcKS)
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
	confirmed, err := promptYesNo(app.Stderr, "\nProceed? [y/N]: ")
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

	destStore, err = database.Open(destPath, destKS)
	if err != nil {
		return fmt.Errorf("open destination database: %w", err)
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

	backupPath = dbPath + rekeyBackupSuffix
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

// currentKeySourceName returns the active key source as named by SESH_KEY_SOURCE.
// Empty defaults to "keychain" to match buildKeySource's behaviour.
func currentKeySourceName() string {
	v := os.Getenv("SESH_KEY_SOURCE")
	if v == "" {
		return "keychain"
	}
	return v
}

// newKeySourceByName constructs a KeySource without unlocking or initialising
// it — the caller decides when to call GetEncryptionKey (which is what
// triggers the master password prompt or keychain key generation).
func newKeySourceByName(name, dataDir string, kc keychain.Provider) (database.KeySource, error) {
	switch name {
	case "password":
		return database.NewMasterPasswordSource(dataDir, promptMasterPassword), nil
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

// promptYesNo reads a y/N answer from stdin. Empty input (bare Enter) is "No"
// to match runMigrate's behaviour. Returns true only on explicit "y" or "Y".
func promptYesNo(stderr io.Writer, prompt string) (bool, error) {
	if _, err := fmt.Fprint(stderr, prompt); err != nil {
		return false, err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	answer := strings.TrimSpace(line)
	return answer == "y" || answer == "Y", nil
}
