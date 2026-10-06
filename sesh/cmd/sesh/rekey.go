package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/bashhack/sesh/internal/agent"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/migration"
	"github.com/bashhack/sesh/internal/secure"
)

const (
	rekeyDestSuffix    = ".new"
	rotateBackupSuffix = ".pre-rotate"
)

// runRekey changes the master password: every entry is re-encrypted under
// the key the new password gives. args are the command's other arguments:
// none, or a help flag. cfg is how the passwords are asked for; production
// passes resolvePasswordPrompt().
func runRekey(app *App, args []string, cfg passwordPromptConfig) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-help" || args[0] == "-h") {
		_, err := fmt.Fprintln(app.Stdout, "Usage: sesh --rekey\n  Change your master password: every entry is re-encrypted under the new one.")
		return err
	}
	if len(args) > 0 {
		return fmt.Errorf("--rekey takes no arguments, got %q: it changes your master password", strings.Join(args, " "))
	}
	return runRotateMasterPassword(app, cfg)
}

// appendErr decorates a primary error with a secondary one from a cleanup or
// rollback path. Keeps the wrapped chain anchored on the first failure.
func appendErr(primary error, label string, secondary error) error {
	if primary == nil {
		return fmt.Errorf("%s: %w", label, secondary)
	}
	return fmt.Errorf("%w (%s also failed: %v)", primary, label, secondary)
}

// runRotateMasterPassword re-encrypts every entry under a freshly-derived
// key from a new master password, into a new vault (.new) with its own key
// record, which then replaces the old one. The old vault is kept
// (.pre-rotate) only until the new one is in place, then removed.
//
// cfg is the prompt configuration shared by source and target sources.
// Production passes resolvePasswordPrompt(); tests inject a sequenced
// prompt that returns the old password first, then the new one twice.
func runRotateMasterPassword(app *App, cfg passwordPromptConfig) error {
	newKey, err := rotateMasterPassword(app, cfg, nil)
	secure.SecureZeroBytes(newKey)
	return err
}

// rotateMasterPassword re-encrypts the vault under a new master password.
// src opens the vault as it is; nil asks for the current master password.
// A recovery passes the key its recovery key opened, and then replaces the
// recovery key itself, so it isn't re-wrapped here. Once the new vault is
// in place it returns the new vault key, which the caller must zero, even
// if writing the summary then fails: a non-nil key means the change
// committed.
func rotateMasterPassword(app *App, cfg passwordPromptConfig, src database.KeySource) (newKey []byte, err error) {
	st, err := settings()
	if err != nil {
		return nil, err
	}
	// SESH_MASTER_PASSWORD answers every prompt with the current password,
	// so the new one is always asked at the terminal: otherwise the "new"
	// password would silently be the old one.
	newCfg := cfg
	if cfg.fromEnv {
		newCfg = terminalPasswordPrompt()
		if !newCfg.interactive {
			return nil, errors.New("SESH_MASTER_PASSWORD gives the current master password; the new master password is asked at a terminal, so run this at one")
		}
	}

	dbPath := st.DBPath.Value
	dataDir := filepath.Dir(dbPath)
	dbNewPath := dbPath + rekeyDestSuffix
	dbBackupPath := dbPath + rotateBackupSuffix

	if err := requireVault(dbPath, fmt.Sprintf("no database to rotate at %s", dbPath)); err != nil {
		return nil, err
	}

	srcKS := src
	if srcKS == nil {
		srcKS = cfg.newSource(dbPath)
	}
	srcStore, err := database.Open(dbPath, database.NewKeySourceOracle(srcKS))
	if err != nil {
		return nil, fmt.Errorf("open source database: %w", err)
	}

	// Rollback state: anything *true / non-empty when err != nil gets
	// unwound; commit zeros them so cleanup no-ops.
	var (
		destStore     *database.Store
		destStoreOpen bool
		destDBCreated bool
		srcStoreOpen  = true
		dbRenamed     bool
		swapped       bool
	)
	// The key-change lock, once taken, is released by this deferred call,
	// registered before the rollback's so it runs after it: no other change
	// can start while rollback is still putting files back.
	release := func() {}
	defer func() { release() }() //nolint:gocritic // the wrapper calls release as reassigned later; `defer release()` would bind the no-op now

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
		// Put back the old vault if the swap had moved it aside but the new
		// one never took its place.
		if dbRenamed && !swapped {
			if rerr := renameFile(dbBackupPath, dbPath); rerr != nil {
				err = appendErr(err, fmt.Sprintf("restore original DB to %s", dbPath), rerr)
			}
		}
	}()

	// Surface "wrong current password" before we ask for the new one. The
	// retry loop in unlock() gives the user up to 3 tries on an interactive
	// TTY — driven by cfg.interactive.
	srcKey, err := srcKS.GetEncryptionKey()
	if err != nil {
		return nil, fmt.Errorf("unlock the vault: %w", err)
	}
	secure.SecureZeroBytes(srcKey)
	// One key change at a time: held until this one ends, so another can't
	// clear the files this one's rollback needs.
	if release, err = lockKeyChange(dataDir); err != nil {
		release = func() {}
		return nil, err
	}
	// The vault opens with its key, so files left by an earlier change
	// (from an older sesh, or one that was interrupted) serve no purpose,
	// and the staged ones must go before new ones are made.
	if err := removeLeftovers(app.Stderr, keyChangeLeftovers(dbPath)...); err != nil {
		return nil, err
	}

	plan, err := migration.Plan(srcStore)
	if err != nil {
		return nil, fmt.Errorf("scan source: %w", err)
	}

	if _, perr := fmt.Fprintf(app.Stderr, "About to rotate master password and re-encrypt %s.\n", entryCount(len(plan))); perr != nil {
		return nil, perr
	}
	if _, perr := fmt.Fprintf(app.Stderr, "  source DB:           %s\n", dbPath); perr != nil {
		return nil, perr
	}
	if _, perr := fmt.Fprintln(app.Stderr, "  The old vault is kept until the new one is in place, then removed."); perr != nil {
		return nil, perr
	}
	confirmed, err := promptYesNo(app.Stdin, app.Stderr, "\nProceed? [y/N]: ")
	if err != nil {
		return nil, err
	}
	if !confirmed {
		if _, perr := fmt.Fprintln(app.Stderr, "Rotation cancelled."); perr != nil {
			return nil, perr
		}
		return nil, nil
	}

	// The new vault's source asks for the new master password ("Create" and
	// "Confirm") and creates the staged vault with its key record.
	destDBCreated = true
	destKS := newCfg.newSource(dbNewPath)
	destKey, err := destKS.GetEncryptionKey()
	if err != nil {
		return nil, fmt.Errorf("set the new master password: %w", err)
	}
	// Kept until the end: Touch ID unlock is re-wrapped with it after the
	// swap, when destKS's cache has been cleared by closing destStore.
	defer secure.SecureZeroBytes(destKey)

	destStore, err = database.Open(dbNewPath, database.NewKeySourceOracle(destKS))
	if err != nil {
		return nil, fmt.Errorf("open destination database: %w", err)
	}
	destStoreOpen = true

	result, err := migration.Migrate(srcStore, destStore)
	if err != nil {
		return nil, fmt.Errorf("copy entries: %w", err)
	}
	if len(result.Errors) > 0 {
		return nil, fmt.Errorf("copy reported %d errors:\n  %s", len(result.Errors), strings.Join(result.Errors, "\n  "))
	}
	if err := checkCopied(destStore, dbNewPath, destKey, len(plan)); err != nil {
		return nil, err
	}

	// Close stores before rename so SQLite checkpoints WAL and removes
	// the -wal/-shm sidecars; otherwise the rename leaves orphans.
	if err := destStore.Close(); err != nil {
		return nil, fmt.Errorf("close destination store: %w", err)
	}
	destStore = nil
	destStoreOpen = false
	if err := srcStore.Close(); err != nil {
		return nil, fmt.Errorf("close source store: %w", err)
	}
	srcStoreOpen = false

	// The swap: each rename is atomic, and the old vault is put back if the
	// second fails.
	if err := renameFile(dbPath, dbBackupPath); err != nil {
		return nil, fmt.Errorf("rename source DB to backup: %w", err)
	}
	dbRenamed = true
	if err := renameFile(dbNewPath, dbPath); err != nil {
		return nil, fmt.Errorf("rename destination DB into place: %w; the old vault was put back", err)
	}
	swapped = true
	destDBCreated = false // canonical now; rollback no longer applies
	// Locked before any output, so a failed write below can't skip it.
	agentNote := lockAgentAfterRekey()
	// Touch ID unlock is re-wrapped for the new key, also before any output.
	touchNote := rewrapTouchID(dbPath, destKey)
	recoveryNote := ""
	if src == nil {
		recoveryNote = rewrapRecovery(dbPath, destKey)
	}
	copiesNote := removeOldCopies(dbBackupPath)

	if _, perr := fmt.Fprintf(app.Stderr, "\nRotated %s under a new master password.\n", entryCount(result.Migrated)); perr != nil {
		return bytes.Clone(destKey), perr
	}
	if _, perr := fmt.Fprintln(app.Stderr, copiesNote); perr != nil {
		return bytes.Clone(destKey), perr
	}
	envNote := ""
	if cfg.fromEnv {
		envNote = "SESH_MASTER_PASSWORD still holds the old password; update it, or the next command will refuse it as wrong."
	}
	for _, msg := range []string{touchNote, recoveryNote, agentNote, envNote} {
		if msg == "" {
			continue
		}
		if _, perr := fmt.Fprintln(app.Stderr, msg); perr != nil {
			return bytes.Clone(destKey), perr
		}
	}
	return bytes.Clone(destKey), nil
}

// lockAgentAfterRekey locks a running, unlocked agent once the database is
// under a new key, and returns a line for the user ("" when there is
// nothing to say). The agent may still hold the old key, which opens the
// .pre-rotate backup without a password. No agent running is
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
	line, err := readAnswer(stdin)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	answer := strings.TrimSpace(line)
	return answer == "y" || answer == "Y", nil
}

// checkCopied confirms, before the new vault at destPath replaces the old
// one, that its key record opens with key and it holds every entry planned.
func checkCopied(dest *database.Store, destPath string, key []byte, want int) error {
	m, err := database.ReadUnlockMaterial(destPath)
	if err != nil {
		return fmt.Errorf("check the new vault's key: %w", err)
	}
	if _, err := database.Decrypt(key, m.Verify); err != nil {
		return fmt.Errorf("check the new vault's key: it doesn't open with the new master password")
	}
	got, err := migration.Plan(dest)
	if err != nil {
		return fmt.Errorf("check the new vault: %w", err)
	}
	if len(got) != want {
		return fmt.Errorf("the new vault holds %s, but %d were copied; nothing was changed", entryCount(len(got)), want)
	}
	return nil
}

// removeOldCopies deletes the old vault's copy once the new vault is in
// place. A copy would only
// let the old password or key open the old contents; the change already
// checked that the new vault works. It returns a line to show.
func removeOldCopies(paths ...string) string {
	var failed []string
	for _, p := range paths {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			failed = append(failed, fmt.Sprintf("%s (%v)", p, err))
		}
	}
	if len(failed) > 0 {
		return "warning: couldn't remove the old vault's copy, which opens with the old key; remove it yourself: " + strings.Join(failed, ", ")
	}
	return "Removed the old vault's copy, so the old key no longer opens anything."
}

// keyChangeLeftovers are the files a password change makes while it runs:
// the staged new vault and the copy of the old one, with SQLite's journal
// files for each, which must not outlive their vault: SQLite would apply a
// stale one to a new file of the same name.
func keyChangeLeftovers(dbPath string) []string {
	var paths []string
	for _, p := range []string{dbPath + rekeyDestSuffix, dbPath + rotateBackupSuffix} {
		paths = append(paths, p, p+"-wal", p+"-shm")
	}
	return paths
}

// removeLeftovers deletes files an earlier change left behind, and says
// which.
func removeLeftovers(w io.Writer, paths ...string) error {
	var removed []string
	for _, p := range paths {
		err := os.Remove(p)
		switch {
		case err == nil:
			removed = append(removed, filepath.Base(p))
		case !os.IsNotExist(err):
			return fmt.Errorf("remove %s, left by an earlier change: %w", p, err)
		}
	}
	if len(removed) > 0 {
		if _, err := fmt.Fprintf(w, "Removed files left by an earlier change: %s\n", strings.Join(removed, ", ")); err != nil {
			return err
		}
	}
	return nil
}

// keyChangeLockFile serialises key changes on a vault: a password change
// or a recovery.
const keyChangeLockFile = ".key-change.lock"

// lockKeyChange takes the vault's key-change lock without waiting. Held from
// before leftovers are cleared until the change ends, it stops a second
// change from deleting the first one's in-progress copies, which its
// rollback needs. The lock goes with the process, so a crash can't leave
// it held.
func lockKeyChange(dataDir string) (release func(), err error) {
	path := filepath.Join(dataDir, keyChangeLockFile)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // next to the user's own vault
	if err != nil {
		return nil, fmt.Errorf("open the key-change lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close() //nolint:errcheck // already failing
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.New("another sesh command is changing this vault's key; try again when it has finished")
		}
		return nil, fmt.Errorf("take the key-change lock: %w", err)
	}
	return func() {
		_ = f.Close() //nolint:errcheck // closing releases the lock; nothing to do on failure
	}, nil
}

// renameFile is os.Rename for the vault swaps and their rollback. Tests
// replace it to make one step fail.
var renameFile = os.Rename

// entryCount says how many entries, as "1 entry" or "n entries".
func entryCount(n int) string {
	if n == 1 {
		return "1 entry"
	}
	return fmt.Sprintf("%d entries", n)
}
