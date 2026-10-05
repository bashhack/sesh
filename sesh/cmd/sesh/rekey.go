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
	sidecarFile        = "passwords.key"
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
// key from a new master password. The old vault and key file are kept
// (.pre-rotate) only until the new ones are in place, then removed.
//
// Source and target both use MasterPasswordSource; the only thing that
// changes is the salt and the derived key. The target source is constructed against a staging
// sidecar path (.new) so the canonical path keeps unlocking with the old
// password until the very end.
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
	sidecarPath := filepath.Join(dataDir, sidecarFile)

	dbNewPath := dbPath + rekeyDestSuffix
	dbBackupPath := dbPath + rotateBackupSuffix
	sidecarNewPath := sidecarPath + rekeyDestSuffix
	sidecarBackupPath := sidecarPath + rotateBackupSuffix

	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no database to rotate at %s", dbPath)
		}
		return nil, fmt.Errorf("stat database: %w", err)
	}
	// A vault without its key file is refused here, saying why.
	if err := refuseNewKeyForExistingVault(dbPath); err != nil {
		return nil, err
	}

	srcKS := src
	if srcKS == nil {
		srcKS = cfg.newSource(dataDir)
	}
	srcStore, err := database.Open(dbPath, database.NewKeySourceOracle(srcKS))
	if err != nil {
		return nil, fmt.Errorf("open source database: %w", err)
	}

	// Rollback state: anything *true / non-empty when err != nil gets
	// unwound; commit zeros them so cleanup no-ops.
	var (
		destStore       *database.Store
		destStoreOpen   bool
		destDBCreated   bool
		newSidecarMade  bool
		srcStoreOpen    = true
		staging         bool
		dbRenamed       bool
		oldSidecarMoved bool
		sidecarRenamed  bool
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
		if newSidecarMade {
			if rerr := os.Remove(sidecarNewPath); rerr != nil && !os.IsNotExist(rerr) {
				err = appendErr(err, "rollback remove staged sidecar", rerr)
			}
		}
		// The staged sidecar's lock (sidecarNewPath + ".lock") is created
		// by initializeLocked the moment it's opened, before any prompt, so
		// it can exist even when newSidecarMade is false (e.g. a mismatched
		// confirmation). It's this change's only once staging has begun;
		// before that, it may belong to another change.
		if staging {
			if rerr := os.Remove(sidecarNewPath + ".lock"); rerr != nil && !os.IsNotExist(rerr) {
				err = appendErr(err, "rollback remove staged sidecar lock", rerr)
			}
		}
		// Put back whatever the swap had already moved aside: the old DB,
		// and the old sidecar if it had been moved but the new one never
		// took its place.
		if dbRenamed && !sidecarRenamed {
			if rerr := renameFile(dbBackupPath, dbPath); rerr != nil {
				err = appendErr(err, fmt.Sprintf("restore original DB to %s", dbPath), rerr)
			}
		}
		if oldSidecarMoved && !sidecarRenamed {
			if rerr := renameFile(sidecarBackupPath, sidecarPath); rerr != nil {
				err = appendErr(err, fmt.Sprintf("restore original sidecar to %s", sidecarPath), rerr)
			}
		}
	}()

	// Surface "wrong current password" before we ask for the new one. The
	// retry loop in unlock() gives the user up to 3 tries on an interactive
	// TTY — driven by cfg.interactive.
	srcKey, err := srcKS.GetEncryptionKey()
	if err != nil {
		return nil, fmt.Errorf("unlock current sidecar: %w", err)
	}
	secure.SecureZeroBytes(srcKey)
	if err := srcStore.VerifyKey(); err != nil {
		return nil, fmt.Errorf("check current key: %w", withKeyHint(err))
	}
	// One key change at a time: held until this one ends, so another can't
	// clear the files this one's rollback needs.
	if release, err = lockKeyChange(dataDir); err != nil {
		release = func() {}
		return nil, err
	}
	// The vault opens with its key, so files left by an earlier change
	// (from an older sesh, or one that was interrupted) serve no purpose,
	// and the staged ones must go before new ones are made.
	if err := removeLeftovers(app.Stderr, keyChangeLeftovers(dbPath, sidecarPath)...); err != nil {
		return nil, err
	}
	staging = true // from here, staged files and their lock are this change's

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

	// Build the target source against the staged sidecar path. The first
	// GetEncryptionKey on this source triggers initialize() — i.e. the
	// "Create master password" + "Confirm master password" prompts that
	// generate the new salt and write the .new sidecar.
	destKS := newCfg.newSourceAtPath(sidecarNewPath)
	destKey, err := destKS.GetEncryptionKey()
	if err != nil {
		return nil, fmt.Errorf("create new sidecar: %w", err)
	}
	// Kept until the end: Touch ID unlock is re-wrapped with it after the
	// swap, when destKS's cache has been cleared by closing destStore.
	defer secure.SecureZeroBytes(destKey)
	newSidecarMade = true

	destStore, err = database.Open(dbNewPath, database.NewKeySourceOracle(destKS))
	if err != nil {
		return nil, fmt.Errorf("open destination database: %w", err)
	}
	destStoreOpen = true
	destDBCreated = true
	if err := destStore.CheckKey(); err != nil {
		return nil, fmt.Errorf("record new key check: %w", err)
	}
	if err := destStore.InitKeyMetadata(); err != nil {
		return nil, fmt.Errorf("init target key metadata: %w", err)
	}

	result, err := migration.Migrate(srcStore, destStore)
	if err != nil {
		return nil, fmt.Errorf("copy entries: %w", err)
	}
	if len(result.Errors) > 0 {
		return nil, fmt.Errorf("copy reported %d errors:\n  %s", len(result.Errors), strings.Join(result.Errors, "\n  "))
	}
	if err := checkCopied(destStore, len(plan)); err != nil {
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

	// Atomic swap. Order matters: rename DB first; if sidecar rename then
	// fails, the new DB sees the OLD sidecar — which can't decrypt it.
	// The rollback restores the DB rename. If the sidecar rename also
	// fails after we've already swapped DB+sidecar, we're committed —
	// surface both paths so the user can finish manually.
	if err := renameFile(dbPath, dbBackupPath); err != nil {
		return nil, fmt.Errorf("rename source DB to backup: %w", err)
	}
	dbRenamed = true
	if err := renameFile(dbNewPath, dbPath); err != nil {
		return nil, fmt.Errorf("rename destination DB into place: %w", err)
	}
	destDBCreated = false // canonical now; rollback no longer applies

	if err := renameFile(sidecarPath, sidecarBackupPath); err != nil {
		return nil, fmt.Errorf("rename source sidecar to backup: %w; the old vault and key file were put back", err)
	}
	oldSidecarMoved = true
	if err := renameFile(sidecarNewPath, sidecarPath); err != nil {
		return nil, fmt.Errorf("rename destination sidecar into place: %w; the old vault and key file were put back", err)
	}
	sidecarRenamed = true
	newSidecarMade = false
	// Locked before any output, so a failed write below can't skip it.
	agentNote := lockAgentAfterRekey()
	// Touch ID unlock is re-wrapped for the new key, also before any output.
	touchNote := rewrapTouchID(dataDir, destKey)
	recoveryNote := ""
	if src == nil {
		recoveryNote = rewrapRecovery(dataDir, destKey)
	}
	copiesNote := removeOldCopies(dbBackupPath, sidecarBackupPath)

	// The .new.lock sentinel was created when destKS first ran
	// initializeLocked. The .new sidecar it guarded has now been renamed
	// to the canonical path, so the lock file is genuinely orphaned —
	// nothing will ever flock against it again. Best-effort cleanup;
	// don't fail the rotation if remove fails.
	if rerr := os.Remove(sidecarNewPath + ".lock"); rerr != nil && !os.IsNotExist(rerr) {
		fmt.Fprintf(app.Stderr, "warning: remove staged sidecar lock %s: %v\n", sidecarNewPath+".lock", rerr) //nolint:errcheck // best-effort cleanup warning; failing to print it shouldn't fail the rotation
	}

	if _, perr := fmt.Fprintf(app.Stderr, "\nRotated %s under a new master password.\n", entryCount(result.Migrated)); perr != nil {
		return bytes.Clone(destKey), perr
	}
	if _, perr := fmt.Fprintln(app.Stderr, copiesNote); perr != nil {
		return bytes.Clone(destKey), perr
	}
	for _, msg := range []string{touchNote, recoveryNote, agentNote} {
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

// checkCopied confirms, before the new vault replaces the old one, that it
// opens with its key and holds every entry planned.
func checkCopied(dest *database.Store, want int) error {
	if err := dest.VerifyKey(); err != nil {
		return fmt.Errorf("check the new vault's key: %w", err)
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

// removeOldCopies deletes the old vault's copy (and, for a password
// change, its key file) once the new vault is in place. A copy would only
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
// staged new files, and copies of the old vault and key file.
func keyChangeLeftovers(dbPath, sidecarPath string) []string {
	return []string{
		dbPath + rekeyDestSuffix, dbPath + rotateBackupSuffix,
		sidecarPath + rekeyDestSuffix, sidecarPath + rekeyDestSuffix + ".lock", sidecarPath + rotateBackupSuffix,
	}
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
