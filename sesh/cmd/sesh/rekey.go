package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/bashhack/sesh/internal/agent"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/recovery"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
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
// key from a new master password, in place, in one transaction
// (database.Store.Rekey).
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
// A recovery passes the key its recovery key opened; the used recovery key
// is removed in the same transaction, and the caller offers a new one. Once
// the change has committed it returns the new vault key, which the caller must zero, even
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
	newCfg = newCfg.withKDF(st.KDF())

	dbPath := st.DBPath.Value
	if err := requireVault(dbPath, fmt.Sprintf("no database to rotate at %s", dbPath)); err != nil {
		return nil, err
	}

	srcKS := src
	if srcKS == nil {
		srcKS = cfg.newSource(dbPath)
	}
	store, err := database.Open(dbPath, database.NewKeySourceOracle(srcKS))
	if err != nil {
		return nil, fmt.Errorf("open the vault: %w", err)
	}
	defer func() {
		if cerr := store.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close the vault: %w", cerr)
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
	if err := store.CheckKey(); err != nil {
		return nil, err
	}
	// Touch ID unlock and the recovery key are kept only if they were made
	// for this vault.
	srcMat, err := database.ReadUnlockMaterial(dbPath)
	if err != nil {
		return nil, err
	}
	oldID := database.UnlockID(srcMat.Verify)
	if src == nil {
		if err := checkRecoveryCarries(dbPath); err != nil {
			return nil, err
		}
	}

	entries, err := store.List(&vault.Filter{})
	if err != nil {
		return nil, err
	}
	if _, perr := fmt.Fprintf(app.Stderr, "About to change the master password and re-encrypt %s in %s.\n", entryCount(len(entries)), dbPath); perr != nil {
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

	key, rec, err := newCfg.newSource(dbPath).NewKey()
	if err != nil {
		return nil, fmt.Errorf("set the new master password: %w", err)
	}
	// Kept until the end: Touch ID unlock is re-wrapped with it after the
	// change.
	defer secure.SecureZeroBytes(key)

	// A password change keeps the recovery key; a recovery's change removes
	// it, since the used key has been taken out and typed in.
	var rewrap func(*database.RecoveryRecord, string) (*database.RecoveryRecord, error)
	if src == nil {
		rewrap = func(r *database.RecoveryRecord, newID string) (*database.RecoveryRecord, error) {
			w, err := recovery.Wrap(r.PublicKey, key, []byte(newID))
			if err != nil {
				return nil, err
			}
			nr := recovery.NewRecord(newID, r.PublicKey, w)
			nr.CreatedAt = r.CreatedAt // the same key
			return nr, nil
		}
	}
	res, err := store.Rekey(key, rec, rewrap)
	if err != nil {
		return nil, err
	}

	// Locked before any output, so a failed write below can't skip it.
	agentNote := lockAgentHoldingOldKey()
	// Touch ID unlock is re-wrapped for the new key, also before any output.
	touchNote := rewrapTouchID(dbPath, oldID, res.NewID, key)
	recoveryNote := ""
	switch res.Recovery {
	case database.RecoveryKept:
		recoveryNote = "Your recovery key still works: it now opens the vault with the new master password."
	case database.RecoveryStale:
		recoveryNote = "Your recovery key's record was for another vault, so it was removed; make a new one with: sesh recovery new"
	}

	if _, perr := fmt.Fprintf(app.Stderr, "\nRotated %s under a new master password.\n", entryCount(res.Entries)); perr != nil {
		return bytes.Clone(key), perr
	}
	fileNote := ""
	if res.OldVaultInFile {
		fileNote = "warning: another sesh command has the vault open, so the vault file on its own still holds the vault under the old password until that command ends; don't copy or back up the file until then."
	}
	envNote := ""
	if cfg.fromEnv {
		envNote = "SESH_MASTER_PASSWORD still holds the old password; update it, or the next command will refuse it as wrong."
	}
	for _, msg := range []string{touchNote, recoveryNote, agentNote, fileNote, envNote} {
		if msg == "" {
			continue
		}
		if _, perr := fmt.Fprintln(app.Stderr, msg); perr != nil {
			return bytes.Clone(key), perr
		}
	}
	// A recovery (src set) is for a forgotten password, not a leaked one.
	if src == nil {
		offerToRemoveOldBackups(app, st, "master password")
	}
	return bytes.Clone(key), nil
}

// lockAgentHoldingOldKey locks a running, unlocked agent once the database
// is under a new key (a password change, or a restore), and returns a line
// for the user ("" when there is nothing to say). The agent may still hold
// the old key, which opens any copy of the vault made before the change
// without a password. No agent running is the normal case. The change has
// already succeeded, so a failure here is a warning that names the command
// to run instead.
func lockAgentHoldingOldKey() string {
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

// promptYesNo reads a y/N answer from stdin: y or yes, in any case, is a
// yes; anything else, including just Enter, is a no.
func promptYesNo(stdin io.Reader, stderr io.Writer, prompt string) (bool, error) {
	if _, err := fmt.Fprint(stderr, prompt); err != nil {
		return false, err
	}
	line, err := readAnswer(stdin)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

// entryCount says how many entries, as "1 entry" or "n entries".
func entryCount(n int) string {
	if n == 1 {
		return "1 entry"
	}
	return fmt.Sprintf("%d entries", n)
}
