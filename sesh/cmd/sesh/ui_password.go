package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/bashhack/sesh/internal/backup"
	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/tui"
)

// uiChangePassword changes the master password of the vault the app has
// open from current to next, as sesh passwd does, and opens the vault
// again with next. It wipes both. An error means nothing changed.
func uiChangePassword(cfg *config.Config, current, next []byte) (tui.Changed, error) {
	defer secure.SecureZeroBytes(current)
	defer secure.SecureZeroBytes(next)
	dbPath := cfg.DBPath.Value
	if err := requireVault(dbPath, "the vault is gone from "+dbPath); err != nil {
		return tui.Changed{}, err
	}
	st, err := settingsOf(dbPath)
	if err != nil {
		return tui.Changed{}, err
	}
	src := database.NewMasterPasswordSource(dbPath, func(string) ([]byte, error) { return bytes.Clone(current), nil })
	store, err := database.Open(dbPath, database.NewKeySourceOracle(src))
	if err != nil {
		return tui.Changed{}, fmt.Errorf("open the vault: %w", err)
	}
	defer store.Close() //nolint:errcheck // the change has committed, or failed, by then
	key, err := src.GetEncryptionKey()
	if errors.Is(err, database.ErrWrongPassword) {
		return tui.Changed{}, tui.ErrWrongPassword
	}
	if err != nil {
		return tui.Changed{}, err
	}
	secure.SecureZeroBytes(key)
	if err := store.CheckKey(); err != nil {
		return tui.Changed{}, err
	}
	mat, err := database.ReadUnlockMaterial(dbPath)
	if err != nil {
		return tui.Changed{}, err
	}
	if err := checkRecoveryCarries(dbPath); err != nil {
		return tui.Changed{}, err
	}
	newKey, rec, err := database.NewMasterPasswordSource(dbPath, func(string) ([]byte, error) { return bytes.Clone(next), nil },
		database.WithKDFParams(st.KDF())).NewKey()
	if err != nil {
		return tui.Changed{}, fmt.Errorf("set the new master password: %w", err)
	}
	defer secure.SecureZeroBytes(newKey)
	res, notes, err := rekeyTo(store, dbPath, database.UnlockID(mat.Verify), newKey, rec, true)
	if err != nil {
		return tui.Changed{}, err
	}

	ch := tui.Changed{Said: []string{"Changed the master password, and re-encrypted " + withTrash(res.Entries, res.Trashed) + "."}}
	// The agent is unlocked again below with the new key, unless the
	// master password comes from SESH_MASTER_PASSWORD, so its being locked
	// is said only then, or when it couldn't be.
	fromEnv := os.Getenv("SESH_MASTER_PASSWORD") != ""
	agentNote := notes.agent
	if !fromEnv && !strings.HasPrefix(notes.agent, "warning:") {
		agentNote = ""
	}
	for _, n := range []string{notes.touch, notes.recovery, agentNote, notes.file} {
		if n != "" {
			ch.Said = append(ch.Said, n)
		}
	}
	if fromEnv {
		ch.Said = append(ch.Said, "SESH_MASTER_PASSWORD still holds the old password; update it, or the next command will refuse it as wrong.")
	}
	ch.OldBackups, ch.Renew = uiOldBackups(dbPath, "master password")
	v, err := reopenWith(cfg, bytes.Clone(next))
	if err != nil {
		ch.Said = append(ch.Said, fmt.Sprintf("It couldn't open the vault again (%v): unlock it with the new master password.", err))
		return ch, nil
	}
	ch.Vault = newUIVault(v)
	return ch, nil
}

// uiOldBackups says the backups of the vault at dbPath, which still open
// with the old what a change replaced, if there are any, and asks whether
// to delete them; a backups folder that can't be listed is said too.
func uiOldBackups(dbPath, what string) (said, ask string) {
	st, err := settingsOf(dbPath)
	if err != nil {
		return "warning: old backups: " + err.Error(), ""
	}
	s, err := backup.SeriesOf(dbPath, st.BackupFolder())
	if err != nil {
		return "warning: old backups: " + err.Error(), ""
	}
	all, err := s.List()
	switch {
	case err != nil:
		return "warning: old backups: " + err.Error(), ""
	case len(all) == 0:
		return "", ""
	}
	them := "them"
	if len(all) == 1 {
		them = "it"
	}
	return oldBackupsSaid(len(all), what, s.Dir) + " If the old " + what + " may have leaked, delete " + them + ".", "Delete " + them + " and make a fresh backup?"
}

// uiRenewBackups makes a fresh backup of the vault the app has open, then
// deletes the rest.
func uiRenewBackups(dbPath string) (string, error) {
	st, err := settingsOf(dbPath)
	if err != nil {
		return "", err
	}
	s, err := backup.SeriesOf(dbPath, st.BackupFolder())
	if err != nil {
		return "", err
	}
	return renewBackups(s, dbPath)
}
