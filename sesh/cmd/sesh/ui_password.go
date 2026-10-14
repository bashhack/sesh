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
// open from current to next, as sesh --rekey does, and opens the vault
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
	// The agent is unlocked again below with the new key, so its being
	// locked is said only when it couldn't be.
	agentNote := ""
	if strings.HasPrefix(notes.agent, "warning:") {
		agentNote = notes.agent
	}
	for _, n := range []string{notes.touch, notes.recovery, agentNote, notes.file} {
		if n != "" {
			ch.Said = append(ch.Said, n)
		}
	}
	if os.Getenv("SESH_MASTER_PASSWORD") != "" {
		ch.Said = append(ch.Said, "SESH_MASTER_PASSWORD still holds the old password; update it, or the next command will refuse it as wrong.")
	}
	s, err := backup.SeriesOf(dbPath, st.BackupFolder())
	if err == nil {
		all, lerr := s.List()
		if len(all) > 0 {
			ch.OldBackups = oldBackupsSaid(len(all), "master password", s.Dir)
		}
		err = lerr
	}
	if err != nil {
		ch.Said = append(ch.Said, fmt.Sprintf("warning: old backups: %v", err))
	}
	v, err := reopenWith(cfg, bytes.Clone(next))
	if err != nil {
		ch.Said = append(ch.Said, fmt.Sprintf("It couldn't open the vault again (%v): unlock it with the new master password.", err))
		return ch, nil
	}
	ch.Vault = newUIVault(v)
	return ch, nil
}

// uiRenewBackups deletes the backups of the vault the app has open, and
// makes a fresh one.
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
