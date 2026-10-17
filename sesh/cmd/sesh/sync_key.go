package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/syncfolder"
	"github.com/bashhack/sesh/internal/vaultsync"
)

// errKeyToSend is a master password change made here that the sync folder
// hasn't taken yet: the folder still has the key record the vault had
// before. A sync sends it.
var errKeyToSend = errors.New("this computer's master password change hasn't reached the sync folder yet: sesh sync sends it, and the other computers then ask for the new password")

// errKeyChangedElsewhere is a sync folder whose master password was
// changed on another computer. A sync at a terminal asks for it; until
// then this vault works here, with its own, and doesn't sync.
var errKeyChangedElsewhere = errors.New("the master password was changed on another computer: sesh sync, at a terminal, asks for the new one and switches this vault to it; until then this vault works here, with its own, and doesn't sync")

// folderKey is how a sync folder's key record stands to the vault's.
type folderKey int

const (
	keySame folderKey = iota
	// keyToSend: errKeyToSend.
	keyToSend
	// keyChangedElsewhere: errKeyChangedElsewhere.
	keyChangedElsewhere
	// keyOtherVault: a folder for other vaults.
	keyOtherVault
)

// folderKeyOf is how the key record of the sync folder whose info is info
// stands to that of the vault at dbPath, m. It unlocks nothing.
func folderKeyOf(dbPath string, info *syncfolder.Info, m database.UnlockMaterial) (folderKey, error) {
	folderID := database.UnlockID(info.Key.Verify)
	if folderID == database.UnlockID(m.Verify) {
		return keySame, nil
	}
	synced, err := database.VaultSyncFolder(dbPath)
	if err != nil {
		return keySame, err
	}
	if synced != info.FolderID {
		return keyOtherVault, nil
	}
	prev, err := database.VaultKeyChange(dbPath)
	if err != nil {
		return keySame, err
	}
	if prev == folderID {
		return keyToSend, nil
	}
	return keyChangedElsewhere, nil
}

// syncKeyChangeWarning says what a master password change does to syncing,
// for a vault that syncs, or synced and could join its folder again; ""
// for one that never did. recovering is a change made with the recovery
// key.
func syncKeyChangeWarning(cfg *config.Config, recovering bool) string {
	if cfg.SyncDir.Value != "" {
		what := "the change"
		if recovering {
			what = "the new master password"
		}
		return fmt.Sprintf("This vault syncs with %s: %s goes to the sync folder, and the other computers ask for the new master password at their next sync.", tildePath(cfg.SyncDir.Value), what)
	}
	if id, err := database.VaultSyncFolder(cfg.DBPath.Value); err == nil && id != "" {
		return "This vault synced with a sync folder before: joining it again asks for the folder's master password and switches this vault to it, so this change isn't kept then."
	}
	return ""
}

// keyChangeAllowed refuses a master password change for a vault whose
// sync folder has a master password changed on another computer: that one
// is taken first. A folder that can't be read doesn't stop the change,
// which is sent later.
func keyChangeAllowed(cfg *config.Config) error {
	if cfg.SyncDir.Value == "" {
		return nil
	}
	info, err := syncfolder.New(cfg.SyncDir.Value).ReadInfo()
	if err != nil {
		return nil //nolint:nilerr // a folder not readable now gets the change later
	}
	m, err := database.ReadUnlockMaterial(cfg.DBPath.Value)
	if err != nil {
		return err
	}
	if k, err := folderKeyOf(cfg.DBPath.Value, info, m); err != nil || k != keyChangedElsewhere {
		return err
	}
	return errors.New("the master password was changed on another computer: take it first (sesh sync asks for it), then change it")
}

// rekeyMode is what a master password change made here means for
// syncing: sent to the folder when the vault syncs.
func rekeyMode(cfg *config.Config) database.RekeySync {
	if cfg.SyncDir.Value != "" {
		return database.RekeySend
	}
	return database.RekeyLocal
}

// heldKey is a key source for a key held here: the vault's new one, just
// made.
type heldKey struct {
	id  string
	key []byte
}

// UnlockID is the id of the key record the key is for.
func (h *heldKey) UnlockID() (string, error) { return h.id, nil } //nolint:unparam // the signature CheckKey asks key sources for

func (h *heldKey) GetEncryptionKey() ([]byte, error) { return bytes.Clone(h.key), nil }
func (h *heldKey) StoreEncryptionKey([]byte) error {
	return errors.New("a held key can't be stored")
}
func (h *heldKey) RequiresUserInput() bool { return false }
func (h *heldKey) Name() string            { return "the new master password's key" }
func (h *heldKey) Close()                  { secure.SecureZeroBytes(h.key) }

// openWithKey opens the vault at dbPath with key, whose key record is id.
func openWithKey(dbPath, id string, key []byte) (*database.Store, error) {
	store, err := database.Open(dbPath, database.NewKeySourceOracle(&heldKey{id: id, key: bytes.Clone(key)}))
	if err != nil {
		return nil, err
	}
	if err := store.CheckKey(); err != nil {
		_ = store.Close() //nolint:errcheck // already failing
		return nil, err
	}
	return store, nil
}

// sendKeyChange sends a master password change just made here to the sync
// folder: its key record, then every file there sealed with the old key,
// sealed again with the new one (old, the store the vault was open in
// before, still opens them). It says what it did, or why the change waits
// for the next sync.
func sendKeyChange(cfg *config.Config, old *database.Store, key []byte, rec database.UnlockMaterial, oldID string) string {
	f := syncfolder.New(cfg.SyncDir.Value)
	info, err := f.ReadInfo()
	if err != nil {
		return fmt.Sprintf("The sync folder can't be read now (%v): the change goes to it at the next sync, and then to the other computers.", err)
	}
	newID := database.UnlockID(rec.Verify)
	switch database.UnlockID(info.Key.Verify) {
	case oldID, newID:
	default:
		return "The master password was changed on another computer too, and that change is in the sync folder first: sesh sync asks for it, and this computer's change isn't kept."
	}
	store, err := openWithKey(cfg.DBPath.Value, newID, key)
	if err != nil {
		return fmt.Sprintf("The change couldn't be sent to the sync folder now (%v): it goes at the next sync.", err)
	}
	defer closeAuditStore(store)
	sum, err := sendWith(store, cfg, f, info, rec, vaultsync.Options{Prev: old.SyncSealer(), PrevKeyID: oldID})
	if err != nil {
		return fmt.Sprintf("The change couldn't be sent to the sync folder now (%v): it goes at the next sync.", err)
	}
	said := fmt.Sprintf("Sent the change to the sync folder %s, sealing %s again with the new key: the other computers ask for the new master password at their next sync.", tildePath(f.Dir()), nouns(sum.Resealed, "entry's file", "entries' files"))
	if n := len(sum.Problems); n > 0 {
		said += fmt.Sprintf(" %s; sesh sync says more.", nouns(n, "problem", "problems"))
	}
	return said
}

// sendWith writes the vault's key record, rec, to the sync folder f, whose
// info is info, then syncs store (open with the new key) with opts.
func sendWith(store *database.Store, cfg *config.Config, f syncfolder.Folder, info *syncfolder.Info, rec database.UnlockMaterial, opts vaultsync.Options) (*vaultsync.Summary, error) {
	sent := *info
	sent.Key = syncfolder.KeyRecord{Salt: rec.Salt, Verify: rec.Verify, Params: rec.Params}
	if err := f.WriteInfo(&sent); err != nil {
		return nil, err
	}
	if err := store.SyncKeyChangeSent(); err != nil {
		return nil, err
	}
	return vaultsync.SyncWith(store, f, cfg.SyncComputerName(), opts)
}

// sendPendingChange is sesh sync for a vault whose master password change
// made here the sync folder hasn't taken yet: it's sent now. The old key is
// gone, so files sealed with it are left for a computer that has it.
func sendPendingChange(app *App, cfg *config.Config, f syncfolder.Folder) error {
	info, err := f.ReadInfo()
	if err != nil {
		return err
	}
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	prev, err := store.SyncKeyChange()
	if err != nil {
		return err
	}
	rec, err := database.ReadUnlockMaterial(cfg.DBPath.Value)
	if err != nil {
		return err
	}
	sum, err := sendWith(store, cfg, f, info, rec, vaultsync.Options{PrevKeyID: prev})
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(app.Stdout, "Sent this computer's master password change to the sync folder: the other computers ask for the new password at their next sync."); err != nil {
		return err
	}
	return writeSyncSummary(app, tildePath(f.Dir()), sum)
}

// takeKeyChange is sesh sync for a vault whose sync folder has a master
// password changed on another computer: it asks for it, at a terminal,
// switches the vault to it (the folder's key record, so the same key), and
// syncs, sealing again with the new key the folder's files sealed with the
// old.
func takeKeyChange(app *App, cfg *config.Config, f syncfolder.Folder) error {
	info, err := f.ReadInfo()
	if err != nil {
		return err
	}
	pc := resolvePasswordPrompt().withKDF(cfg.KDF())
	// SESH_MASTER_PASSWORD gives this vault's password; the new one is
	// typed.
	newCfg := pc
	if pc.fromEnv {
		newCfg = terminalPasswordPrompt()
	}
	if !newCfg.interactive {
		return fmt.Errorf("%w (there's no terminal here to type it at)", errKeyChangedElsewhere)
	}
	store, err := openSQLiteStoreWithPrompt(cfg, pc)
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	m, err := database.ReadUnlockMaterial(cfg.DBPath.Value)
	if err != nil {
		return err
	}
	oldID := database.UnlockID(m.Verify)
	pending, err := store.SyncKeyChange()
	if err != nil {
		return err
	}
	folderRec := database.UnlockMaterial{Salt: info.Key.Salt, Verify: info.Key.Verify, Params: info.Key.Params}
	if _, err := fmt.Fprintln(app.Stderr, "The master password was changed on another computer."); err != nil {
		return err
	}
	pw, err := folderPassword(newCfg, "New master password (the one the other computers use now): ", folderRec)
	if err != nil {
		return err
	}
	defer secure.SecureZeroBytes(pw)
	key := database.DeriveKey(pw, folderRec.Salt, folderRec.Params)
	defer secure.SecureZeroBytes(key)
	var sum *vaultsync.Summary
	var syncErr error
	_, notes, err := rekeyTo(store, cfg.DBPath.Value, oldID, key, folderRec, true, database.RekeyAdopt, func() string {
		next, err := openWithKey(cfg.DBPath.Value, database.UnlockID(folderRec.Verify), key)
		if err != nil {
			syncErr = err
			return ""
		}
		defer closeAuditStore(next)
		sum, syncErr = vaultsync.SyncWith(next, f, cfg.SyncComputerName(), vaultsync.Options{Prev: store.SyncSealer(), PrevKeyID: oldID})
		return ""
	})
	if err != nil {
		return err
	}
	unlockAgentWith(cfg.DBPath.Value, bytes.Clone(pw))
	var said strings.Builder
	said.WriteString("This vault now opens with the new master password, as the other computers' do.\n")
	if pending != "" {
		said.WriteString("This computer's own master password change wasn't kept: the one made on another computer was in the sync folder first.\n")
	}
	for _, n := range []string{notes.touch, notes.recovery, notes.file} {
		if n != "" {
			said.WriteString(n + "\n")
		}
	}
	if _, err := fmt.Fprint(app.Stdout, said.String()); err != nil {
		return err
	}
	if syncErr != nil {
		return fmt.Errorf("the sync after switching: %w; sesh sync tries again", syncErr)
	}
	return writeSyncSummary(app, tildePath(f.Dir()), sum)
}
