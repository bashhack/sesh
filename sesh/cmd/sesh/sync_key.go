package main

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
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

// errKeyRolledBack is a sync folder whose key record is one this vault
// replaced: an older sesh-sync.json put back. A sync writes it as it is.
var errKeyRolledBack = errors.New("the sync folder's master password record is an older one, put back (by a sync tool, a restore, or someone): sesh sync writes it as it is now")

// errKeyFork is a sync folder whose key record is a change from a key this
// vault replaced: two computers changed the master password from the same
// one (a sync tool's race, or a record put back). The change whose key
// record's ID sorts last is kept, on every computer alike; a sync settles
// it.
var errKeyFork = errors.New("the master password was changed elsewhere from one this computer had before, while this computer's moved on to another: sesh sync settles it, keeping one of them on every computer (at a terminal, it may ask for the other's)")

// errKeyForged is a sync folder whose key record no change from this
// vault's leads to: not made by a computer that had this vault's key.
var errKeyForged = errors.New("the sync folder's master password record wasn't made by a computer that had this vault's key, so it isn't taken. If no computer of yours changed it, someone with access to the folder may have; sesh passwd puts this vault's back, and sesh sync leave stops syncing with the folder")

// folderKey is how a sync folder's key record stands to the vault's.
type folderKey int

const (
	keySame folderKey = iota
	// keyToSend: errKeyToSend.
	keyToSend
	// keyChangedElsewhere: errKeyChangedElsewhere.
	keyChangedElsewhere
	// keyRolledBack: errKeyRolledBack.
	keyRolledBack
	// keyFork: errKeyFork.
	keyFork
	// keyForged: errKeyForged.
	keyForged
	// keyOtherVault: a folder for other vaults.
	keyOtherVault
)

// folderKeyOf is how the key record of the sync folder whose info is info
// stands to that of the vault at dbPath, m. It unlocks nothing, so a
// change elsewhere is only one the folder's links lead to from a key this
// vault had; their proofs are checked as it's taken.
func folderKeyOf(dbPath string, info *syncfolder.Info, m database.UnlockMaterial) (folderKey, error) {
	folderID, ownID := database.UnlockID(info.Key.Verify), database.UnlockID(m.Verify)
	if folderID == ownID {
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
	return folderKeyFrom(dbPath, info, ownID)
}

// folderKeyFrom is how a sync folder's key record, not the vault's, stands
// to the vault at dbPath, whose key record's ID is ownID: one it replaced
// (put back), one a change from its key leads to (changed elsewhere), or
// neither (forged). Only the links' IDs are looked at: their proofs are
// checked once the vault is open.
func folderKeyFrom(dbPath string, info *syncfolder.Info, ownID string) (folderKey, error) {
	own, err := database.VaultKeyLinks(dbPath)
	if err != nil {
		return keySame, err
	}
	folderID := database.UnlockID(info.Key.Verify)
	if slices.ContainsFunc(own, func(l syncfolder.KeyLink) bool { return l.From == folderID }) {
		return keyRolledBack, nil
	}
	prev, err := database.VaultKeyChange(dbPath)
	if err != nil {
		return keySame, err
	}
	if changeFrom(info, knownKeys(ownID, prev)) != nil {
		return keyChangedElsewhere, nil
	}
	if changeFrom(info, replacedKeys(own)) != nil {
		return keyFork, nil
	}
	return keyForged, nil
}

// replacedKeys are the IDs of the key records the vault with links
// replaced: those its changes came from.
func replacedKeys(links []syncfolder.KeyLink) map[string]bool {
	ids := map[string]bool{}
	for i := range links {
		ids[links[i].From] = true
	}
	return ids
}

// forkKept says whether, of two changes from one key, the folder's (whose
// key record's ID is folderID) is kept over this vault's (ownID): the ID
// that sorts last wins, so every computer settles it alike. Tests turn it
// around, to settle it both ways.
var forkKept = func(folderID, ownID string) bool { return folderID > ownID }

// knownKeys are the IDs of the key records a change taken here may come
// from: the vault's key now, and, while a change made here waits to be
// sent, the one before it (the folder's). An older key of the vault's
// doesn't count: someone who learned an old master password can't make it
// take a change.
func knownKeys(ownID, prev string) map[string]bool {
	known := map[string]bool{ownID: true}
	if prev != "" {
		known[prev] = true
	}
	return known
}

// changeFrom is the nearest of changesFrom, or nil when there's none.
func changeFrom(info *syncfolder.Info, known map[string]bool) *syncfolder.KeyLink {
	if ls := changesFrom(info, known); len(ls) > 0 {
		return ls[0]
	}
	return nil
}

// changesFrom are the links from a key in known on a path of the folder's
// changes to its key record now, the nearest first: every path back is
// searched, the links being a graph (taking a change adds one from the
// taker's key), and every link between two keys is given, since anyone
// with the folder can add one alongside the real one.
func changesFrom(info *syncfolder.Info, known map[string]bool) []*syncfolder.KeyLink {
	into := map[string][]*syncfolder.KeyLink{}
	for i := range info.Links {
		into[info.Links[i].To] = append(into[info.Links[i].To], &info.Links[i])
	}
	start := database.UnlockID(info.Key.Verify)
	seen := map[string]bool{start: true}
	var out []*syncfolder.KeyLink
	for queue := []string{start}; len(queue) > 0; queue = queue[1:] {
		for _, l := range into[queue[0]] {
			if known[l.From] {
				out = append(out, l)
				continue
			}
			if !seen[l.From] {
				seen[l.From] = true
				queue = append(queue, l.From)
			}
		}
	}
	return out
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

// keyChangeAllowed refuses a master password change for a vault, open in
// store, whose sync folder has a master password changed on another
// computer: that one is taken first. A folder that can't be read doesn't
// stop the change, which is sent later; nor does one whose record is forged
// (its link's proof doesn't hold with this vault's key) or older, which the
// change replaces.
func keyChangeAllowed(cfg *config.Config, store *database.Store) error {
	if k, err := folderKeyNow(cfg); err != nil || k != keyChangedElsewhere {
		return err
	}
	if !changeProven(cfg, store) {
		return nil
	}
	return errors.New("the master password was changed on another computer: take it first (sesh sync asks for it; if this computer's own is forgotten, sesh recover opens it with the recovery key and takes it), then change it")
}

// changeProven says whether the first link of the sync folder's change,
// from this vault's key (or the one a change made here came from), has a
// proof that holds with that key, the vault open in store.
func changeProven(cfg *config.Config, store *database.Store) bool {
	info, err := syncfolder.New(cfg.SyncDir.Value).ReadInfo()
	if err != nil {
		return false
	}
	first, older, err := firstLink(store, info, false)
	if err != nil || first == nil {
		return false
	}
	defer older.Close()
	return proofHolds(store, older, first)
}

// provenFrom says whether the folder's change whose info is info has a
// first link from the key record fromID, an older key of the vault open in
// store, whose proof holds with that key.
func provenFrom(store *database.Store, info *syncfolder.Info, fromID string) bool {
	firsts := changesFrom(info, map[string]bool{fromID: true})
	if len(firsts) == 0 {
		return false
	}
	older, err := store.SyncOlderKeys()
	if err != nil {
		return false
	}
	defer older.Close()
	s := older.Sealer(fromID)
	return s != nil && slices.ContainsFunc(firsts, func(l *syncfolder.KeyLink) bool { return database.LinkProofHolds(s, l) })
}

// firstLink is the first link of the folder's change whose info is info
// leading from a key a change taken by the vault in store may come from
// (knownKeys, and with fork the keys it replaced): the nearest whose proof
// holds, else the nearest; and the vault's older keys. nil when there's
// none.
func firstLink(store *database.Store, info *syncfolder.Info, fork bool) (*syncfolder.KeyLink, *database.OlderKeys, error) {
	ownID, err := store.SyncKeyID()
	if err != nil {
		return nil, nil, err
	}
	prev, err := store.SyncKeyChange()
	if err != nil {
		return nil, nil, err
	}
	known := knownKeys(ownID, prev)
	if fork {
		own, err := store.SyncKeyLinks()
		if err != nil {
			return nil, nil, err
		}
		for id := range replacedKeys(own) {
			known[id] = true
		}
	}
	firsts := changesFrom(info, known)
	if len(firsts) == 0 {
		return nil, nil, nil
	}
	older, err := store.SyncOlderKeys()
	if err != nil {
		return nil, nil, err
	}
	for _, l := range firsts {
		if proofHolds(store, older, l) {
			return l, older, nil
		}
	}
	return firsts[0], older, nil
}

// proofHolds says whether l's proof holds with the vault's key it comes
// from: its key now, or an older one (older).
func proofHolds(store *database.Store, older *database.OlderKeys, l *syncfolder.KeyLink) bool {
	ownID, err := store.SyncKeyID()
	if err != nil {
		return false
	}
	from := store.SyncSealer()
	if l.From != ownID {
		from = older.Sealer(l.From)
	}
	return from != nil && database.LinkProofHolds(from, l)
}

// folderKeyNow is how the sync folder cfg names stands to the vault's key
// record, keySame when the vault doesn't sync or the folder can't be read.
func folderKeyNow(cfg *config.Config) (folderKey, error) {
	if cfg.SyncDir.Value == "" {
		return keySame, nil
	}
	info, err := syncfolder.New(cfg.SyncDir.Value).ReadInfo()
	if err != nil {
		return keySame, nil //nolint:nilerr // a folder not readable now is met at the next sync
	}
	m, err := database.ReadUnlockMaterial(cfg.DBPath.Value)
	if err != nil {
		return keySame, err
	}
	return folderKeyOf(cfg.DBPath.Value, info, m)
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

// syncOlder syncs store with f, opening files sealed with keys the vault
// had before through its links.
func syncOlder(store *database.Store, cfg *config.Config, f syncfolder.Folder) (*vaultsync.Summary, error) {
	older, err := store.SyncOlderKeys()
	if err != nil {
		return nil, err
	}
	defer older.Close()
	return vaultsync.SyncWith(store, f, cfg.SyncComputerName(), vaultsync.Options{Older: older})
}

// changeLink is the key link for a master password change from oldKey,
// whose key record's ID is oldID, to newKey, whose record is rec.
func changeLink(oldKey, newKey []byte, oldID string, rec database.UnlockMaterial) (*syncfolder.KeyLink, error) {
	return database.NewKeyLink(oldKey, newKey, oldID, database.UnlockID(rec.Verify))
}

// sendKeyChange sends a master password change just made here to the sync
// folder: its key record and links, then every file there sealed with an
// older key, sealed again with the new one. It says what it did, or why
// the change waits for the next sync.
func sendKeyChange(cfg *config.Config, key []byte, rec database.UnlockMaterial, oldID string) string {
	f := syncfolder.New(cfg.SyncDir.Value)
	info, err := f.ReadInfo()
	if err != nil {
		return fmt.Sprintf("The sync folder can't be read now (%v): the change goes to it at the next sync, and then to the other computers.", err)
	}
	newID := database.UnlockID(rec.Verify)
	store, err := openWithKey(cfg.DBPath.Value, newID, key)
	if err != nil {
		return fmt.Sprintf("The change couldn't be sent to the sync folder now (%v): it goes at the next sync.", err)
	}
	defer closeAuditStore(store)
	if folderID := database.UnlockID(info.Key.Verify); folderID != oldID && folderID != newID {
		// Another computer's change first, its link's proof holding with
		// the old key (which the link just made reaches), is kept; a record
		// forged or put back, this change replaces.
		if k, err := folderKeyFrom(cfg.DBPath.Value, info, oldID); err != nil || k == keyChangedElsewhere && provenFrom(store, info, oldID) {
			return "The master password was changed on another computer too, and that change is in the sync folder first: sesh sync asks for it, and this computer's change isn't kept."
		}
	}
	sum, err := sendWith(store, cfg, f, info, rec)
	if err != nil {
		return fmt.Sprintf("The change wasn't all sent to the sync folder (%v): the next sync finishes it.", err)
	}
	said := fmt.Sprintf("Sent the change to the sync folder %s, sealing %s again with the new key: the other computers ask for the new master password at their next sync.", tildePath(f.Dir()), nouns(sum.Resealed, "entry's file", "entries' files"))
	if n := len(sum.Problems); n > 0 {
		said += fmt.Sprintf(" %s; sesh sync says more.", nouns(n, "problem", "problems"))
	}
	return said
}

// sendWith writes the vault's key record, rec, and its links to the sync
// folder f, whose info is info, then syncs store (open with the new key),
// sealing again what's sealed with an older key.
func sendWith(store *database.Store, cfg *config.Config, f syncfolder.Folder, info *syncfolder.Info, rec database.UnlockMaterial) (*vaultsync.Summary, error) {
	links, err := store.SyncKeyLinks()
	if err != nil {
		return nil, err
	}
	// The folder's links stay: dropping one could leave files sealed with a
	// key nothing leads back to.
	sent := *info
	sent.Key = syncfolder.KeyRecord{Salt: rec.Salt, Verify: rec.Verify, Params: rec.Params}
	sent.Links = database.UnionLinks(links, info.Links)
	if err := f.WriteInfo(&sent); err != nil {
		return nil, err
	}
	if err := store.SyncKeyChangeSent(); err != nil {
		return nil, err
	}
	return syncOlder(store, cfg, f)
}

// sendPendingChange is sesh sync for a vault whose master password change
// made here the sync folder hasn't taken yet: it's sent now.
func sendPendingChange(app *App, cfg *config.Config, f syncfolder.Folder) error {
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	return sendPendingWith(app, cfg, f, store)
}

// sendPendingWith is sendPendingChange with the vault open in store.
func sendPendingWith(app *App, cfg *config.Config, f syncfolder.Folder, store *database.Store) error {
	info, err := f.ReadInfo()
	if err != nil {
		return err
	}
	rec, err := database.ReadUnlockMaterial(cfg.DBPath.Value)
	if err != nil {
		return err
	}
	sum, err := sendWith(store, cfg, f, info, rec)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(app.Stdout, "Sent this computer's master password change to the sync folder: the other computers ask for the new password at their next sync."); err != nil {
		return err
	}
	return writeSyncSummary(app, tildePath(f.Dir()), sum)
}

// mendRolledBack writes the vault's key record and links over an older
// sesh-sync.json put back in the folder f, keeping its ID.
func mendRolledBack(app *App, cfg *config.Config, f syncfolder.Folder) error {
	info, err := f.ReadInfo()
	if err != nil {
		return err
	}
	m, err := database.ReadUnlockMaterial(cfg.DBPath.Value)
	if err != nil {
		return err
	}
	links, err := database.VaultKeyLinks(cfg.DBPath.Value)
	if err != nil {
		return err
	}
	if err := f.WriteInfo(syncfolder.InfoFor(info.FolderID, syncfolder.KeyRecord{Salt: m.Salt, Verify: m.Verify, Params: m.Params}, database.UnionLinks(links, info.Links))); err != nil {
		return err
	}
	_, err = fmt.Fprintln(app.Stdout, "The sync folder's master password record was an older one, put back: written as it is now.")
	return err
}

// settleFork is sesh sync for a vault whose sync folder has a change from a
// key it replaced, made alongside its own: the one kept (forkKept) is the
// folder's, taken as a change elsewhere is, or this vault's, written over
// the folder's, with both's links.
func settleFork(app *App, cfg *config.Config, f syncfolder.Folder) error {
	info, err := f.ReadInfo()
	if err != nil {
		return err
	}
	m, err := database.ReadUnlockMaterial(cfg.DBPath.Value)
	if err != nil {
		return err
	}
	if forkKept(database.UnlockID(info.Key.Verify), database.UnlockID(m.Verify)) {
		if _, err := fmt.Fprintln(app.Stderr, "The master password was changed elsewhere from one this computer had before, while this computer's moved on to another: the other's is kept on every computer."); err != nil {
			return err
		}
		if err := takeKeyChange(app, cfg, f); err != nil {
			return fmt.Errorf("%w (if no computer of yours made the other change, someone with access to the folder may have, with an old master password: sesh passwd puts this computer's back)", err)
		}
		return nil
	}
	links, err := database.VaultKeyLinks(cfg.DBPath.Value)
	if err != nil {
		return err
	}
	if err := f.WriteInfo(syncfolder.InfoFor(info.FolderID, syncfolder.KeyRecord{Salt: m.Salt, Verify: m.Verify, Params: m.Params}, database.UnionLinks(links, info.Links))); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(app.Stdout, "The master password was changed elsewhere from one this computer had before, while this computer's moved on to another: this computer's is kept, and the other computers ask for it at their next sync."); err != nil {
		return err
	}
	return syncWith(app, cfg)
}

// takeKeyChange is sesh sync for a vault whose sync folder has a master
// password changed on another computer: it asks for this vault's own, then
// the new one, at a terminal, switches the vault to it (the folder's key
// record, so the same key), and syncs, sealing again with the new key the
// folder's files sealed with an older one.
func takeKeyChange(app *App, cfg *config.Config, f syncfolder.Folder) error {
	pc := resolvePasswordPrompt().withKDF(cfg.KDF())
	newCfg := pc
	if pc.fromEnv {
		newCfg = terminalPasswordPrompt()
	}
	if !newCfg.interactive {
		return fmt.Errorf("%w (there's no terminal here to type it at)", errKeyChangedElsewhere)
	}
	if _, err := fmt.Fprintln(app.Stderr, "The master password was changed on another computer. First, this computer's own, the one this vault opens with now:"); err != nil {
		return err
	}
	// Opened with the password typed, not the agent: the old key is kept
	// in the link to the new one, so files sealed with it go on opening.
	src := pc.newSource(cfg.DBPath.Value)
	store, err := openStoreWith(cfg.DBPath.Value, database.NewKeySourceOracle(src))
	if err != nil {
		return fmt.Errorf("%w (forgot this computer's own? sesh recover opens it with the recovery key, and takes the new one)", err)
	}
	defer closeAuditStore(store)
	ownKey, err := src.GetEncryptionKey()
	if err != nil {
		return err
	}
	defer secure.SecureZeroBytes(ownKey)
	key, err := takeKeyChangeWith(app, cfg, f, store, ownKey, newCfg, true)
	secure.SecureZeroBytes(key)
	return err
}

// errNotLatest is a sync folder whose key record its own files outrun:
// one sealed with a key the record's changes don't lead to.
var errNotLatest = errors.New("some of the sync folder's files are sealed with a key its master password record doesn't lead to: it may be an older record put back. If you know a newer master password than the one it asks for, don't type the older: sesh sync on a computer with the newer puts it back")

// takeKeyChangeWith is takeKeyChange with the vault open in store with
// ownKey, its key now, the new password asked with newCfg; keepRecovery
// keeps the recovery key working (a recovery's use removes it). Once the
// vault has switched it returns the new key, which the caller zeroes, even
// when the sync after fails.
func takeKeyChangeWith(app *App, cfg *config.Config, f syncfolder.Folder, store *database.Store, ownKey []byte, newCfg passwordPromptConfig, keepRecovery bool) ([]byte, error) {
	info, err := f.ReadInfo()
	if err != nil {
		return nil, err
	}
	m, err := database.ReadUnlockMaterial(cfg.DBPath.Value)
	if err != nil {
		return nil, err
	}
	ownID := database.UnlockID(m.Verify)
	own, err := store.SyncKeyLinks()
	if err != nil {
		return nil, err
	}
	pending, err := store.SyncKeyChange()
	if err != nil {
		return nil, err
	}
	// The change's first link, from this vault's key (or, settling a fork,
	// one it replaced): its proof, made with that key, is checked before
	// the new password is asked for.
	k, err := folderKeyFrom(cfg.DBPath.Value, info, ownID)
	if err != nil {
		return nil, err
	}
	first, older, err := firstLink(store, info, k == keyFork)
	if err != nil {
		return nil, err
	}
	if first == nil {
		return nil, errKeyForged
	}
	defer older.Close()
	if !proofHolds(store, older, first) {
		return nil, errKeyForged
	}
	// A record the folder's own files outrun may be an older one put
	// back: said, and the password typed decides (one newer than the
	// record's doesn't open it).
	mine := replacedKeys(own)
	mine[ownID] = true
	if notLatest(f, info, mine) {
		if _, err := fmt.Fprintln(app.Stderr, "⚠️  "+errNotLatest.Error()); err != nil {
			return nil, err
		}
	}
	folderRec := database.UnlockMaterial{Salt: info.Key.Salt, Verify: info.Key.Verify, Params: info.Key.Params}
	pw, err := folderPassword(newCfg, "Now the new master password, the one the other computers use: ", folderRec)
	if err != nil {
		return nil, err
	}
	defer secure.SecureZeroBytes(pw)
	key := database.DeriveKey(pw, folderRec.Salt, folderRec.Params)
	defer secure.SecureZeroBytes(key)
	// From the new key back to this vault's, through links each of whose
	// proofs holds with the key it opens to.
	newID := database.UnlockID(folderRec.Verify)
	back := database.NewCheckedOlderKeys(database.KeySealer(key), newID, info.Links)
	defer back.Close()
	if back.Key(first.From) == nil {
		return nil, errKeyForged
	}
	// This vault's own links stay, with one from its key to the new: files
	// it sealed with its key, on a branch the folder's links don't reach,
	// go on opening.
	link, err := database.NewKeyLink(ownKey, key, ownID, newID)
	if err != nil {
		return nil, err
	}
	links := database.UnionLinks(own, back.Used())
	var sum *vaultsync.Summary
	var syncErr error
	_, notes, err := rekeyTo(store, cfg.DBPath.Value, ownID, key, folderRec, keepRecovery, database.RekeyOptions{Sync: database.RekeyAdopt, Links: links, Link: link}, func() string {
		next, err := openWithKey(cfg.DBPath.Value, newID, key)
		if err != nil {
			syncErr = err
			return ""
		}
		defer closeAuditStore(next)
		// The folder gets this vault's links too.
		if fresh, err := f.ReadInfo(); err == nil {
			if mine, err := next.SyncKeyLinks(); err == nil {
				fresh.Links = database.UnionLinks(mine, fresh.Links)
				_ = f.WriteInfo(fresh) //nolint:errcheck // the next sync writes them, should this fail
			}
		}
		sum, syncErr = syncOlder(next, cfg, f)
		return ""
	})
	if err != nil {
		return nil, err
	}
	switched := bytes.Clone(key)
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
		return switched, err
	}
	if syncErr != nil {
		return switched, fmt.Errorf("the sync after switching: %w; sesh sync tries again", syncErr)
	}
	return switched, writeSyncSummary(app, tildePath(f.Dir()), sum)
}

// notLatest says whether the folder f, whose info is info, holds a file
// sealed with a key neither its record's changes lead to nor this vault
// had (mine: its own, which the link it makes leads to): the record is
// older than the file.
func notLatest(f syncfolder.Folder, info *syncfolder.Info, mine map[string]bool) bool {
	c, err := f.Scan()
	if err != nil {
		return false
	}
	ids := map[string]bool{database.UnlockID(info.Key.Verify): true}
	for id := range mine {
		ids[id] = true
	}
	for i := range info.Links {
		ids[info.Links[i].From], ids[info.Links[i].To] = true, true
	}
	return slices.ContainsFunc(c.Files, func(file syncfolder.File) bool { return !ids[file.KeyIDString()] })
}
