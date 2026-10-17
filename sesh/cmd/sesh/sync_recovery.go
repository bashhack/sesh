package main

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/bashhack/sesh/internal/agent"
	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/keywrap"
	"github.com/bashhack/sesh/internal/recovery"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/syncfolder"
)

// folderRecoveryState is what a sync folder's recovery key record is to a
// vault syncing with it.
type folderRecoveryState int

const (
	// recoveryNone: the folder has none.
	recoveryNone folderRecoveryState = iota
	// recoveryTrusted: sealed with the vault's key now, so made by a
	// computer that has it.
	recoveryTrusted
	// recoveryOlderKey: sealed with a key the vault had before; someone
	// who learned an older master password could have made it, so it's
	// never taken.
	recoveryOlderKey
	// recoveryForeign: it doesn't open with any key the vault has had.
	recoveryForeign
)

// folderRecovery is the recovery key record of the sync folder whose info
// is info, opened with the vault's key now (sealer, whose key record's ID
// is keyID) or an older one (older), and what it is to the vault.
func folderRecovery(info *syncfolder.Info, sealer syncfolder.Sealer, keyID string, older *database.OlderKeys) (syncfolder.Recovery, folderRecoveryState) {
	sr := info.Recovery
	if sr == nil {
		return syncfolder.Recovery{}, recoveryNone
	}
	if sr.Key == keyID {
		if r, err := syncfolder.OpenRecovery(sealer, info.FolderID, sr); err == nil {
			return r, recoveryTrusted
		}
		return syncfolder.Recovery{}, recoveryForeign
	}
	if s := older.Sealer(sr.Key); s != nil {
		if r, err := syncfolder.OpenRecovery(s, info.FolderID, sr); err == nil {
			return r, recoveryOlderKey
		}
	}
	return syncfolder.Recovery{}, recoveryForeign
}

// syncRecovery syncs the recovery key record of the vault open in store
// with the sync folder f's, once their key records are the same: a change
// in the folder is taken (a change made here and not sent yet is dropped,
// the first in the folder kept), one made here is sent, and a folder
// record that can't be taken (older, or not sealed with the vault's key
// now) is written over with what the vault saw last. It says what it did
// (notes) and what's wrong (warnings).
func syncRecovery(store *database.Store, f syncfolder.Folder, older *database.OlderKeys, computer string) (notes, warnings []string, err error) {
	info, err := f.ReadInfo()
	if err != nil {
		return nil, nil, err
	}
	keyID, err := store.SyncKeyID()
	if err != nil || database.UnlockID(info.Key.Verify) != keyID {
		return nil, nil, err
	}
	// What the vault saw is of the folder it syncs with: another is met
	// at a whole sync first.
	if id, err := store.SyncFolderID(); err != nil || id != info.FolderID {
		return nil, nil, err
	}
	seen, err := store.SyncRecovery()
	if err != nil {
		return nil, nil, err
	}
	local, err := store.Recovery()
	switch {
	case errors.Is(err, database.ErrNoRecovery):
		local = nil
	case err != nil:
		return nil, nil, err
	}
	var localPub []byte
	if local != nil {
		localPub = local.PublicKey
	}
	pending := !bytes.Equal(localPub, seen.PublicKey)
	folder, state := folderRecovery(info, store.SyncSealer(), keyID, older)

	if state == recoveryTrusted && (folder.Count > seen.Count || folder.Count == seen.Count && !folder.Same(seen)) {
		// This computer's own, sent, lost to another sent at once (the sync
		// tool kept the other's): as good as not sent.
		lost := pending || folder.Count == seen.Count && seen.Computer == computer
		return takeRecovery(store, folder, local, keyID, lost)
	}
	// The record the vault saw: a change made here is sent; one sealed
	// with an earlier key (the master password changed since) is sealed
	// again with the key now.
	if (state == recoveryTrusted || state == recoveryOlderKey) && folder.Same(seen) {
		switch {
		case pending:
			return sendRecovery(store, f, keyID, local, seen.Count+1, computer)
		case state == recoveryOlderKey:
			return nil, nil, writeFolderRecovery(f, store.SyncSealer(), keyID, seen)
		}
		return nil, nil, nil
	}
	if seen.Count == 0 && !pending {
		if state == recoveryForeign || state == recoveryOlderKey {
			warnings = append(warnings, recoveryUntakenSaid(state))
		}
		return nil, warnings, nil
	}
	switch state {
	case recoveryTrusted:
		warnings = append(warnings, "the sync folder's recovery key record was an older one, put back: written as it is now")
	case recoveryOlderKey, recoveryForeign:
		warnings = append(warnings, recoveryUntakenSaid(state)+": written as this computer last saw it")
	}
	if pending {
		notes, _, err = sendRecovery(store, f, keyID, local, seen.Count+1, computer)
		return notes, warnings, err
	}
	return nil, warnings, writeFolderRecovery(f, store.SyncSealer(), keyID, seen)
}

// recoveryUntakenSaid says why a folder's recovery key record in state
// isn't taken.
func recoveryUntakenSaid(state folderRecoveryState) string {
	if state == recoveryOlderKey {
		return "the sync folder's recovery key record is sealed with the key of an earlier master password, so it isn't taken (anyone who knew that password could have made it)"
	}
	return "the sync folder's recovery key record doesn't open with this vault's key (damaged, or not made by one of your computers), so it isn't taken"
}

// takeRecovery makes folder, the sync folder's recovery key record, the
// vault's: its public key, wrapped to here with the vault's key (keyID),
// or none. local is the vault's record before, and lost says it's a
// change made here the folder didn't keep, which is dropped.
func takeRecovery(store *database.Store, folder syncfolder.Recovery, local *database.RecoveryRecord, keyID string, lost bool) (notes, warnings []string, err error) {
	var localPub []byte
	if local != nil {
		localPub = local.PublicKey
	}
	rec := local
	switch {
	case folder.PublicKey == nil:
		rec = nil
	case !bytes.Equal(localPub, folder.PublicKey):
		if err := recovery.CheckPublicKey(folder.PublicKey); err != nil {
			return nil, nil, fmt.Errorf("the sync folder's recovery key: %w", err)
		}
		wrap := storeWrap(store)
		if wrap == nil {
			return nil, nil, errors.New("this vault's key can't be wrapped to the sync folder's recovery key here")
		}
		w, err := wrap(keyID, folder.PublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("wrap the vault key for the sync folder's recovery key: %w", err)
		}
		rec = recovery.NewRecord(keyID, folder.PublicKey, w)
		rec.CreatedAt = folder.Made
	}
	if err := store.SyncTakeRecovery(folder, rec, localPub); err != nil {
		if errors.Is(err, database.ErrRecoveryChanged) {
			return nil, nil, nil // the next sync looks again
		}
		return nil, nil, err
	}
	where := recoveryMadeSaid(folder)
	switch {
	case lost && localPub != nil:
		if folder.PublicKey == nil {
			warnings = append(warnings, fmt.Sprintf("The recovery key made here doesn't work: the recovery key was removed on %s, and that reached the sync folder first, so it's kept on every computer. Make a fresh one with: sesh recovery new", folder.Computer))
		} else {
			warnings = append(warnings, fmt.Sprintf("The recovery key made here doesn't work: one made on %s reached the sync folder first and opens this vault on every computer. Throw away the one you wrote down, or make a fresh one with: sesh recovery new", where))
		}
	case lost && folder.PublicKey != nil:
		warnings = append(warnings, fmt.Sprintf("The recovery key was removed here, but one made on %s reached the sync folder first: it opens this vault on every computer. To remove it everywhere: sesh recovery remove", where))
	case folder.PublicKey == nil && localPub != nil:
		notes = append(notes, fmt.Sprintf("The recovery key was removed on %s: it no longer opens this vault here either.", folder.Computer))
	case folder.PublicKey != nil && localPub == nil:
		notes = append(notes, fmt.Sprintf("The recovery key made on %s now opens this vault here too.", where))
	case folder.PublicKey != nil && !bytes.Equal(localPub, folder.PublicKey):
		notes = append(notes, fmt.Sprintf("The recovery key made on %s now opens this vault here too; the one before it no longer does.", where))
	}
	return notes, warnings, nil
}

// recoveryMadeSaid is where and when r's key was made, as a note says it.
func recoveryMadeSaid(r syncfolder.Recovery) string {
	if r.Made.IsZero() {
		return r.Computer
	}
	return r.Computer + " on " + r.Made.Local().Format("2006-01-02")
}

// sendRecovery writes the vault's recovery key record, local (nil for
// none), to the sync folder f as its change count, sealed with the vault's
// key (keyID), and records it as the folder's.
func sendRecovery(store *database.Store, f syncfolder.Folder, keyID string, local *database.RecoveryRecord, count uint64, computer string) (notes, warnings []string, err error) {
	r := syncfolder.Recovery{Count: count, Computer: computer, Made: time.Now().UTC()}
	if local != nil {
		r.PublicKey, r.Made = local.PublicKey, local.CreatedAt
	}
	if err := writeFolderRecovery(f, store.SyncSealer(), keyID, r); err != nil {
		return nil, nil, err
	}
	if err := store.SyncRecoverySent(r); err != nil {
		return nil, nil, err
	}
	if local == nil {
		return []string{"The recovery key's removal goes to the other computers: it stops opening the vault on each at its next sync."}, nil, nil
	}
	return []string{"This computer's recovery key goes to the other computers: it opens the vault on each after its next sync."}, nil, nil
}

// writeFolderRecovery writes r as the sync folder f's recovery key record,
// sealed with sealer, the key of the key record keyID, unless the folder's
// key record is another now.
func writeFolderRecovery(f syncfolder.Folder, sealer syncfolder.Sealer, keyID string, r syncfolder.Recovery) error {
	info, err := f.ReadInfo()
	if err != nil {
		return err
	}
	if database.UnlockID(info.Key.Verify) != keyID {
		return errors.New("the sync folder's master password changed meanwhile")
	}
	sr, err := syncfolder.SealRecovery(sealer, info.FolderID, keyID, r)
	if err != nil {
		return err
	}
	info.Recovery = sr
	return f.WriteInfo(info)
}

// storeWrap wraps the key of the vault open in store to a recovery key's
// public key: through the agent, when it holds the key, or with the key
// the store was opened with. nil when neither can.
func storeWrap(store *database.Store) wrapFunc {
	switch o := store.SyncSealer().(type) {
	case *agent.Oracle:
		return func(_ string, pub []byte) (keywrap.Wrapped, error) {
			return o.WrapKey(agent.WrapForRecovery, pub)
		}
	case interface {
		WithKey(func([]byte) error) error
	}:
		return func(id string, pub []byte) (keywrap.Wrapped, error) {
			var w keywrap.Wrapped
			err := o.WithKey(func(key []byte) error {
				var err error
				w, err = recovery.Wrap(pub, key, []byte(id))
				return err
			})
			return w, err
		}
	}
	return nil
}

// recoveryWithFolder syncs the recovery key record of the vault cfg names
// with its sync folder now, outside a whole sync: unlocking it through the
// agent, as p asks, then as recoveryWithStore does.
func recoveryWithFolder(app *App, cfg *config.Config, p passwordPromptConfig, changed bool) error {
	oracle, typed, err := keySourceFromAgent(cfg.DBPath.Value, p)
	secure.SecureZeroBytes(typed)
	if err != nil {
		return err
	}
	if oracle == nil {
		return errors.New("syncing the recovery key needs the sesh agent, which isn't available (see the warning above)")
	}
	store, err := openStoreWith(cfg.DBPath.Value, oracle)
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	recoveryWithStore(app, cfg, store, changed)
	return nil
}

// recoveryWithStore syncs the recovery key record of the vault open in
// store with the sync folder cfg names, once the vault syncs with it under
// the same master password, and says what it did; what fails is said, and
// left for the next sync. changed says the vault's record just changed,
// so a sync left for later is said to be.
func recoveryWithStore(app *App, cfg *config.Config, store *database.Store, changed bool) {
	if k, err := folderKeyNow(cfg); err != nil || k != keySame {
		if changed {
			fmt.Fprintln(app.Stderr, "The other computers get the recovery key change at this computer's next sesh sync.") //nolint:errcheck // best-effort note
		}
		return
	}
	older, err := store.SyncOlderKeys()
	if err == nil {
		defer older.Close()
		var notes, warnings []string
		notes, warnings, err = syncRecovery(store, syncfolder.New(cfg.SyncDir.Value), older, cfg.SyncComputerName())
		for _, n := range notes {
			fmt.Fprintln(app.Stdout, n) //nolint:errcheck // best-effort note
		}
		for _, w := range warnings {
			fmt.Fprintln(app.Stderr, "⚠️  "+w) //nolint:errcheck // best-effort warning
		}
	}
	if err != nil {
		fmt.Fprintf(app.Stderr, "⚠️  The recovery key wasn't synced with the sync folder (%v): sesh sync tries again.\n", err) //nolint:errcheck // best-effort warning
	}
}
