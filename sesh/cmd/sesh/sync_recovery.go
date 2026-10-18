package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
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
// is keyID) or an older one (older), and what it is to the vault. One
// sealed with the key whose ID is also (the one a change made here came
// from, while it's sent) is trusted too: until the change, every computer
// took what that key sealed.
func folderRecovery(info *syncfolder.Info, sealer syncfolder.Sealer, keyID, also string, older *database.OlderKeys) (syncfolder.Recovery, folderRecoveryState) {
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
			if sr.Key == also {
				return r, recoveryTrusted
			}
			return r, recoveryOlderKey
		}
	}
	return syncfolder.Recovery{}, recoveryForeign
}

// recoveryOrder is how the folder's recovery key record stands to the one
// the vault saw.
type recoveryOrder int

const (
	recoverySame recoveryOrder = iota
	// recoveryNewer: it replaces the one seen.
	recoveryNewer
	// recoveryOlder: an older one put back, or the one not kept of two
	// sent at once.
	recoveryOlder
)

// compareRecovery says how the folder's record r stands to seen. One seen
// under the key before a change taken from another computer is replaced
// by any other key under the key now. Of two with one count, sent at once,
// the one whose key sorts last is kept on every computer (decided with the
// user), so putting the other back changes nothing.
func compareRecovery(r *syncfolder.Recovery, seen *database.SeenRecovery) recoveryOrder {
	switch {
	case seen.Earlier && bytes.Equal(r.PublicKey, seen.PublicKey), r.Same(&seen.Recovery):
		return recoverySame
	case seen.Earlier, r.Count > seen.Count:
		return recoveryNewer
	case r.Count < seen.Count:
		return recoveryOlder
	case bytes.Compare(r.PublicKey, seen.PublicKey) > 0:
		return recoveryNewer
	}
	return recoveryOlder
}

// syncRecovery syncs the recovery key record of the vault open in store
// with the sync folder f's, once their key records are the same: a change
// in the folder is taken (a change made here the folder didn't keep is
// dropped, and said to be), one made here is sent, and a folder record
// that can't be taken (older, or not sealed with the vault's key now) is
// written over with what the vault saw last, unless that was seen under
// an earlier key and not made here. also is as folderRecovery has it. It
// says what it did (notes) and what's wrong (warnings).
func syncRecovery(store *database.Store, f syncfolder.Folder, older *database.OlderKeys, computer, also string) (notes, warnings []string, err error) {
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
	folder, state := folderRecovery(info, store.SyncSealer(), keyID, also, older)

	if state == recoveryTrusted {
		switch compareRecovery(&folder, &seen) {
		case recoverySame:
			// Seen under an earlier key: now seen under this one.
			if seen.Earlier {
				seen = database.SeenRecovery{Recovery: folder, Mine: seen.Mine}
				if err := store.SyncTakeRecovery(&seen, local, localPub); err != nil {
					return nil, nil, recoveryTakeErr(err)
				}
			}
			switch {
			case pending:
				return sendRecovery(store, f, keyID, local, &seen.Recovery, computer)
			case info.Recovery.Key != keyID:
				// Sealed with the key a change made here came from: sealed
				// again with the key now.
				return nil, nil, writeFolderRecovery(f, store.SyncSealer(), keyID, &folder)
			}
			return nil, nil, nil
		case recoveryNewer:
			// A change made here the folder didn't keep: one not sent, or
			// one sent that the folder's wasn't made after seeing.
			lost := !bytes.Equal(localPub, folder.PublicKey) && (pending || seen.Mine && !folder.Replaces(&seen.Recovery))
			notes, warnings, err = takeRecovery(store, &folder, local, keyID, lost)
			// Sealed with the key a change made here came from: sealed again
			// with the key now.
			if err == nil && info.Recovery.Key != keyID {
				err = writeFolderRecovery(f, store.SyncSealer(), keyID, &folder)
			}
			return notes, warnings, err
		}
	}
	// Taken from the folder under the key before a change taken from
	// another computer, and not confirmed under the key now: not kept, as
	// anyone who knew the old password could have made it. The folder's is
	// taken once it's sealed with the key now.
	if seen.Earlier && !seen.Mine && localPub != nil && !pending {
		aside := seen
		aside.PublicKey = nil
		if err := store.SyncTakeRecovery(&aside, nil, localPub); err != nil {
			return nil, nil, recoveryTakeErr(err)
		}
		return nil, []string{"this computer's recovery key, taken from the sync folder before the master password changed, isn't kept: the folder's record isn't sealed with the new password's key yet (or is damaged), and anyone who knew the old password could have made the one taken. A later sync takes the folder's once it is"}, nil
	}
	if seen.Count == 0 && !pending {
		if state == recoveryForeign || state == recoveryOlderKey {
			warnings = append(warnings, recoveryUntakenSaid(state))
		}
		return nil, warnings, nil
	}
	// Seen under the key before a change taken, and not made here: not
	// this computer's to write under the key now.
	if seen.Earlier && !seen.Mine && !pending {
		if state == recoveryForeign || state == recoveryOlderKey {
			warnings = append(warnings, recoveryUntakenSaid(state))
		}
		return nil, warnings, nil
	}
	switch {
	case state == recoveryTrusted && folder.Count < seen.Count:
		warnings = append(warnings, "the sync folder's recovery key record was an older one, put back: written as it is now")
	case state == recoveryOlderKey, state == recoveryForeign:
		warnings = append(warnings, recoveryUntakenSaid(state)+": written as this computer last saw it")
	}
	if pending {
		notes, _, err = sendRecovery(store, f, keyID, local, &seen.Recovery, computer)
		return notes, warnings, err
	}
	return nil, warnings, writeFolderRecovery(f, store.SyncSealer(), keyID, &seen.Recovery)
}

// recoveryTakeErr is err, from taking a recovery key record, as the sync
// says it: another sesh command changing the vault's meanwhile is left for
// the next sync.
func recoveryTakeErr(err error) error {
	if errors.Is(err, database.ErrRecoveryChanged) {
		return errors.New("this vault's recovery key changed during the sync; the next sync takes the folder's")
	}
	return err
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
func takeRecovery(store *database.Store, folder *syncfolder.Recovery, local *database.RecoveryRecord, keyID string, lost bool) (notes, warnings []string, err error) {
	var localPub []byte
	if local != nil {
		localPub = local.PublicKey
	}
	rec := local
	switch {
	case folder.PublicKey == nil:
		rec = nil
	case !bytes.Equal(localPub, folder.PublicKey):
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
	if err := store.SyncTakeRecovery(&database.SeenRecovery{Recovery: *folder}, rec, localPub); err != nil {
		return nil, nil, recoveryTakeErr(err)
	}
	where := recoveryMadeSaid(folder)
	switch {
	case lost && localPub != nil && folder.PublicKey == nil:
		warnings = append(warnings, fmt.Sprintf("The recovery key made here doesn't work: it was removed on %s before this computer's reached the others, and that's kept on every computer. Make a fresh one with: sesh recovery new", folder.Computer))
	case lost && localPub != nil:
		warnings = append(warnings, fmt.Sprintf("The recovery key made here doesn't work: one made on %s before this computer's reached the others is kept on every computer instead. Throw away the one you wrote down, or make a fresh one with: sesh recovery new", where))
	case lost:
		warnings = append(warnings, fmt.Sprintf("The recovery key was removed here, but one made on %s before the removal reached the others is kept on every computer, and opens this vault. To remove it everywhere: sesh recovery remove", where))
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
func recoveryMadeSaid(r *syncfolder.Recovery) string {
	if r.Made.IsZero() {
		return r.Computer
	}
	return r.Computer + " on " + r.Made.Local().Format("2006-01-02")
}

// sendRecovery writes the vault's recovery key record, local (nil for
// none), to the sync folder f as the change after prior, sealed with the
// vault's key (keyID), and records it as the folder's.
func sendRecovery(store *database.Store, f syncfolder.Folder, keyID string, local *database.RecoveryRecord, prior *syncfolder.Recovery, computer string) (notes, warnings []string, err error) {
	if prior.Count >= syncfolder.MaxRecoveryCount {
		return nil, nil, errors.New("the sync folder's recovery key record has counted as high as it goes")
	}
	r := syncfolder.Recovery{Count: prior.Count + 1, PriorCount: prior.Count, PriorKey: prior.PublicKey, Computer: computer, Made: time.Now().UTC()}
	if local != nil {
		r.PublicKey, r.Made = local.PublicKey, local.CreatedAt
	}
	if err := writeFolderRecovery(f, store.SyncSealer(), keyID, &r); err != nil {
		return nil, nil, err
	}
	if err := store.SyncRecoverySent(&r); err != nil {
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
func writeFolderRecovery(f syncfolder.Folder, sealer syncfolder.Sealer, keyID string, r *syncfolder.Recovery) error {
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
	for _, l := range recoveryLines(cfg, store, changed) {
		w := app.Stdout
		if strings.HasPrefix(l, "⚠️") {
			w = app.Stderr
		}
		fmt.Fprintln(w, l) //nolint:errcheck // best-effort note
	}
}

// recoveryLines is recoveryWithStore's sync, and what it says, line by
// line (warnings marked ⚠️).
func recoveryLines(cfg *config.Config, store *database.Store, changed bool) []string {
	if k, err := folderKeyNow(cfg); err != nil || k != keySame {
		if changed {
			return []string{"The other computers get the recovery key change at this computer's next sesh sync."}
		}
		return []string{"The sync folder's recovery key isn't looked at first now (sesh sync says why): a key made here goes to the other computers at the next sesh sync."}
	}
	older, err := store.SyncOlderKeys()
	if err != nil {
		return []string{fmt.Sprintf("⚠️  The recovery key wasn't synced with the sync folder (%v): sesh sync tries again.", err)}
	}
	defer older.Close()
	notes, warnings, err := syncRecovery(store, syncfolder.New(cfg.SyncDir.Value), older, cfg.SyncComputerName(), "")
	lines := notes
	for _, w := range warnings {
		lines = append(lines, "⚠️  "+w)
	}
	if err != nil {
		lines = append(lines, fmt.Sprintf("⚠️  The recovery key wasn't synced with the sync folder (%v): sesh sync tries again.", err))
	}
	return lines
}

// agentStore is the vault cfg names opened through the agent, when it holds
// the vault's key now, asking for nothing; nil when it doesn't.
func agentStore(cfg *config.Config) *database.Store {
	mat, err := database.ReadUnlockMaterial(cfg.DBPath.Value)
	if err != nil {
		return nil
	}
	conn, err := agent.DialExisting()
	if err != nil {
		return nil
	}
	id := agent.UnlockID(mat.Verify)
	if st, err := agent.Status(conn); err != nil || !st.Unlocked || st.UnlockID != id {
		closeAgentConn(conn)
		return nil
	}
	store, err := openStoreWith(cfg.DBPath.Value, agent.NewOracle(conn, id))
	if err != nil {
		return nil
	}
	return store
}

// recoveryChangeSent syncs a recovery key change just made in the vault
// cfg names with its sync folder, through the agent when it holds the
// vault's key, and says what it did; "" when the vault doesn't sync.
func recoveryChangeSent(cfg *config.Config) string {
	if cfg.SyncDir.Value == "" {
		return ""
	}
	store := agentStore(cfg)
	if store == nil {
		return "It reaches the other computers once this one syncs (sesh sync)."
	}
	defer closeAuditStore(store)
	return strings.Join(recoveryLines(cfg, store, true), " ")
}
