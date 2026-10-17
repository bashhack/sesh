package database

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/shell"
	"github.com/bashhack/sesh/internal/syncfolder"
	"github.com/bashhack/sesh/internal/vault"
)

// ErrVaultKeyChanged means the vault's master password was changed after
// this command unlocked it: its key no longer opens the vault.
var ErrVaultKeyChanged = errors.New("the vault's master password was changed by another sesh command while this one ran; run this again")

// querier is a *sql.DB or a *sql.Tx.
type querier interface {
	QueryRow(query string, args ...any) *sql.Row
}

// unlockedID is the id of the key record the store's key was checked
// against, or "" when its key source can't say (a bare key, in tests).
func (s *Store) unlockedID() (string, error) {
	o, ok := s.oracle.(interface{ UnlockID() (string, error) })
	if !ok {
		return "", nil
	}
	return o.UnlockID()
}

// keyUnchanged returns ErrVaultKeyChanged unless the vault's key record,
// read through q, is the one the store's key was checked against.
func (s *Store) keyUnchanged(q querier) error {
	id, err := s.unlockedID()
	if err != nil || id == "" {
		return err
	}
	var verify []byte
	if err := q.QueryRow(`SELECT verify FROM vault_key WHERE id = 1`).Scan(&verify); err != nil {
		return fmt.Errorf("read the vault's key record: %w", err)
	}
	if UnlockID(verify) != id {
		return ErrVaultKeyChanged
	}
	return nil
}

// quietly runs f in tx with quiet_writes set, so what it writes doesn't
// count as changes to the entries (their rev stays): for writes that
// change how entries are kept, not what they hold.
func quietly(tx *sql.Tx, f func() error) error {
	if _, err := tx.Exec(`INSERT INTO quiet_writes (id) VALUES (1)`); err != nil {
		return err
	}
	if err := f(); err != nil {
		return err
	}
	_, err := tx.Exec(`DELETE FROM quiet_writes`)
	return err
}

// inTx runs f in a write transaction that first checks the vault's key is
// still the one the store's key was checked against, so nothing is written
// under a key a password change has replaced.
func (s *Store) inTx(f func(tx *sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if err := s.keyUnchanged(tx); err != nil {
		_ = tx.Rollback() //nolint:errcheck // already failing
		return err
	}
	if err := f(tx); err != nil {
		_ = tx.Rollback() //nolint:errcheck // already failing
		return err
	}
	return tx.Commit()
}

// RecoveryOutcome is what a password change did with the vault's recovery
// key record.
type RecoveryOutcome int

// The outcomes.
const (
	// RecoveryNone: the vault had no recovery key record.
	RecoveryNone RecoveryOutcome = iota
	// RecoveryKept: the record was re-wrapped to the new key.
	RecoveryKept
	// RecoveryRemoved: the record was removed, as a recovery asks.
	RecoveryRemoved
	// RecoveryStale: the record was for another vault, so it was removed.
	RecoveryStale
)

// RekeySync is what a password change means for syncing.
type RekeySync int

// The meanings.
const (
	// RekeyLocal: nothing to sync (the vault doesn't sync now).
	RekeyLocal RekeySync = iota
	// RekeySend: a change made here, for the sync folder to take: the key
	// record the vault had, the folder's, is kept until it's sent.
	RekeySend
	// RekeyAdopt: the vault takes the sync folder's key record, changed on
	// another computer; any change of its own not sent is dropped.
	RekeyAdopt
)

// RekeyOptions are what a password change does beyond re-encrypting.
type RekeyOptions struct {
	// Link is the change as a key link (NewKeyLink), kept with the vault's
	// others; nil when there's none to keep.
	Link *syncfolder.KeyLink
	// Links, with Sync RekeyAdopt, are the sync folder's links, which the
	// vault takes in place of its own.
	Links []syncfolder.KeyLink
	Sync  RekeySync
}

// RekeyResult reports a password change.
type RekeyResult struct {
	// NewID is the id of the vault's new key record.
	NewID string
	// Entries is how many entries were re-encrypted; Trashed, how many in
	// the trash.
	Entries, Trashed int
	Recovery         RecoveryOutcome
	// OldVaultInFile means another sesh command had the vault open, so the
	// change couldn't be folded into the vault file yet: until that command
	// ends, the file on its own still holds the vault under the old key.
	OldVaultInFile bool
}

// Rekey re-encrypts the vault in place under newKey, whose key record is
// rec, in one transaction: every entry's secret and details, the key record, and the recovery
// key record, which rewrap re-wraps to the new key. The recovery key record
// is removed instead when rewrap is nil (a recovery, whose key has been
// used) or when it was made for another vault. Nothing changes unless all
// of it does, and the audit log is kept, with one event for the change.
//
// The slow part, re-encrypting each entry, happens before the transaction,
// so other sesh commands wait for it only briefly; an entry saved in the
// meantime is re-encrypted inside it.
//
// It refuses with ErrVaultKeyChanged when the vault's key isn't the one the
// store's key was checked against. Afterwards the store's key no longer
// opens the vault, so the caller closes it.
//
// opts says what it means for syncing, and the key links kept.
func (s *Store) Rekey(newKey []byte, rec UnlockMaterial, rewrap func(r *RecoveryRecord, newID string) (*RecoveryRecord, error), opts RekeyOptions) (RekeyResult, error) {
	res := RekeyResult{NewID: UnlockID(rec.Verify)}
	oldID, err := s.unlockedID()
	if err != nil {
		return res, err
	}
	if oldID == "" {
		return res, errors.New("change the master password: the key source doesn't say which vault it unlocked")
	}
	// The entries, and those in the trash, are re-encrypted ahead, outside
	// the transaction, then checked in it for any changed meanwhile.
	type row struct {
		table string
		id    int64
	}
	sealed := map[row]sealedEntry{}
	for _, table := range sealedTables {
		before, err := sealedEntries(s.db, table)
		if err != nil {
			return res, err
		}
		for i := range before {
			e := &before[i]
			if err := s.reseal(s.db, e, newKey); err != nil {
				return res, err
			}
			sealed[row{table, e.id}] = *e
		}
	}
	bases, err := s.resealBases(s.db, newKey, res.NewID, nil)
	if err != nil {
		return res, err
	}
	err = s.inTx(func(tx *sql.Tx) error {
		return quietly(tx, func() error {
			if _, err := s.resealBases(tx, newKey, res.NewID, bases); err != nil {
				return err
			}
			for _, table := range sealedTables {
				now, err := sealedEntries(tx, table)
				if err != nil {
					return err
				}
				for i := range now {
					e := &now[i]
					// An entry unchanged since it was re-encrypted ahead takes
					// that; one saved since is re-encrypted now.
					if done, ok := sealed[row{table, e.id}]; ok && done.unchangedFrom(e) {
						*e = done
					} else if err := s.reseal(tx, e, newKey); err != nil {
						return err
					}
					q, args := `UPDATE `+table+` SET encrypted_data = ?, salt = ?, sealed_details = ?, details_salt = ? WHERE id = ?`, []any{e.data, e.salt, e.details, e.detailsSalt, e.id} //nolint:gosec // table is one of sealedTables
					if table == "history" {
						q, args = `UPDATE history SET encrypted_data = ?, salt = ? WHERE id = ?`, []any{e.data, e.salt, e.id}
					}
					if _, err := tx.Exec(q, args...); err != nil {
						return fmt.Errorf("store %s: %w", e.k, err)
					}
				}
				switch table {
				case "trash":
					res.Trashed = len(now)
				case "entries":
					res.Entries = len(now)
				}
			}
			if res.Recovery, err = rewrapRecoveryRecord(tx, oldID, res.NewID, rewrap); err != nil {
				return err
			}
			if _, err := tx.Exec(`UPDATE vault_key SET salt = ?, kdf = ?, kdf_params = ?, verify = ? WHERE id = 1`,
				rec.Salt, kdfArgon2id, rec.Params.MarshalParams(), rec.Verify); err != nil {
				return fmt.Errorf("record the new key: %w", err)
			}
			if opts.Sync == RekeyAdopt {
				if _, err := tx.Exec(`DELETE FROM key_links`); err != nil {
					return err
				}
				for i := range opts.Links {
					if err := putKeyLink(tx, &opts.Links[i]); err != nil {
						return err
					}
				}
			}
			if opts.Link != nil {
				if err := putKeyLink(tx, opts.Link); err != nil {
					return err
				}
			}
			switch opts.Sync {
			case RekeySend:
				// The first change not sent keeps the key the folder has.
				if _, err := tx.Exec(`UPDATE sync_info SET prev_key_id = ? WHERE id = 1 AND prev_key_id = ''`, oldID); err != nil {
					return err
				}
			case RekeyAdopt:
				if _, err := tx.Exec(`UPDATE sync_info SET prev_key_id = ''`); err != nil {
					return err
				}
			}
			entries := fmt.Sprintf("%d entries", res.Entries)
			if res.Entries == 1 {
				entries = "1 entry"
			}
			if res.Trashed > 0 {
				entries += fmt.Sprintf(" and %d in the trash", res.Trashed)
			}
			if _, err := tx.Exec(`INSERT INTO audit_log (event_type, entry_id, detail, created_at) VALUES ('rekey', NULL, ?, ?)`,
				"master password changed, "+entries+" re-encrypted", time.Now().UTC()); err != nil {
				return fmt.Errorf("log the change: %w", err)
			}
			return nil
		})
	})
	if err != nil {
		return res, fmt.Errorf("change the master password: %w", err)
	}
	// Fold the change into the vault file now, so a copy of the file alone
	// isn't the old vault. Another command with the vault open can hold
	// this off; the change is committed either way.
	var busy, logFrames, checkpointed int
	if err := s.db.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &checkpointed); err != nil || busy != 0 {
		res.OldVaultInFile = true
	}
	return res, nil
}

// sealedEntry is an entry's encrypted secret and details: as stored
// (data, salt, details, detailsSalt), and as stored before resealing (the
// old ones).
type sealedEntry struct {
	k                          vault.Key
	data, salt                 []byte
	details, detailsSalt       []byte
	oldData, oldSalt           []byte
	oldDetails, oldDetailsSalt []byte
	id                         int64
	// trashID is the entry's id in the trash, 0 for one that isn't.
	trashID int64
	// history is an earlier secret of an entry's, sealed with historyAAD;
	// version is its number, as sesh history lists it.
	history bool
	version int
}

// unchangedFrom reports whether now, as stored, is what e was resealed
// from.
func (e *sealedEntry) unchangedFrom(now *sealedEntry) bool {
	return e.k == now.k && bytes.Equal(e.oldData, now.data) && bytes.Equal(e.oldSalt, now.salt) &&
		bytes.Equal(e.oldDetails, now.details) && bytes.Equal(e.oldDetailsSalt, now.detailsSalt)
}

// sealedTables are the tables holding secrets sealed with the vault's
// key: the entries, the trash's, and their earlier secrets.
var sealedTables = []string{"entries", "trash", "history"}

// sealedEntries reads the encrypted secret and details of every entry in
// table, one of sealedTables, through q.
func sealedEntries(q interface {
	Query(query string, args ...any) (*sql.Rows, error)
}, table string) (_ []sealedEntry, err error) {
	// An earlier secret has no details; its version (as sesh history
	// numbers it) and its entry's trash id go in errors instead.
	extra := `sealed_details, details_salt, 0, 0`
	if table == "history" {
		extra = `NULL, NULL, COALESCE(trash_id, 0), ROW_NUMBER() OVER (PARTITION BY kind, service, username, trash_id ORDER BY id DESC) + 1`
	}
	rows, err := q.Query(`SELECT id, kind, service, username, encrypted_data, salt, ` + extra + ` FROM ` + table) //nolint:gosec // table is one of sealedTables
	if err != nil {
		return nil, fmt.Errorf("read entries: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("read entries: %w", cerr)
		}
	}()
	var all []sealedEntry
	for rows.Next() {
		var e sealedEntry
		var kind string
		var ofTrash, version int64
		if err := rows.Scan(&e.id, &kind, &e.k.Service, &e.k.Username, &e.data, &e.salt, &e.details, &e.detailsSalt, &ofTrash, &version); err != nil {
			return nil, fmt.Errorf("read entries: %w", err)
		}
		e.k.Kind = vault.Kind(kind)
		switch table {
		case "trash":
			e.trashID = e.id
		case "history":
			e.history, e.version = true, int(version)
			e.trashID = ofTrash
		}
		e.oldData, e.oldSalt = e.data, e.salt
		e.oldDetails, e.oldDetailsSalt = e.details, e.detailsSalt
		all = append(all, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read entries: %w", err)
	}
	return all, nil
}

// reseal decrypts e's secret and details with the store's key and
// encrypts them under newKey, into e. q is what the vault is read through:
// the transaction, inside one, since the store has a single connection.
func (s *Store) reseal(q querier, e *sealedEntry, newKey []byte) (err error) {
	defer func() {
		// Not when the master password changed meanwhile: then the entry
		// is fine, and the advice is to run it again.
		if err == nil || errors.Is(err, ErrVaultKeyChanged) {
			return
		}
		id := shell.Quote(e.k.String())
		switch {
		case e.history && e.trashID != 0:
			err = fmt.Errorf("%w (version %d of an entry in the trash, id %d: restore it with sesh trash restore %d, then sesh history %s --forget %d)", err, e.version, e.trashID, e.trashID, id, e.version)
		case e.history:
			err = fmt.Errorf("%w (version %d: sesh history %s --forget %d forgets it)", err, e.version, id, e.version)
		case e.trashID != 0:
			err = fmt.Errorf("%w (it's in the trash, id %d: sesh trash remove %d deletes it for good)", err, e.trashID, e.trashID)
		}
	}()
	aad, what := entryAAD(e.k), ""
	if e.history {
		aad, what = historyAAD(e.k), "an earlier secret of "
	}
	if e.data, e.salt, err = s.resealOne(q, e.k, e.oldData, e.oldSalt, aad, newKey, what); err != nil {
		return err
	}
	if e.oldDetails != nil {
		if e.details, e.detailsSalt, err = s.resealOne(q, e.k, e.oldDetails, e.oldDetailsSalt, detailsAAD(e.k), newKey, "the details of "); err != nil {
			return err
		}
	}
	return nil
}

// resealOne decrypts one sealed value of k's, what in errors, with the
// store's key and encrypts it under newKey.
func (s *Store) resealOne(q querier, k vault.Key, data, salt, aad, newKey []byte, what string) (newData, newSalt []byte, err error) {
	plain, err := s.oracle.DecryptEntry(data, salt, aad)
	if err != nil {
		if kerr := s.keyUnchanged(q); errors.Is(kerr, ErrVaultKeyChanged) {
			err = kerr
		}
		return nil, nil, fmt.Errorf("decrypt %s%s: %w", what, k, err)
	}
	defer secure.SecureZeroBytes(plain)
	if newData, newSalt, err = EncryptEntry(newKey, plain, aad); err != nil {
		return nil, nil, fmt.Errorf("encrypt %s%s: %w", what, k, err)
	}
	return newData, newSalt, nil
}

// rewrapRecoveryRecord re-wraps the recovery key record in tx from the key
// record oldID to newID with rewrap, or removes it (see Rekey).
func rewrapRecoveryRecord(tx *sql.Tx, oldID, newID string, rewrap func(*RecoveryRecord, string) (*RecoveryRecord, error)) (RecoveryOutcome, error) {
	r, err := scanRecovery(tx)
	if errors.Is(err, ErrNoRecovery) {
		return RecoveryNone, nil
	}
	if err != nil {
		return RecoveryNone, err
	}
	outcome := RecoveryKept
	switch {
	case r.UnlockID != oldID:
		outcome = RecoveryStale
	case rewrap == nil:
		outcome = RecoveryRemoved
	}
	if outcome != RecoveryKept {
		if _, err := tx.Exec(`DELETE FROM recovery`); err != nil {
			return outcome, fmt.Errorf("remove the recovery key record: %w", err)
		}
		return outcome, nil
	}
	nr, err := rewrap(r, newID)
	if err != nil {
		return outcome, fmt.Errorf("keep the recovery key: %w", err)
	}
	if err := putRecovery(tx, nr); err != nil {
		return outcome, err
	}
	return outcome, nil
}

// keySealer seals with a key held here: the new one, as the vault changes
// to it.
type keySealer []byte

func (k keySealer) EncryptEntry(plaintext, aad []byte) ([]byte, []byte, error) {
	return EncryptEntry(k, plaintext, aad)
}

func (k keySealer) DecryptEntry(data, salt, aad []byte) ([]byte, error) {
	return DecryptEntry(k, data, salt, aad)
}

// resealedBase is an agreed sync version sealed again: its sealed bytes
// before and after.
type resealedBase struct{ from, to []byte }

// resealBases seals each version this computer agreed with the sync folder
// (sync_state) again for newKey, whose key record is newID, as sync files
// are sealed. done, when not nil, are those sealed again before, taken as
// they are if unchanged since; in a transaction (tx), the rows are
// updated.
func (s *Store) resealBases(q interface {
	Query(query string, args ...any) (*sql.Rows, error)
}, newKey []byte, newID string, done map[string]resealedBase) (map[string]resealedBase, error) {
	rows, err := q.Query(`SELECT uid, base FROM sync_state`)
	if err != nil {
		return nil, fmt.Errorf("read what was synced: %w", err)
	}
	now := map[string][]byte{}
	for rows.Next() {
		var uid string
		var base []byte
		if err := rows.Scan(&uid, &base); err != nil {
			_ = rows.Close() //nolint:errcheck // already failing
			return nil, err
		}
		now[uid] = base
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("read what was synced: %w", err)
	}
	out := map[string]resealedBase{}
	for uid, base := range now {
		if d, ok := done[uid]; ok && bytes.Equal(d.from, base) {
			out[uid] = d
			continue
		}
		h, rec, err := syncfolder.Open(s.oracle, base)
		if err != nil {
			// Damaged, or sealed with another key (a backup restored):
			// dropped, so the entry merges as never synced.
			out[uid] = resealedBase{from: base}
			continue
		}
		nh, err := syncfolder.NewHeader(h.UIDString(), newID)
		if err != nil {
			rec.Wipe()
			return nil, err
		}
		to, err := syncfolder.Seal(keySealer(newKey), nh, rec)
		rec.Wipe()
		if err != nil {
			return nil, fmt.Errorf("seal what %s was synced at: %w", uid, err)
		}
		out[uid] = resealedBase{from: base, to: to}
	}
	if tx, ok := q.(*sql.Tx); ok {
		for uid, b := range out {
			q, args := `UPDATE sync_state SET base = ? WHERE uid = ?`, []any{b.to, uid}
			if b.to == nil {
				q, args = `DELETE FROM sync_state WHERE uid = ?`, []any{uid}
			}
			if _, err := tx.Exec(q, args...); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// linkAAD and proofAAD bind a key link's two sealed values to both its key
// records' IDs, and to which of the two each is.
func linkAAD(from, to string) []byte  { return []byte("sesh-key-link-v1\x00" + from + "\x00" + to) }
func proofAAD(from, to string) []byte { return []byte("sesh-key-proof-v1\x00" + from + "\x00" + to) }

// NewKeyLink is the master password change from oldKey, whose key record's
// ID is from, to newKey, whose is to.
func NewKeyLink(oldKey, newKey []byte, from, to string) (*syncfolder.KeyLink, error) {
	k, ks, err := EncryptEntry(newKey, oldKey, linkAAD(from, to))
	if err != nil {
		return nil, err
	}
	p, ps, err := EncryptEntry(oldKey, []byte(to), proofAAD(from, to))
	if err != nil {
		return nil, err
	}
	return &syncfolder.KeyLink{From: from, To: to, Key: k, KeySalt: ks, Proof: p, ProofSalt: ps}, nil
}

// LinkProofHolds says whether l's proof opens with old, the sealer of the
// key l comes from: whether the change was made by a computer that had it.
func LinkProofHolds(old syncfolder.Sealer, l *syncfolder.KeyLink) bool {
	to, err := old.DecryptEntry(l.Proof, l.ProofSalt, proofAAD(l.From, l.To))
	if err != nil {
		return false
	}
	defer secure.SecureZeroBytes(to)
	return string(to) == l.To
}

// OpenKeyLink is the old key l holds, opened with sealer, the new key's.
// The caller zeroes it.
func OpenKeyLink(sealer syncfolder.Sealer, l *syncfolder.KeyLink) ([]byte, error) {
	return sealer.DecryptEntry(l.Key, l.KeySalt, linkAAD(l.From, l.To))
}

// KeySealer seals with key, held here.
func KeySealer(key []byte) syncfolder.Sealer { return keySealer(key) }

func putKeyLink(tx *sql.Tx, l *syncfolder.KeyLink) error {
	_, err := tx.Exec(`INSERT OR REPLACE INTO key_links (from_id, to_id, key, key_salt, proof, proof_salt) VALUES (?, ?, ?, ?, ?, ?)`,
		l.From, l.To, l.Key, l.KeySalt, l.Proof, l.ProofSalt)
	if err != nil {
		return fmt.Errorf("keep the master password change: %w", err)
	}
	return nil
}

// keyLinks reads the vault's key links through q, oldest first.
func keyLinks(q interface {
	Query(query string, args ...any) (*sql.Rows, error)
}) (_ []syncfolder.KeyLink, err error) {
	rows, err := q.Query(`SELECT from_id, to_id, key, key_salt, proof, proof_salt FROM key_links ORDER BY rowid`)
	if err != nil {
		return nil, fmt.Errorf("read the master password changes: %w", err)
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	var out []syncfolder.KeyLink
	for rows.Next() {
		var l syncfolder.KeyLink
		if err := rows.Scan(&l.From, &l.To, &l.Key, &l.KeySalt, &l.Proof, &l.ProofSalt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// SyncKeyLinks are the vault's master password changes, oldest first.
func (s *Store) SyncKeyLinks() ([]syncfolder.KeyLink, error) { return keyLinks(s.db) }

// VaultKeyLinks are the master password changes of the vault at dbPath,
// read without unlocking it; none when there's no vault.
func VaultKeyLinks(dbPath string) (_ []syncfolder.KeyLink, err error) {
	db, err := openExisting(dbPath)
	if errors.Is(err, ErrNoVault) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { err = closeVault(db, err) }()
	return keyLinks(db)
}

// OlderKeys are the keys a vault had before master password changes,
// reached through key links from a key whose sealer it has: every link
// whose new key is reached opens to its old one, whatever order or branch
// the changes came in. Opened when first asked for, and zeroed by Close.
type OlderKeys struct {
	start   syncfolder.Sealer
	keys    map[string][]byte
	startID string
	links   []syncfolder.KeyLink
	checked bool
	walked  bool
}

// NewOlderKeys are the keys reached back through links from the key record
// whose ID is id, which sealer opens with.
func NewOlderKeys(sealer syncfolder.Sealer, id string, links []syncfolder.KeyLink) *OlderKeys {
	return &OlderKeys{start: sealer, startID: id, links: links, keys: map[string][]byte{}}
}

// NewCheckedOlderKeys are NewOlderKeys taking only links whose proof holds
// with the key they open to: for links read from a sync folder, so each key
// reached is one a change was made from.
func NewCheckedOlderKeys(sealer syncfolder.Sealer, id string, links []syncfolder.KeyLink) *OlderKeys {
	o := NewOlderKeys(sealer, id, links)
	o.checked = true
	return o
}

func (o *OlderKeys) sealer(id string) syncfolder.Sealer {
	if id == o.startID {
		return o.start
	}
	if k, ok := o.keys[id]; ok {
		return keySealer(k)
	}
	return nil
}

func (o *OlderKeys) walk() {
	if o.walked {
		return
	}
	o.walked = true
	for more := true; more; {
		more = false
		for i := range o.links {
			l := &o.links[i]
			if _, done := o.keys[l.From]; done || l.From == o.startID {
				continue
			}
			s := o.sealer(l.To)
			if s == nil {
				continue
			}
			k, err := OpenKeyLink(s, l)
			if err != nil {
				continue
			}
			if o.checked && !LinkProofHolds(keySealer(k), l) {
				secure.SecureZeroBytes(k)
				continue
			}
			o.keys[l.From] = k
			more = true
		}
	}
}

// Key is the older key whose key record's ID is id, nil when it isn't
// reached. It's zeroed by Close.
func (o *OlderKeys) Key(id string) []byte {
	if o == nil {
		return nil
	}
	o.walk()
	return o.keys[id]
}

// Sealer is a sealer for the older key whose key record's ID is id, nil
// when it isn't reached.
func (o *OlderKeys) Sealer(id string) syncfolder.Sealer {
	if k := o.Key(id); k != nil {
		return keySealer(k)
	}
	return nil
}

// Close zeroes the keys opened.
func (o *OlderKeys) Close() {
	if o == nil {
		return
	}
	for _, k := range o.keys {
		secure.SecureZeroBytes(k)
	}
}

// UnionLinks are the links of a and b, each once (by the two key records
// it joins), a's first.
func UnionLinks(a, b []syncfolder.KeyLink) []syncfolder.KeyLink {
	seen := map[[2]string]bool{}
	var out []syncfolder.KeyLink
	for _, ls := range [][]syncfolder.KeyLink{a, b} {
		for i := range ls {
			if k := [2]string{ls[i].From, ls[i].To}; !seen[k] {
				seen[k] = true
				out = append(out, ls[i])
			}
		}
	}
	return out
}

// SyncOlderKeys are this vault's older keys, through its own links, from
// its key now.
func (s *Store) SyncOlderKeys() (*OlderKeys, error) {
	links, err := s.SyncKeyLinks()
	if err != nil {
		return nil, err
	}
	id, err := s.SyncKeyID()
	if err != nil {
		return nil, err
	}
	return NewOlderKeys(s.oracle, id, links), nil
}
