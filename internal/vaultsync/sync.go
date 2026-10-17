// Package vaultsync syncs a vault with a sync folder (internal/syncfolder):
// what changed here goes to the folder, what changed there comes here, and
// what changed in both is merged (syncfolder.Merge). Each entry is synced
// on its own, by its uid, against the version this computer and the
// folder last agreed on.
package vaultsync

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/syncfolder"
	"github.com/bashhack/sesh/internal/vault"
)

// Summary is what a sync did.
type Summary struct {
	// Received are the entries taken from the folder, Sent those written
	// to it, by name.
	Received, Sent []string
	// Merged are the entries changed both here and in the folder.
	Merged []Merged
	// Renamed are entries made on two computers under one name, with
	// different secrets: the one renamed, by its new name.
	Renamed []string
	// Joined are entries made on two computers under one name with the
	// same secret: made one.
	Joined []string
	// Problems are files that can't be read and entries that can't be
	// written, each with why.
	Problems []string
	// Ignored counts older copies of entries' files, already seen here: put
	// back by a sync tool, or someone.
	Ignored int
	// NotDownloaded counts files the sync tool has yet to download.
	NotDownloaded int
	// OtherKey counts files sealed with another master password's key.
	OtherKey int
	// Later counts entries another sesh command changed while this one
	// synced: the next sync takes them.
	Later int
}

// Merged is an entry changed both here and in the folder: what both
// changed their own ways, the newer change kept (syncfolder.Merged).
type Merged struct {
	Name      string
	Conflicts []string
}

// Nothing says whether the sync found nothing to do.
func (s *Summary) Nothing() bool {
	return len(s.Received)+len(s.Sent)+len(s.Merged)+len(s.Renamed)+len(s.Joined)+len(s.Problems)+s.Ignored+s.NotDownloaded+s.OtherKey+s.Later == 0
}

// syncer is one sync's state.
type syncer struct {
	store  *database.Store
	sealer syncfolder.Sealer
	items  map[string]*database.SyncItem
	// done are the entries written this sync, by uid: settled with
	// another, they aren't synced again from the files read before.
	done map[string]bool
	// busy are the entries being synced, by uid, while another is synced
	// first.
	busy map[string]bool
	// files are each entry's files in the folder, by uid.
	files map[string][]syncfolder.File
	// waiting are the entries waiting for a file to be readable, by uid:
	// nothing is written over it.
	waiting  map[string]bool
	sum      *Summary
	now      func() time.Time
	folder   syncfolder.Folder
	keyID    string
	id       string
	computer string
}

// Sync syncs store with the sync folder at folder, as the computer named
// computer. An error is one that stopped the whole sync (the folder can't
// be read, say); one entry's problems are in the summary, and the rest
// still sync.
func Sync(store *database.Store, folder syncfolder.Folder, computer string) (*Summary, error) {
	y := &syncer{store: store, sealer: store.SyncSealer(), folder: folder, computer: computer, sum: &Summary{}, done: map[string]bool{}, busy: map[string]bool{}, waiting: map[string]bool{}, now: func() time.Time { return time.Now().UTC() }}
	var err error
	if y.keyID, err = store.SyncKeyID(); err != nil {
		return nil, err
	}
	if y.id, err = store.SyncComputerID(); err != nil {
		return nil, err
	}
	contents, err := folder.Scan()
	if err != nil {
		return nil, err
	}
	if err := y.loadItems(); err != nil {
		return nil, err
	}
	files := map[string][]syncfolder.File{}
	y.files = files
	for _, f := range contents.Files {
		files[f.UIDString()] = append(files[f.UIDString()], f)
	}
	waiting := y.waiting
	for _, p := range contents.NotDownloaded {
		if uid := uidOf(p); uid != "" {
			waiting[uid] = true
		}
	}
	y.sum.NotDownloaded = len(contents.NotDownloaded)
	// A file that can't be read may be newer than anything here (from a
	// newer sesh, or being written): its entry waits too.
	for _, p := range contents.Problems {
		y.sum.Problems = append(y.sum.Problems, fmt.Sprintf("%s: %s", filepath.Base(p.Path), p.Why))
		if uid := uidOf(p.Path); uid != "" {
			waiting[uid] = true
		}
	}
	// So does one with a file sealed with another master password's key:
	// it's for the computer that wrote it to write again, not for this one
	// to write over.
	for uid, fs := range files {
		if slices.ContainsFunc(fs, func(f syncfolder.File) bool { return f.KeyIDString() != y.keyID }) {
			y.sum.OtherKey++
			waiting[uid] = true
		}
	}
	var uids []string
	for uid := range files {
		uids = append(uids, uid)
	}
	for uid := range y.items {
		if _, ok := files[uid]; !ok {
			uids = append(uids, uid)
		}
	}
	slices.Sort(uids)
	for _, uid := range uids {
		// A file not downloaded yet may be newer than any here: the entry
		// waits for it, and nothing is written over it.
		if waiting[uid] || y.done[uid] {
			continue
		}
		err := y.entry(uid, files[uid])
		switch {
		case errors.Is(err, database.ErrEntryChanged):
			y.sum.Later++
		case err != nil:
			y.sum.Problems = append(y.sum.Problems, fmt.Sprintf("%s: %v", y.name(uid), err))
		}
	}
	store.LogSync(y.sum.String())
	return y.sum, nil
}

// uidOf is the uid an entry file's name starts with (as sync tools' copies
// and iCloud's placeholders keep it), or "".
func uidOf(path string) string {
	name := strings.TrimPrefix(filepath.Base(path), ".")
	if len(name) < 32 {
		return ""
	}
	if _, err := syncfolder.NewHeader(name[:32], strings.Repeat("0", 64)); err != nil {
		return ""
	}
	return name[:32]
}

func (y *syncer) loadItems() error {
	items, err := y.store.SyncItems()
	if err != nil {
		return err
	}
	y.items = map[string]*database.SyncItem{}
	for i := range items {
		y.items[items[i].UID] = &items[i]
	}
	return nil
}

// item is uid's entry here; one never here is gone, never synced.
func (y *syncer) item(uid string) *database.SyncItem {
	if it, ok := y.items[uid]; ok {
		return it
	}
	return &database.SyncItem{UID: uid, Place: database.SyncGone}
}

// name is how the summary names uid's entry: by its name here, or its uid.
func (y *syncer) name(uid string) string {
	if it := y.item(uid); it.Place != database.SyncGone {
		return it.Key.String()
	}
	return uid
}

// remote is one of an entry's files, opened.
type remote struct {
	rec  *syncfolder.Record
	file syncfolder.File
}

// own says whether f is the entry's own file, not a sync tool's copy.
func ownFile(f *syncfolder.File) bool { return filepath.Base(f.Path) == f.UIDString()+syncfolder.Ext }

// entry syncs the entry uid, whose files in the folder are files.
func (y *syncer) entry(uid string, files []syncfolder.File) error {
	it := y.item(uid)
	if it.Restored {
		return y.restored(uid, it, files)
	}
	var base *syncfolder.Record
	if it.Agreed != nil {
		var err error
		// One that doesn't open (damaged) is mended from the folder's file
		// of it, when that's still the one agreed; else it's merged as
		// never synced.
		if base, err = y.store.SyncBase(uid); err != nil {
			if base = y.mendBase(uid, it, files); base == nil {
				y.sum.Problems = append(y.sum.Problems, fmt.Sprintf("%s: what it was last synced at doesn't open, so it's merged as never synced: %v", y.name(uid), err))
			}
		}
		defer func() {
			if base != nil {
				base.Wipe()
			}
		}()
	}
	var fresh []remote
	defer func() {
		for _, r := range fresh {
			r.rec.Wipe()
		}
	}()
	agreedHere, ownStale := false, false
	var copies []string
	for i := range files {
		f := &files[i]
		if !ownFile(f) {
			copies = append(copies, f.Path)
		}
		if it.Agreed != nil && f.Hash == it.Agreed.Hash {
			agreedHere = agreedHere || ownFile(f)
			continue
		}
		b, err := y.folder.Read(f)
		if err != nil {
			return err
		}
		_, rec, err := syncfolder.Open(y.sealer, b)
		if err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(f.Path), err)
		}
		// Every change in it seen here already: an older copy, put back.
		if base != nil && base.Versions.Covers(rec.Versions) {
			rec.Wipe()
			y.sum.Ignored++
			ownStale = ownStale || ownFile(f)
			continue
		}
		fresh = append(fresh, remote{rec: rec, file: *f})
	}
	// The entry's own file missing, or older than what was agreed: it's
	// written again, as a sync tool or someone lost it.
	changedHere := it.Changed() || (it.Agreed != nil && !agreedHere && len(fresh) == 0) || ownStale

	if len(fresh) == 0 {
		if changedHere {
			local, rev, err := y.store.SyncRecord(uid, y.computer)
			if err != nil {
				return err
			}
			defer local.Wipe()
			if base != nil {
				local.Versions = base.Versions
			}
			if err := y.push(uid, rev, local, false); err != nil {
				return err
			}
			y.sum.Sent = append(y.sum.Sent, recordName(uid, local))
		}
		return y.removeCopies(copies)
	}
	// A version that hasn't seen the one agreed here was made alongside
	// it, from an older one: there's no version both came from to merge
	// against, so everything they differ in is settled as both changing it.
	from := base
	for _, r := range fresh {
		if base != nil && !r.rec.Versions.Covers(base.Versions) {
			from = nil
		}
	}
	theirs := fresh[0].rec
	var conflicts []string
	var merged []*syncfolder.Record
	defer func() {
		for _, r := range merged {
			r.Wipe()
		}
	}()
	for _, r := range fresh[1:] {
		switch {
		case theirs.Versions.Covers(r.rec.Versions):
		case r.rec.Versions.Covers(theirs.Versions):
			theirs = r.rec
		default:
			m, err := y.merge(uid, from, theirs, r.rec)
			if err != nil {
				return err
			}
			conflicts = append(conflicts, m.Conflicts...)
			theirs = m.Record
			merged = append(merged, theirs)
		}
	}
	// What's here is merged in even when it hasn't changed: its earlier
	// secrets are kept, whatever history.keep the other computer has.
	local, rev, err := y.store.SyncRecord(uid, y.computer)
	if err != nil {
		return err
	}
	defer local.Wipe()
	if base != nil {
		local.Versions = base.Versions
	}
	m, err := y.merge(uid, from, local, theirs)
	if err != nil {
		return err
	}
	defer m.Wipe()
	conflicts = append(conflicts, m.Conflicts...)
	switch {
	case !changedHere && from == base && len(fresh) == 1 && ownFile(&fresh[0].file) && onlyOlderHistory(m.Record, theirs):
		// Just the folder's version, with what's here it doesn't have (the
		// earlier secrets of a longer history.keep): taken, and nothing
		// written back.
		if err := y.apply(uid, it.Rev, m.Record, fresh[0].file.Hash); err != nil {
			return err
		}
		y.sum.Received = append(y.sum.Received, recordName(uid, theirs))
	default:
		m.Changed = y.now()
		if err := y.pushApplied(uid, rev, m.Record); err != nil {
			return err
		}
		y.sum.Merged = append(y.sum.Merged, Merged{Name: recordName(uid, m.Record), Conflicts: conflicts})
	}
	return y.removeCopies(copies)
}

// restored syncs the entry uid, restored from a backup and not synced
// since (decided with the user 2026-10-17). It's merged with the folder's
// version, all of it read, as a change made after it: the restored values
// win where they differ, and nothing secret of the folder's is lost (its
// secret into the history, its notes and secret fields kept beside). One
// the folder has deleted (to the trash, or for good) stays deleted,
// unless it was changed here after the restore: then, as any change, it
// wins over the deletion.
func (y *syncer) restored(uid string, it *database.SyncItem, files []syncfolder.File) error {
	var base *syncfolder.Record
	if it.Agreed != nil {
		if b, err := y.store.SyncBase(uid); err == nil {
			base = b
			defer base.Wipe()
		}
	}
	var folder *syncfolder.Record
	var own *syncfolder.File
	var copies []string
	var held []syncfolder.Merged
	var opened []*syncfolder.Record
	defer func() {
		for _, m := range held {
			m.Wipe()
		}
		for _, r := range opened {
			r.Wipe()
		}
	}()
	for i := range files {
		f := &files[i]
		if ownFile(f) {
			own = f
		} else {
			copies = append(copies, f.Path)
		}
		b, err := y.folder.Read(f)
		if err != nil {
			return err
		}
		_, rec, err := syncfolder.Open(y.sealer, b)
		if err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(f.Path), err)
		}
		opened = append(opened, rec)
		switch {
		case folder == nil, rec.Versions.Covers(folder.Versions):
			folder = rec
		case folder.Versions.Covers(rec.Versions):
		default:
			m, err := y.merge(uid, nil, folder, rec)
			if err != nil {
				return err
			}
			held = append(held, m)
			folder = m.Record
		}
	}
	local, rev, err := y.store.SyncRecord(uid, y.computer)
	if err != nil {
		return err
	}
	defer local.Wipe()
	if base != nil {
		local.Versions = base.Versions
	}
	if folder == nil {
		// The folder never had it.
		if err := y.push(uid, rev, local, false); err != nil {
			return err
		}
		y.sum.Sent = append(y.sum.Sent, recordName(uid, local))
		return y.removeCopies(copies)
	}
	changedSince := rev != it.RestoredRev
	if !folder.Purged.IsZero() && !changedSince {
		gone := &syncfolder.Record{Purged: folder.Purged, Changed: y.now(), Versions: folder.Versions}
		if err := y.pushApplied(uid, rev, gone); err != nil {
			return err
		}
		y.sum.Received = append(y.sum.Received, recordName(uid, gone))
		return y.removeCopies(copies)
	}
	// The restored version, as a change made now: the newer, its secret
	// replacing the folder's, which goes into its history (so it's a
	// conflict the newer wins, not one the folder settled before).
	now := y.now()
	l := *local
	l.Changed = latest(now, folder.Changed.Add(time.Nanosecond))
	if len(folder.Secret) > 0 && !bytes.Equal(folder.Secret, local.Secret) {
		l.History = append(slices.Clone(local.History), syncfolder.Earlier{ReplacedAt: now, Computer: y.computer, FileName: folder.Settings.FileName, Secret: folder.Secret})
		l.Updated = now
	}
	m, err := y.merge(uid, nil, &l, folder)
	if err != nil {
		return err
	}
	defer m.Wipe()
	switch {
	case changedSince:
		m.Deleted = local.Deleted
	case !folder.Deleted.IsZero():
		m.Deleted = folder.Deleted
	default:
		m.Deleted = local.Deleted
	}
	m.Versions = folder.Versions
	if base != nil {
		m.Versions = m.Versions.Join(base.Versions)
	}
	// Nothing the folder's own file doesn't have: taken, nothing written.
	if own != nil && len(copies) == 0 && sameEntry(m.Record, folder) {
		if err := y.apply(uid, rev, m.Record, own.Hash); err != nil {
			return err
		}
		return nil
	}
	m.Changed = now
	if err := y.pushApplied(uid, rev, m.Record); err != nil {
		return err
	}
	y.sum.Merged = append(y.sum.Merged, Merged{Name: recordName(uid, m.Record), Conflicts: append([]string{"restored"}, m.Conflicts...)})
	return y.removeCopies(copies)
}

func latest(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// mendBase is the version the entry uid was last agreed at, read from its
// file in the folder when that's still the one agreed, and kept again in
// the vault; nil when there's none to read.
func (y *syncer) mendBase(uid string, it *database.SyncItem, files []syncfolder.File) *syncfolder.Record {
	for i := range files {
		f := &files[i]
		if f.Hash != it.Agreed.Hash || f.KeyIDString() != y.keyID {
			continue
		}
		b, err := y.folder.Read(f)
		if err != nil {
			continue
		}
		_, rec, err := syncfolder.Open(y.sealer, b)
		if err != nil {
			continue
		}
		if err := y.store.SyncMendBase(uid, rec); err != nil {
			rec.Wipe()
			return nil
		}
		return rec
	}
	return nil
}

// removeCopies removes a sync tool's copies of an entry's file, merged
// into it now.
func (y *syncer) removeCopies(copies []string) error {
	for _, p := range copies {
		if err := y.folder.Remove(p); err != nil {
			y.sum.Problems = append(y.sum.Problems, fmt.Sprintf("%s: %v", filepath.Base(p), err))
		}
	}
	return nil
}

// onlyOlderHistory says whether merged holds what theirs does, and only
// earlier secrets older than all of theirs besides (those a computer
// keeping fewer trimmed): nothing the folder needs.
func onlyOlderHistory(merged, theirs *syncfolder.Record) bool {
	m, t := *merged, *theirs
	if len(m.History) < len(t.History) {
		return false
	}
	for i := range t.History {
		a, b := &m.History[i], &t.History[i]
		if !a.ReplacedAt.Equal(b.ReplacedAt) || a.Computer != b.Computer || a.FileName != b.FileName || !bytes.Equal(a.Secret, b.Secret) {
			return false
		}
	}
	m.History, t.History = nil, nil
	return sameEntry(&m, &t)
}

// sameEntry says whether a and b hold the same entry, whoever made them
// and when.
func sameEntry(a, b *syncfolder.Record) bool {
	x, y := *a, *b
	x.Changed, y.Changed, x.Computer, y.Computer, x.Versions, y.Versions = time.Time{}, time.Time{}, "", "", nil, nil
	ja, err := json.Marshal(&x) //nolint:gosec // compared, then zeroed; never written
	if err != nil {
		return false
	}
	defer secure.SecureZeroBytes(ja)
	jb, err := json.Marshal(&y) //nolint:gosec // compared, then zeroed; never written
	if err != nil {
		return false
	}
	defer secure.SecureZeroBytes(jb)
	return bytes.Equal(ja, jb)
}

// recordName is how the summary names rec, the entry uid.
func recordName(uid string, rec *syncfolder.Record) string {
	if !rec.Purged.IsZero() || rec.Service == "" {
		return uid + " (deleted for good)"
	}
	return vault.Key{Kind: rec.Kind, Service: rec.Service, Username: rec.Username}.String()
}

// push writes rec, a new version of the entry uid (at rev here), to the
// folder, as this computer's change, and records it agreed: rec is what
// the entry holds here already.
func (y *syncer) push(uid string, rev int64, rec *syncfolder.Record, apply bool) error {
	// Never over a file waiting to be read: the next sync.
	if y.waiting[uid] {
		return database.ErrEntryChanged
	}
	n, err := y.store.SyncNextChange(rec.Versions[y.id])
	if err != nil {
		return err
	}
	rec.Versions = rec.Versions.Join(nil)
	rec.Versions[y.id] = n
	rec.Computer = y.computer
	if rec.Changed.IsZero() {
		rec.Changed = y.now()
	}
	h, err := syncfolder.NewHeader(uid, y.keyID)
	if err != nil {
		return err
	}
	b, err := syncfolder.Seal(y.sealer, h, rec)
	// Too large for a sync file (large files, a long history): the oldest
	// earlier secrets aren't sent, until it fits; this computer keeps them.
	sent := *rec
	for errors.Is(err, syncfolder.ErrTooLarge) && len(sent.History) > 0 {
		sent.History = sent.History[:len(sent.History)/2]
		b, err = syncfolder.Seal(y.sealer, h, &sent)
	}
	if err != nil {
		return err
	}
	hash, err := y.folder.Write(h, b)
	if err != nil {
		return err
	}
	y.done[uid] = true
	if apply {
		return y.apply(uid, rev, rec, hash)
	}
	return y.store.SyncAgree(uid, rev, rec, hash)
}

// pushApplied writes rec, a new version of the entry uid (at rev here), to
// the folder and makes the entry here as it has it.
func (y *syncer) pushApplied(uid string, rev int64, rec *syncfolder.Record) error {
	return y.push(uid, rev, rec, true)
}

// apply makes the entry uid (at rev here) as rec, the folder's file of
// hash, has it. A name another entry has here is settled as two computers
// making one entry under one name are: the same secret, one entry; others,
// both, one renamed.
//
// The other may be moving off the name in the folder (renamed, deleted):
// it's synced first, then this again.
func (y *syncer) apply(uid string, rev int64, rec *syncfolder.Record, hash syncfolder.Hash) error {
	_, err := y.store.SyncApply(uid, rev, rec, hash)
	if !errors.Is(err, database.ErrNameTaken) {
		return err
	}
	k := vault.Key{Kind: rec.Kind, Service: rec.Service, Username: rec.Username}
	for _, it := range y.items {
		if it.UID == uid || it.Place != database.SyncLive || it.Key != k || y.done[it.UID] || y.busy[it.UID] || y.waiting[it.UID] || len(y.files[it.UID]) == 0 {
			continue
		}
		y.busy[uid] = true
		err := y.entry(it.UID, y.files[it.UID])
		delete(y.busy, uid)
		y.done[it.UID] = true
		if err != nil {
			return err
		}
		if err := y.loadItems(); err != nil {
			return err
		}
		if _, err := y.store.SyncApply(uid, rev, rec, hash); !errors.Is(err, database.ErrNameTaken) {
			return err
		}
		break
	}
	return y.sameName(uid, rev, rec)
}

// merge merges ours and theirs, versions of the entry uid, against base,
// so they make an entry sesh can keep: when the older's notes or secret
// fields kept beside the newer's don't fit, the newer's alone, said in
// the summary.
func (y *syncer) merge(uid string, base, ours, theirs *syncfolder.Record) (syncfolder.Merged, error) {
	var err error
	for i, b := range []syncfolder.Beside{{Notes: true, Fields: true}, {Fields: true}, {Notes: true}, {}} {
		m := syncfolder.MergeWith(base, ours, theirs, b)
		if err = y.store.SyncCheck(m.Record); err == nil {
			if i > 0 {
				y.sum.Problems = append(y.sum.Problems, fmt.Sprintf("%s: changed on two computers, and the older's %s don't fit beside the newer's: the newer's were kept", recordName(uid, m.Record), map[int]string{1: "notes", 2: "secret fields", 3: "notes and secret fields"}[i]))
			}
			return m, nil
		}
		m.Wipe()
	}
	return syncfolder.Merged{}, fmt.Errorf("its versions can't be merged into an entry sesh can keep (%w): each computer keeps its own until one is changed to fit", err)
}

// sameName settles the entry uid (at rev here), as rec has it, taking a
// name another entry here has. Both computers settle it alike: the entry
// with the lower uid keeps the name; with the same secret, the other is
// merged into it and deleted for good, else renamed with " (2)".
func (y *syncer) sameName(uid string, rev int64, rec *syncfolder.Record) error {
	k := vault.Key{Kind: rec.Kind, Service: rec.Service, Username: rec.Username}
	if err := y.loadItems(); err != nil {
		return err
	}
	var other *database.SyncItem
	for _, it := range y.items {
		if it.UID != uid && it.Place == database.SyncLive && it.Key == k {
			other = it
		}
	}
	if other == nil {
		return database.ErrEntryChanged // gone meanwhile: the next sync
	}
	theirs, theirRev, err := y.store.SyncRecord(other.UID, y.computer)
	if err != nil {
		return err
	}
	defer theirs.Wipe()
	if other.Agreed != nil {
		if base, err := y.store.SyncBase(other.UID); err == nil && base != nil {
			theirs.Versions = base.Versions
			base.Wipe()
		}
	}
	// Either waiting for its file: both wait, so neither is half settled.
	if y.waiting[uid] || y.waiting[other.UID] {
		return database.ErrEntryChanged
	}
	keep, keepRev, keepRec, drop, dropRev, dropRec := uid, rev, rec, other.UID, theirRev, theirs
	if other.UID < uid {
		keep, keepRev, keepRec, drop, dropRev, dropRec = other.UID, theirRev, theirs, uid, rev, rec
	}
	if bytes.Equal(rec.Secret, theirs.Secret) {
		m, err := y.merge(keep, nil, keepRec, dropRec)
		if err != nil {
			return err
		}
		defer m.Wipe()
		m.Changed = y.now()
		gone := &syncfolder.Record{Purged: y.now(), Changed: y.now(), Versions: dropRec.Versions}
		if err := y.pushApplied(drop, dropRev, gone); err != nil {
			return err
		}
		if err := y.pushApplied(keep, keepRev, m.Record); err != nil {
			return err
		}
		y.sum.Joined = append(y.sum.Joined, k.String())
		return y.loadItems()
	}
	renamed := *dropRec
	renamed.Service = y.freeName(k)
	renamed.Changed = y.now()
	if err := y.pushApplied(drop, dropRev, &renamed); err != nil {
		return err
	}
	y.sum.Renamed = append(y.sum.Renamed, vault.Key{Kind: k.Kind, Service: renamed.Service, Username: k.Username}.String())
	if keep == uid {
		if err := y.pushApplied(keep, keepRev, keepRec); err != nil {
			return err
		}
	}
	return y.loadItems()
}

// freeName is k's service with " (2)" (or the first number free) added,
// for an entry renamed to make way for another.
func (y *syncer) freeName(k vault.Key) string {
	service := k.Service
	// "bank (2)" taken too: "bank (3)", not "bank (2) (2)".
	if i := strings.LastIndex(service, " ("); i > 0 && strings.HasSuffix(service, ")") {
		if _, err := strconv.Atoi(service[i+2 : len(service)-1]); err == nil {
			service = service[:i]
		}
	}
	for i := 2; ; i++ {
		s := fmt.Sprintf("%s (%d)", service, i)
		taken := false
		for _, it := range y.items {
			if it.Place == database.SyncLive && it.Key == (vault.Key{Kind: k.Kind, Service: s, Username: k.Username}) {
				taken = true
			}
		}
		if !taken {
			return s
		}
	}
}

// String is the summary in a line, as the audit log keeps it.
func (s *Summary) String() string {
	var parts []string
	add := func(n int, what string) {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, what))
		}
	}
	add(len(s.Received), "received")
	add(len(s.Sent), "sent")
	add(len(s.Merged), "merged")
	add(len(s.Renamed), "renamed")
	add(len(s.Joined), "joined")
	add(s.Ignored, "older copies ignored")
	add(s.NotDownloaded, "not downloaded")
	add(s.OtherKey, "sealed with another key")
	add(s.Later, "left for the next sync")
	add(len(s.Problems), "problems")
	if len(parts) == 0 {
		return "Sync: nothing to do"
	}
	return "Sync: " + strings.Join(parts, ", ")
}
