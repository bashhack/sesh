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
	"maps"
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
	// Warnings are what's wrong but kept nothing from syncing, such as a
	// folder whose permissions can't be made private.
	Warnings []string
	// Notes are what else the sync did, said as they are: the recovery
	// key taken or sent, say.
	Notes []string
	// SetBack are the entries, by name, made as the folder has them under
	// the new key, on the first sync after a master password change taken
	// here: what was here besides was taken under the old key, and
	// nothing was typed here since the folder's version.
	SetBack []string
	// HeldBack are the entries, by name, the folder has no version of
	// under the new key, nor made here: not sent, and left as they are,
	// until it has, or they're deleted for good here. Said, but not
	// something a sync did (Nothing).
	HeldBack []string
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
	// Resealed counts files sealed with the key from before a master
	// password change, written again with this one.
	Resealed int
	// Rewritten counts files of entries not changed here written again:
	// lost from the folder, or an older copy put back.
	Rewritten int
	// Unfinished counts entries left for the next sync, its deadline
	// passed (Options.Deadline).
	Unfinished int
	// EarlierKey counts entries with a file sealed with a key from before
	// a master password change, not the one agreed: not taken.
	EarlierKey int
}

// Merged is an entry changed both here and in the folder: what both
// changed their own ways, the newer change kept (syncfolder.Merged).
type Merged struct {
	Name      string
	Conflicts []string
}

// Nothing says whether the sync found nothing to do.
func (s *Summary) Nothing() bool {
	return len(s.Received)+len(s.Sent)+len(s.Merged)+len(s.Renamed)+len(s.Joined)+len(s.Problems)+len(s.Notes)+len(s.SetBack)+s.Ignored+s.NotDownloaded+s.OtherKey+s.Later+s.Rewritten+s.Resealed+s.Unfinished+s.EarlierKey == 0
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
	waiting map[string]bool
	sum     *Summary
	now     func() time.Time
	folder  syncfolder.Folder
	// older open files sealed with keys the vault had before master
	// password changes (Options.Older).
	older    Older
	keyID    string
	id       string
	computer string
}

// Older gives a sealer for a key the vault had before a master password
// change, by its key record's ID; nil when it has none for it
// (database.OlderKeys).
type Older interface {
	Sealer(id string) syncfolder.Sealer
}

// Options are what a sync can do beyond the usual.
type Options struct {
	// Deadline, when set, is when the sync stops taking up entries: the
	// rest wait for the next sync (Summary.Unfinished).
	Deadline time.Time
	// Older open files sealed with keys the vault had before master
	// password changes: they're read, and written again with the vault's
	// key.
	Older Older
	// LogOnlyChanges leaves a sync with nothing to do out of the audit
	// log.
	LogOnlyChanges bool
}

// sealerFor is the sealer that opens f: the vault's, or an older key's for
// a file sealed with one.
func (y *syncer) sealerFor(f *syncfolder.File) syncfolder.Sealer {
	if y.stale(f) {
		return y.older.Sealer(f.KeyIDString())
	}
	return y.sealer
}

// stale says whether f is sealed with a key from before a password change,
// which this sync opens and writes again with the vault's. Only the file
// agreed is (decided with the user): any other is never read, as anyone
// who knew that password, with an older sesh-sync.json, could have made it
// (earlier, in entry).
func (y *syncer) stale(f *syncfolder.File) bool {
	return f.KeyIDString() != y.keyID && y.older != nil && y.older.Sealer(f.KeyIDString()) != nil
}

// Sync syncs store with the sync folder at folder, as the computer named
// computer. An error is one that stopped the whole sync (the folder can't
// be read, say); one entry's problems are in the summary, and the rest
// still sync.
func Sync(store *database.Store, folder syncfolder.Folder, computer string) (*Summary, error) {
	return SyncWith(store, folder, computer, Options{})
}

// SyncWith is Sync with opts.
func SyncWith(store *database.Store, folder syncfolder.Folder, computer string, opts Options) (*Summary, error) {
	y := &syncer{store: store, sealer: store.SyncSealer(), older: opts.Older, folder: folder, computer: computer, sum: &Summary{}, done: map[string]bool{}, busy: map[string]bool{}, waiting: map[string]bool{}, now: func() time.Time { return time.Now().UTC() }}
	var err error
	if y.keyID, err = store.SyncKeyID(); err != nil {
		return nil, err
	}
	if y.id, err = store.SyncComputerID(); err != nil {
		return nil, err
	}
	// A folder whose permissions can't be changed (another user's, or a
	// file system without them) still syncs; it's said, as a warning.
	if err := folder.Tighten(); err != nil {
		y.sum.Warnings = append(y.sum.Warnings, strings.Split(err.Error(), "\n")...)
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
	// to write over. One sealed with a key from before a password change
	// is read (Options.Older).
	for uid, fs := range files {
		if slices.ContainsFunc(fs, func(f syncfolder.File) bool { return f.KeyIDString() != y.keyID && !y.stale(&f) }) {
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
	for i, uid := range uids {
		if !opts.Deadline.IsZero() && time.Now().After(opts.Deadline) {
			y.sum.Unfinished = len(uids) - i
			break
		}
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
	if !opts.LogOnlyChanges || !y.sum.Nothing() {
		store.LogSync(y.sum.String())
	}
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

// unchanged says whether the entry it, whose files in the folder are
// files, changed neither here nor there: every file is the one agreed, its
// own among them, sealed with the vault's key (stale says it isn't), and
// the version agreed is intact (one that isn't is mended while the folder
// still has the file agreed). Nothing is opened for it, so a sync with
// nothing new decrypts nothing.
func unchanged(it *database.SyncItem, files []syncfolder.File, stale func(*syncfolder.File) bool) bool {
	if it.Agreed == nil || !it.Agreed.Intact || it.Changed() {
		return false
	}
	own := false
	for i := range files {
		f := &files[i]
		if f.Hash != it.Agreed.Hash {
			return false
		}
		if ownFile(f) {
			if stale(f) {
				return false
			}
			own = true
		}
	}
	return own
}

// copiesOf are the paths of files that are a sync tool's copies of an
// entry's own.
func copiesOf(files []syncfolder.File) []string {
	var out []string
	for i := range files {
		if !ownFile(&files[i]) {
			out = append(out, files[i].Path)
		}
	}
	return out
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
	if it.Left {
		return y.left(uid, it, files)
	}
	if it.Restored {
		return y.restored(uid, it, files)
	}
	if unchanged(it, files, y.stale) {
		return y.removeCopies(copiesOf(files))
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
	// oldKey: the entry's own file is sealed with the key from before a
	// password change, so it's written again with the vault's.
	// olderCopy: an older copy put back, whatever key sealed it.
	agreedHere, ownStale, oldKey, olderCopy := false, false, false, false
	// earlier: a file under a key from before a password change, not the
	// one agreed; earlierOwn, the entry's own file is one.
	earlier, earlierOwn := false, false
	defer func() {
		if earlier {
			y.sum.EarlierKey++
		}
	}()
	// same are versions holding just what was agreed, sealed or written
	// again elsewhere (a password change, a lost file written back): no
	// change from there, unless something else in the folder is.
	var same []remote
	defer func() {
		for _, r := range same {
			r.rec.Wipe()
		}
	}()
	var copies, earlierFiles []string
	for i := range files {
		f := &files[i]
		if !ownFile(f) {
			copies = append(copies, f.Path)
		}
		if it.Agreed != nil && f.Hash == it.Agreed.Hash {
			oldKey = oldKey || ownFile(f) && y.stale(f)
			agreedHere = agreedHere || ownFile(f)
			continue
		}
		// Not the file agreed, under a key from before a password change:
		// not read; the entry's own is written over with what was agreed.
		if y.stale(f) {
			earlier = true
			earlierOwn = earlierOwn || ownFile(f)
			earlierFiles = append(earlierFiles, f.Path)
			continue
		}
		b, err := y.folder.Read(f)
		if err != nil {
			return err
		}
		_, rec, err := syncfolder.Open(y.sealerFor(f), b)
		if err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(f.Path), err)
		}
		// What was agreed as it was, sealed again elsewhere: no change.
		if base != nil && maps.Equal(rec.Versions, base.Versions) && sameButHistory(rec, base) {
			same = append(same, remote{rec: rec, file: *f})
			continue
		}
		// Every change in it seen here already: an older copy, put back.
		if base != nil && base.Versions.Covers(rec.Versions) {
			rec.Wipe()
			y.sum.Ignored++
			olderCopy = olderCopy || ownFile(f)
			ownStale = ownStale || ownFile(f)
			continue
		}
		if base != nil && sameEntry(rec, base) {
			same = append(same, remote{rec: rec, file: *f})
			continue
		}
		fresh = append(fresh, remote{rec: rec, file: *f})
	}
	// A real change in the folder: the others are merged with it, as ever.
	if len(fresh) > 0 {
		fresh = append(fresh, same...)
		same = nil
	}
	// Otherwise what was agreed takes their counts, so what's written from
	// here covers them; the entry's own file among them stands for it.
	var sameOwn *remote
	for i := range same {
		base.Versions = base.Versions.Join(same[i].rec.Versions)
		if ownFile(&same[i].file) {
			sameOwn = &same[i]
		}
	}
	agreedHere = agreedHere || sameOwn != nil
	// The entry's own file missing, or older than what was agreed: it's
	// written again, as a sync tool or someone lost it.
	changedHere := it.Changed() || (it.Agreed != nil && !agreedHere && len(fresh) == 0) || ownStale

	if len(fresh) == 0 {
		// Never had here, and only under an earlier key: removed, as nothing
		// here could write over it. A computer that wrote it before taking
		// the change sends it again once it does.
		if it.Agreed == nil && it.Place == database.SyncGone && len(same) == 0 {
			return y.removeCopies(earlierFiles)
		}
		// The entry's own file under an earlier key: written over with what
		// was agreed, as it was agreed (no change of this computer's
		// counted), with the earlier secrets kept here, so a computer that
		// changed it before taking the password change still has the newer
		// change, and sends it.
		if earlierOwn && !it.Changed() && base != nil {
			local, _, err := y.store.SyncRecord(uid, y.computer)
			if err != nil {
				return err
			}
			defer local.Wipe()
			over := *base
			over.History = local.History
			if err := y.write(uid, it.Rev, &over, false, false); err != nil {
				return err
			}
			return y.removeCopies(copies)
		}
		// Sealed with the key from before a password change: written again.
		if changedHere || oldKey {
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
			switch {
			case it.Changed():
				y.sum.Sent = append(y.sum.Sent, recordName(uid, local))
			case oldKey && !olderCopy:
				y.sum.Resealed++
			default:
				y.sum.Rewritten++
			}
		} else if sameOwn != nil {
			// Nothing to write: the file, as it is now, is what's agreed.
			if err := y.store.SyncAgree(uid, it.Rev, sameOwn.rec, sameOwn.file.Hash); err != nil {
				return err
			}
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
		// Sealed with the key from before a password change: written again
		// with the vault's.
		if oldKey {
			if err := y.pushApplied(uid, it.Rev, m.Record); err != nil {
				return err
			}
			y.sum.Resealed++
		} else if err := y.apply(uid, it.Rev, m.Record, fresh[0].file.Hash); err != nil {
			return err
		}
		// Not said when nothing here changed: a file written again as it
		// was, or the deletion of an entry never here.
		if !sameEntry(local, m.Record) && (it.Place != database.SyncGone || m.Record.Purged.IsZero()) {
			y.sum.Received = append(y.sum.Received, recordName(uid, theirs))
		}
	default:
		m.Changed = y.now()
		if err := y.pushApplied(uid, rev, m.Record); err != nil {
			return err
		}
		y.sum.Merged = append(y.sum.Merged, Merged{Name: recordName(uid, m.Record), Conflicts: conflicts})
	}
	return y.removeCopies(copies)
}

// left syncs the entry uid, agreed here under a key this computer has
// left behind, taking a master password change made elsewhere (decided
// with the user 2026-10-18): anyone with the old password could have
// written what its syncs took under that key, so none of it is trusted.
// It's made again from the folder's version under the new key, with only
// what was typed here made again on it (syncfolder.Typed): what was sent
// and no other computer's version has seen, and what wasn't sent yet. A
// deletion for good in the folder stands. With no version in the folder
// under the new key, an entry made here is sent, one deleted for good
// here is forgotten, and any other is held back: not sent.
func (y *syncer) left(uid string, it *database.SyncItem, files []syncfolder.File) error {
	var folder *syncfolder.Record
	var hash syncfolder.Hash
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
		if y.stale(f) {
			continue
		}
		b, err := y.folder.Read(f)
		if err != nil {
			return err
		}
		_, rec, err := syncfolder.Open(y.sealerFor(f), b)
		if err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(f.Path), err)
		}
		opened = append(opened, rec)
		if ownFile(f) {
			hash = f.Hash
		}
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
	typed, err := y.store.SyncTyped(uid)
	if err != nil {
		return err
	}
	local, rev, err := y.store.SyncRecord(uid, y.computer)
	if err != nil {
		return err
	}
	defer local.Wipe()
	if it.Changed() {
		base, err := y.store.SyncBase(uid)
		if err != nil {
			base = nil
		}
		typed = append(typed, syncfolder.Diff(base, local))
		if base != nil {
			base.Wipe()
		}
	}
	// What was typed, as far as the entry here still has it.
	for i, t := range typed {
		typed[i], _ = t.Kept(local)
	}
	name := y.name(uid)
	var from *syncfolder.Record
	switch {
	case folder != nil:
		from = folder
		typed = slices.DeleteFunc(typed, func(t *syncfolder.Typed) bool { return t.N != 0 && t.N <= folder.Versions[y.id] })
	case it.Place == database.SyncGone:
		return y.store.SyncDropEntry(uid)
	case slices.ContainsFunc(typed, func(t *syncfolder.Typed) bool { return t.Created }):
		from = &syncfolder.Record{}
	default:
		y.sum.HeldBack = append(y.sum.HeldBack, name)
		return nil
	}
	r := from.Clone()
	for _, t := range typed {
		if !r.Purged.IsZero() {
			break
		}
		if t.Has("purged") {
			if slices.Contains(t.Contents, syncfolder.ContentHash(r)) {
				r = &syncfolder.Record{Purged: t.Post.Purged, Changed: t.Post.Purged, Versions: r.Versions}
			}
			continue
		}
		base, ours := t.Rebase(r)
		m, err := y.merge(uid, base, ours, r)
		base.Wipe()
		ours.Wipe()
		if err != nil {
			return err
		}
		held = append(held, m)
		m.Changed = latest(r.Changed, t.Post.Changed)
		r = m.Record
	}
	// The forget marks are what's made here: any taken under the old key
	// go, before the earlier secrets are written.
	if err := y.store.SyncSetForgotten(uid, r.Forgotten); err != nil {
		return err
	}
	if folder != nil && sameEntry(r, folder) && slices.Equal(r.Forgotten, folder.Forgotten) {
		if err := y.apply(uid, rev, folder, hash); err != nil {
			return err
		}
		if !sameEntry(local, folder) {
			y.sum.SetBack = append(y.sum.SetBack, name)
		}
	} else {
		r.Changed = y.now()
		if err := y.pushApplied(uid, rev, r); err != nil {
			return err
		}
		y.sum.Sent = append(y.sum.Sent, recordName(uid, r))
	}
	y.done[uid] = true
	return y.store.SyncLeftDone(uid)
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
	earlier := false
	defer func() {
		if earlier {
			y.sum.EarlierKey++
		}
	}()
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
		// Under a key from before a password change, not the file agreed:
		// not read (see stale).
		if y.stale(f) && (it.Agreed == nil || f.Hash != it.Agreed.Hash) {
			earlier = true
			continue
		}
		b, err := y.folder.Read(f)
		if err != nil {
			return err
		}
		_, rec, err := syncfolder.Open(y.sealerFor(f), b)
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
	// The version last agreed, when the folder's files are older (a sync
	// tool put one back, or lost it): the folder's as far as is known.
	baseUsed := false
	if base != nil {
		switch {
		case folder == nil, base.Versions.Covers(folder.Versions) && !folder.Versions.Covers(base.Versions):
			folder, baseUsed = base, true
		case !folder.Versions.Covers(base.Versions):
			m, err := y.merge(uid, nil, folder, base)
			if err != nil {
				return err
			}
			held = append(held, m)
			folder, baseUsed = m.Record, true
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
	// Changed after the restore, or in the backup and never synced: an
	// edit, which wins over a deletion.
	changedSince := rev != it.RestoredRev || it.RestoredChanged
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
	// conflict the newer wins, not one the folder settled before). Its
	// secret's use began when the backup had it set: forgotten elsewhere
	// since, it's the secret until replaced, then forgotten.
	now := y.now()
	l := *local
	l.Changed = latest(now, folder.Changed.Add(time.Nanosecond))
	if len(folder.Secret) > 0 && !bytes.Equal(folder.Secret, local.Secret) {
		l.History = append(slices.Clone(local.History), syncfolder.Earlier{ReplacedAt: now, SetAt: folder.Began(), Computer: y.computer, FileName: folder.Settings.FileName, Secret: folder.Secret})
		l.Updated, l.SetAt = now, local.Began()
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
	if own != nil && len(copies) == 0 && !baseUsed && !y.stale(own) && sameEntry(m.Record, folder) {
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
		if f.Hash != it.Agreed.Hash || f.KeyIDString() != y.keyID && !y.stale(f) {
			continue
		}
		b, err := y.folder.Read(f)
		if err != nil {
			continue
		}
		_, rec, err := syncfolder.Open(y.sealerFor(f), b)
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
		if !a.ReplacedAt.Equal(b.ReplacedAt) || !a.SetAt.Equal(b.SetAt) || a.Computer != b.Computer || a.FileName != b.FileName || !bytes.Equal(a.Secret, b.Secret) {
			return false
		}
	}
	m.History, t.History = nil, nil
	return sameEntry(&m, &t)
}

// sameButHistory is sameEntry, whatever earlier secrets each keeps (as
// each computer trims its own).
func sameButHistory(a, b *syncfolder.Record) bool {
	x, y := *a, *b
	x.History, y.History = nil, nil
	return sameEntry(&x, &y)
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
	return y.write(uid, rev, rec, apply, true)
}

// write is push, counting it as a change of this computer's when count
// says to.
func (y *syncer) write(uid string, rev int64, rec *syncfolder.Record, apply, count bool) error {
	// Never over a file waiting to be read: the next sync.
	if y.waiting[uid] {
		return database.ErrEntryChanged
	}
	var typed *syncfolder.Typed
	if count {
		var err error
		typed, err = y.typedHere(uid)
		if err != nil {
			return err
		}
		n, err := y.store.SyncNextChange(rec.Versions[y.id])
		if err != nil {
			return err
		}
		if typed != nil {
			typed.N = n
		}
		rec.Versions = rec.Versions.Join(nil)
		rec.Versions[y.id] = n
		rec.Computer = y.computer
	}
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
	// Kept once it's sent: what a password change taken later makes again.
	if typed != nil {
		if err := y.store.SyncAddTyped(uid, typed); err != nil {
			return err
		}
	}
	y.done[uid] = true
	if apply {
		return y.apply(uid, rev, rec, hash)
	}
	return y.store.SyncAgree(uid, rev, rec, hash)
}

// typedHere is what was typed here in the entry uid since it was last
// agreed (syncfolder.Diff), nil when it wasn't changed here: read before
// a version of it is written, as the vault still has what was typed.
func (y *syncer) typedHere(uid string) (*syncfolder.Typed, error) {
	it := y.item(uid)
	if !it.Changed() {
		return nil, nil
	}
	local, _, err := y.store.SyncRecord(uid, y.computer)
	if err != nil {
		return nil, err
	}
	defer local.Wipe()
	var base *syncfolder.Record
	if it.Agreed != nil {
		if base, err = y.store.SyncBase(uid); err != nil {
			base = nil
		}
		defer func() {
			if base != nil {
				base.Wipe()
			}
		}()
	}
	return syncfolder.Diff(base, local), nil
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
	if err := y.applyNamed(uid, rev, rec, hash); err != nil {
		return err
	}
	return y.store.SyncTypedKept(uid, y.computer)
}

// applyNamed is apply, settling a name another entry has here.
func (y *syncer) applyNamed(uid string, rev int64, rec *syncfolder.Record, hash syncfolder.Hash) error {
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
	// One held back under the name (Summary.HeldBack) is never sent: it's
	// renamed here, quietly, as the folder's version of it, when there is
	// one, has its own name.
	for _, it := range y.items {
		if it.UID == uid || it.Place != database.SyncLive || it.Key != k || !it.Left || it.Agreed == nil || y.done[it.UID] {
			continue
		}
		if y.waiting[it.UID] {
			return database.ErrEntryChanged
		}
		// What was typed in it and not sent is kept as sent, as the rename
		// makes it what's agreed.
		typed, err := y.typedHere(it.UID)
		if err != nil {
			return err
		}
		if typed != nil {
			if typed.N, err = y.store.SyncNextChange(0); err != nil {
				return err
			}
			if err := y.store.SyncAddTyped(it.UID, typed); err != nil {
				return err
			}
		}
		other, otherRev, err := y.store.SyncRecord(it.UID, y.computer)
		if err != nil {
			return err
		}
		other.Service = y.freeName(k)
		_, err = y.store.SyncApply(it.UID, otherRev, other, it.Agreed.Hash)
		other.Wipe()
		if err != nil {
			return err
		}
		if err := y.loadItems(); err != nil {
			return err
		}
		_, err = y.store.SyncApply(uid, rev, rec, hash)
		return err
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
	add(s.Unfinished, "left for the next sync, out of time")
	add(s.EarlierKey, "under an earlier key, not taken")
	add(len(s.SetBack), "set back to the folder's, not sent")
	add(len(s.HeldBack), "held back until the folder has them under the new key")
	add(s.Rewritten, "written again")
	add(s.Resealed, "sealed again with the new master password's key")
	add(len(s.Problems), "problems")
	if len(parts) == 0 {
		return "Sync: nothing to do"
	}
	return "Sync: " + strings.Join(parts, ", ")
}
