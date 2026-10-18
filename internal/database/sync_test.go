package database

import (
	"bytes"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/syncfolder"
	"github.com/bashhack/sesh/internal/vault"
)

// syncPair is two vaults under one master password, as two computers
// syncing have.
func syncPair(t *testing.T) (a, b *Store) {
	t.Helper()
	p, a := rekeyVault(t)
	q := filepath.Join(t.TempDir(), "passwords.db")
	if err := CopyTo(p, q); err != nil {
		t.Fatal(err)
	}
	b, err := Open(q, NewKeySourceOracle(NewMasterPasswordSource(q, staticPrompt("old-password-1"))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() }) //nolint:errcheck // test cleanup
	for _, s := range []*Store{a, b} {
		s.SetTrashDays(30)
		s.SetHistoryKeep(10)
	}
	return a, b
}

func uidOf(t *testing.T, s *Store, k vault.Key) string {
	t.Helper()
	uid, _ := idOf(t, s, k)
	return uid
}

// An entry read as a record and written into another vault is the same
// entry there: its name, secret, details, folder, tags, times, earlier
// secrets (with the computers they were replaced on) and forgotten ones;
// and reading it back gives the same record.
func TestSyncRecordApply(t *testing.T) {
	a, b := syncPair(t)
	k := vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}
	for _, pw := range []string{"pw-1", "pw-2", "pw-3"} {
		if err := a.Put(k, []byte(pw)); err != nil {
			t.Fatal(err)
		}
	}
	d := &vault.Details{URL: "https://github.com", Notes: []byte("notes"), Fields: []vault.Field{{Name: "pin", Value: []byte("1234"), Secret: true}, {Name: "team", Value: []byte("core")}}}
	if err := a.SaveWithDetails(&vault.Entry{Key: k, Folder: "work/dev", Tags: []string{"b", "a"}}, []byte("pw-4"), d); err != nil {
		t.Fatal(err)
	}
	if err := a.ForgetVersions(k, 4); err != nil { // pw-1
		t.Fatal(err)
	}
	uid := uidOf(t, a, k)
	rec, rev, err := a.SyncRecord(uid, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if string(rec.Secret) != "pw-4" || rec.Folder != "work/dev" || !slices.Equal(rec.Tags, []string{"a", "b"}) || string(rec.Notes) != "notes" ||
		len(rec.Fields) != 2 || string(rec.Fields[0].Value) != "1234" || !slices.Equal(secrets(rec.History), []string{"pw-3", "pw-2"}) ||
		rec.History[0].Computer != "laptop" || len(rec.Forgotten) != 1 || rec.Changed.IsZero() {
		t.Fatalf("record %+v", rec)
	}
	_, idRev := idOf(t, a, k)
	if rev != idRev {
		t.Errorf("rev %d, want %d", rev, idRev)
	}
	rec.History[1].Computer = "desktop"
	if _, err := b.SyncApply(uid, 0, rec, syncfolder.Hash{1}); err != nil {
		t.Fatal(err)
	}
	got, _, err := b.SyncRecord(uid, "elsewhere")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Secret) != "pw-4" || got.Folder != rec.Folder || !slices.Equal(got.Tags, rec.Tags) || !bytes.Equal(got.Notes, rec.Notes) ||
		len(got.Fields) != 2 || !slices.Equal(secrets(got.History), secrets(rec.History)) || got.History[1].Computer != "desktop" ||
		!slices.Equal(got.Forgotten, rec.Forgotten) || !got.Created.Equal(rec.Created) || !got.Updated.Equal(rec.Updated) {
		t.Errorf("applied %+v\nwant %+v", got, rec)
	}
	// Agreed, and so not changed here since.
	it := syncItem(t, b, uid)
	if it.Changed() || it.Agreed.Hash != (syncfolder.Hash{1}) {
		t.Errorf("item %+v", it)
	}
	if base, err := b.SyncBase(uid); err != nil || string(base.Secret) != "pw-4" {
		t.Errorf("base %v, %v", base, err)
	}
	// In the trash, then deleted for good.
	rec.Deleted = rec.Changed
	newRev, err := b.SyncApply(uid, it.Rev, rec, syncfolder.Hash{2})
	if err != nil {
		t.Fatal(err)
	}
	if tr, err := b.Trash(); err != nil || len(tr) != 1 || tr[0].Key != k {
		t.Errorf("trash %v, %v", tr, err)
	}
	if h, err := b.syncHistory(&syncRow{key: k, place: SyncTrashed, id: trashID(t, b)}, "x"); err != nil || len(h) != 2 {
		t.Errorf("trash history %d, %v", len(h), err)
	}
	if _, err := b.SyncApply(uid, newRev, &syncfolder.Record{Purged: rec.Changed}, syncfolder.Hash{3}); err != nil {
		t.Fatal(err)
	}
	it = syncItem(t, b, uid)
	if tr, _ := b.Trash(); len(tr) != 0 || it.Place != SyncGone || it.Changed() { //nolint:errcheck // a count
		t.Errorf("after deleting for good: trash %v, item %+v", tr, it)
	}
}

func trashID(t *testing.T, s *Store) int64 {
	t.Helper()
	tr, err := s.Trash()
	if err != nil || len(tr) != 1 {
		t.Fatalf("trash %v, %v", tr, err)
	}
	return tr[0].ID
}

func secrets(hs []syncfolder.Earlier) (out []string) {
	for _, h := range hs {
		out = append(out, string(h.Secret))
	}
	return out
}

// Applying a record refuses an entry changed since its rev was read, and a
// name another entry has, changing nothing.
func TestSyncApply_Refuses(t *testing.T) {
	a, b := syncPair(t)
	k := vault.Key{Kind: vault.KindPassword, Service: "github"}
	if err := a.Put(k, []byte("a")); err != nil {
		t.Fatal(err)
	}
	rec, _, err := a.SyncRecord(uidOf(t, a, k), "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Put(k, []byte("b")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.SyncApply(uidOf(t, a, k), 0, rec, syncfolder.Hash{}); !errors.Is(err, ErrNameTaken) {
		t.Errorf("a name taken: %v", err)
	}
	own := uidOf(t, b, k)
	if _, err := b.SyncApply(own, 0, rec, syncfolder.Hash{}); !errors.Is(err, ErrEntryChanged) {
		t.Errorf("an old rev: %v", err)
	}
	if got, _ := b.Get(k); string(got) != "b" { //nolint:errcheck // compared
		t.Errorf("b's entry is %q", got)
	}
	if err := b.SyncAgree(own, 99, rec, syncfolder.Hash{}); !errors.Is(err, ErrEntryChanged) {
		t.Errorf("agree at an old rev: %v", err)
	}
	if it := syncItem(t, b, own); it.Agreed != nil {
		t.Errorf("item %+v", it)
	}
}

// A new master password seals what was agreed again, so it still opens.
func TestSync_RekeyKeepsWhatWasAgreed(t *testing.T) {
	p, s := rekeyVault(t)
	k := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	uid := uidOf(t, s, k)
	rec, rev, err := s.SyncRecord(uid, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SyncAgree(uid, rev, rec, syncfolder.Hash{7}); err != nil {
		t.Fatal(err)
	}
	key, kr := newKeyFor(t, "new-password-1")
	if _, err := s.Rekey(key, kr, rewrapTo, RekeyOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(p, NewKeySourceOracle(NewMasterPasswordSource(p, staticPrompt("new-password-1"))))
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close() //nolint:errcheck // test cleanup
	base, err := s2.SyncBase(uid)
	if err != nil || string(base.Secret) != "bank-secret" {
		t.Fatalf("after the new password: %v, %v", base, err)
	}
	id, err := s2.SyncKeyID()
	if err != nil {
		t.Fatal(err)
	}
	var b []byte
	if err := s2.db.QueryRow(`SELECT base FROM sync_state WHERE uid = ?`, uid).Scan(&b); err != nil {
		t.Fatal(err)
	}
	if h, err := syncfolder.ParseHeader(b); err != nil || h.KeyIDString() != id {
		t.Errorf("sealed for %s, want the new key record %s (%v)", h.KeyIDString(), id, err)
	}
	if it := syncItem(t, s2, uid); it.Changed() {
		t.Errorf("a new password changed the entry: %+v", it)
	}
}

// Each computer's sync ID is made once, and its own.
func TestSyncComputerID(t *testing.T) {
	a, b := syncPair(t)
	ia, err := a.SyncComputerID()
	if err != nil {
		t.Fatal(err)
	}
	again, _ := a.SyncComputerID() //nolint:errcheck // compared
	ib, _ := b.SyncComputerID()    //nolint:errcheck // compared
	if len(ia) != 16 || again != ia || ib == ia {
		t.Errorf("ids %q %q %q", ia, again, ib)
	}
}

// syncItem is uid's item in s.
func syncItem(t *testing.T, s *Store, uid string) SyncItem {
	t.Helper()
	items, err := s.SyncItems()
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(items, func(it SyncItem) bool { return it.UID == uid })
	if i < 0 {
		t.Fatalf("no item %s in %+v", uid, items)
	}
	return items[i]
}

// A use's start other than the update time (a restore's) is kept by sync,
// the trash and settings changes, and goes into the history with it.
func TestSyncRecord_SetAt(t *testing.T) {
	a, b := syncPair(t)
	k := vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}
	if err := a.Put(k, []byte("pw-1")); err != nil {
		t.Fatal(err)
	}
	uid := uidOf(t, a, k)
	rec, _, err := a.SyncRecord(uid, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	began := rec.Updated.Add(-time.Hour)
	rec.SetAt = began
	if _, err := b.SyncApply(uid, 0, rec, syncfolder.Hash{}); err != nil {
		t.Fatal(err)
	}
	if err := b.SetSettings(k, &vault.Settings{}); err != nil {
		t.Fatal(err)
	}
	if err := b.Delete(k); err != nil {
		t.Fatal(err)
	}
	tr, err := b.Trash()
	if err != nil || len(tr) != 1 {
		t.Fatalf("trash %+v, %v", tr, err)
	}
	if _, err := b.RestoreFromTrash(tr[0].ID, vault.Key{}); err != nil {
		t.Fatal(err)
	}
	if got, _, err := b.SyncRecord(uid, "desktop"); err != nil || !got.SetAt.Equal(began) {
		t.Fatalf("set %v (%v), want %s", got.SetAt, err, began)
	}
	if err := b.Put(k, []byte("pw-2")); err != nil {
		t.Fatal(err)
	}
	got, _, err := b.SyncRecord(uid, "desktop")
	if err != nil {
		t.Fatal(err)
	}
	if !got.SetAt.IsZero() || len(got.History) != 1 || !got.History[0].SetAt.Equal(began) {
		t.Errorf("set %v, history %+v; want a new use, and pw-1 set %s", got.SetAt, got.History, began)
	}
}

// New settings don't start a new use of the secret.
func TestSetSettings_KeepsSetAt(t *testing.T) {
	a, _ := syncPair(t)
	k := vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}
	if err := a.Put(k, []byte("pw-1")); err != nil {
		t.Fatal(err)
	}
	e, err := a.Lookup(k)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.SetSettings(k, &vault.Settings{}); err != nil {
		t.Fatal(err)
	}
	if err := a.Put(k, []byte("pw-2")); err != nil {
		t.Fatal(err)
	}
	rec, _, err := a.SyncRecord(uidOf(t, a, k), "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.History) != 1 || !rec.History[0].SetAt.Equal(e.UpdatedAt) {
		t.Errorf("history %+v, want pw-1 set %s", rec.History, e.UpdatedAt)
	}
}

// An earlier secret keeps when its use was set, its entry's update time as
// replaced (by Put or Edit); forgetting it marks no earlier than that.
func TestSyncHistory_SetAt(t *testing.T) {
	a, _ := syncPair(t)
	k := vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}
	if err := a.Put(k, []byte("pw-1")); err != nil {
		t.Fatal(err)
	}
	// pw-1 was set by a computer whose clock is 10 minutes ahead.
	if _, err := a.db.Exec(`UPDATE entries SET updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now', '+10 minutes')`); err != nil {
		t.Fatal(err)
	}
	set := func() time.Time {
		e, err := a.Lookup(k)
		if err != nil {
			t.Fatal(err)
		}
		return e.UpdatedAt
	}
	set1 := set()
	if err := a.Put(k, []byte("pw-2")); err != nil {
		t.Fatal(err)
	}
	set2 := set()
	if _, err := a.Edit(k, EntryEdit{Secret: []byte("pw-3")}); err != nil {
		t.Fatal(err)
	}
	rec, _, err := a.SyncRecord(uidOf(t, a, k), "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if h := rec.History; len(h) != 2 || string(h[0].Secret) != "pw-2" || !h[0].SetAt.Equal(set2) || string(h[1].Secret) != "pw-1" || !h[1].SetAt.Equal(set1) {
		t.Fatalf("history %+v, want pw-2 set %s, pw-1 set %s", h, set2, set1)
	}
	if err := a.ForgetVersions(k, 3); err != nil { // pw-1
		t.Fatal(err)
	}
	if rec, _, err = a.SyncRecord(uidOf(t, a, k), "laptop"); err != nil {
		t.Fatal(err)
	}
	if len(rec.Forgotten) != 1 || rec.Forgotten[0].At.Before(set1) {
		t.Errorf("forgotten %+v, want at %s or later", rec.Forgotten, set1)
	}
}

// A change's count is past any seen for this computer, whatever the vault
// had counted.
func TestSyncNextChange(t *testing.T) {
	s, _ := syncPair(t)
	if n, err := s.SyncNextChange(0); err != nil || n != 1 {
		t.Fatalf("first: %d, %v", n, err)
	}
	if n, err := s.SyncNextChange(10); err != nil || n != 11 {
		t.Errorf("past 10 seen: %d, %v", n, err)
	}
	if n, err := s.SyncNextChange(3); err != nil || n != 12 {
		t.Errorf("then: %d, %v", n, err)
	}
	// One that would reach MaxCount isn't given, nor counted.
	if _, err := s.SyncNextChange(syncfolder.MaxCount - 1); err == nil || !strings.Contains(err.Error(), "too high") {
		t.Errorf("at the cap: %v, want an error with %q", err, "too high")
	}
	if n, err := s.SyncNextChange(3); err != nil || n != 13 {
		t.Errorf("after the cap: %d, %v", n, err)
	}
}

// What was typed in an entry is kept, folded, dropped once another's
// version has seen it, sealed again for a new master password, and gone
// once the entry is made again after a change taken.
func TestSyncTyped(t *testing.T) {
	s, _ := syncPair(t)
	pre := &syncfolder.Record{Kind: vault.KindPassword, Service: "a", Secret: []byte("1"), Notes: []byte("n")}
	typed := func(n uint64, secret, notes string) *syncfolder.Typed {
		post := *pre
		post.Secret, post.Notes = []byte(secret), []byte(notes)
		d := syncfolder.Diff(pre, &post)
		d.N = n
		return d
	}
	for _, d := range []*syncfolder.Typed{typed(3, "2", "n"), typed(5, "1", "m")} {
		if err := s.SyncAddTyped("u", d); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.SyncTyped("u")
	if err != nil || len(got) != 2 || got[0].N != 3 || string(got[0].Post.Secret) != "2" || string(got[1].Post.Notes) != "m" {
		t.Fatalf("kept %+v, %v: want both, in order", got, err)
	}
	key, rec := newKeyFor(t, "new-password-1")
	if _, err := s.Rekey(key, rec, rewrapTo, RekeyOptions{}); err != nil {
		t.Fatal(err)
	}
	s, err = Open(s.Path(), NewKeySourceOracle(NewMasterPasswordSource(s.Path(), staticPrompt("new-password-1"))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() }) //nolint:errcheck // test cleanup
	if got, err := s.SyncTyped("u"); err != nil || len(got) != 2 {
		t.Fatalf("after a new master password: %d kept, %v; want both, sealed again", len(got), err)
	}
	if err := s.SyncTypedSeen("u", 4); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.SyncTyped("u"); len(got) != 1 || got[0].N != 5 { //nolint:errcheck // checked by the result
		t.Errorf("seen up to 4: %+v, want the one sent with 5", got)
	}
	if err := s.SyncLeftDone("u"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.SyncTyped("u"); len(got) != 0 { //nolint:errcheck // checked by the result
		t.Errorf("made again: %+v, want none", got)
	}
}

// Joining makes a vault with the folder's key record; an empty one with
// another is given it, its recovery record removed; one with entries joins
// only the folder it synced with, under its key, keeping what it agreed.
func TestJoinVault(t *testing.T) {
	p, s := rekeyVault(t)
	m, err := ReadUnlockMaterial(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SyncStartFolder("f1"); err != nil {
		t.Fatal(err)
	}
	id, err := s.SyncComputerID()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := CheckMasterPassword([]byte("old-password-1"), m); err != nil {
		t.Errorf("the right password: %v", err)
	}
	if err := CheckMasterPassword([]byte("nope"), m); err == nil {
		t.Error("a wrong password passed")
	}
	fresh := filepath.Join(t.TempDir(), "new.db")
	if rejoin, err := JoinVault(fresh, m, "f1", nil); err != nil || rejoin {
		t.Fatal(rejoin, err)
	}
	if got, err := ReadUnlockMaterial(fresh); err != nil || UnlockID(got.Verify) != UnlockID(m.Verify) {
		t.Errorf("new vault's key record: %v", err)
	}
	if got := folderOf(t, fresh); got != "f1" {
		t.Errorf("new vault's sync folder: %q", got)
	}
	if got, err := VaultSyncFolder(fresh); err != nil || got != "f1" {
		t.Errorf("VaultSyncFolder = %q, %v", got, err)
	}
	if got, err := VaultSyncFolder(filepath.Join(t.TempDir(), "none.db")); err != nil || got != "" {
		t.Errorf("VaultSyncFolder with no vault = %q, %v", got, err)
	}
	if rejoin, err := JoinVault(fresh, m, "f1", nil); err != nil || !rejoin {
		t.Errorf("again: %v, %v; want it rejoining", rejoin, err)
	}
	if !opensWith(t, p, "old-password-1") {
		t.Fatal("the vault doesn't open")
	}
	other := mustOtherKey(t)
	for _, c := range []struct {
		want   error
		folder string
		m      UnlockMaterial
	}{
		{ErrVaultNotEmpty, "f2", other},
		{ErrVaultNotEmpty, "f2", m},
		{ErrRejoinOtherKey, "f1", other},
	} {
		if _, err := CanJoin(p, c.m, c.folder); !errors.Is(err, c.want) {
			t.Errorf("CanJoin with entries, folder %s: %v, want %v", c.folder, err, c.want)
		}
		if _, err := JoinVault(p, c.m, c.folder, nil); !errors.Is(err, c.want) {
			t.Errorf("JoinVault with entries, folder %s: %v, want %v", c.folder, err, c.want)
		}
	}
	// Joining again the folder it synced with: what it agreed is kept.
	if rejoin, err := CanJoin(p, m, "f1"); err != nil || !rejoin {
		t.Errorf("CanJoin again: %v, %v", rejoin, err)
	}
	if rejoin, err := JoinVault(p, m, "f1", nil); err != nil || !rejoin {
		t.Errorf("JoinVault again: %v, %v", rejoin, err)
	}
	if !opensWith(t, p, "old-password-1") || folderOf(t, p) != "f1" || computerOf(t, p) != id {
		t.Error("joining again changed the vault")
	}
	for path, want := range map[string]error{fresh: nil, filepath.Join(t.TempDir(), "none.db"): nil} {
		if _, err := CanJoin(path, m, "f1"); !errors.Is(err, want) {
			t.Errorf("CanJoin(%s) = %v, want %v", filepath.Base(path), err, want)
		}
	}
	// An empty vault with a key record and a recovery record of its own.
	empty := filepath.Join(t.TempDir(), "empty.db")
	es, err := Open(empty, NewKeySourceOracle(NewMasterPasswordSource(empty, staticPrompt("other-password-1", "other-password-1"))))
	if err != nil {
		t.Fatal(err)
	}
	k := vault.Key{Kind: vault.KindPassword, Service: "x"}
	if err := es.Put(k, []byte("x")); err != nil {
		t.Fatal(err)
	}
	// It synced with another folder, under its own key, before.
	uid := uidOf(t, es, k)
	emptyID, err := es.SyncComputerID()
	if err != nil {
		t.Fatal(err)
	}
	rec, rev, err := es.SyncRecord(uid, "x")
	if err != nil {
		t.Fatal(err)
	}
	if err := es.SyncAgree(uid, rev, rec, syncfolder.Hash{1}); err != nil {
		t.Fatal(err)
	}
	if err := es.PurgeMany([]vault.Key{k}); err != nil {
		t.Fatal(err)
	}
	if err := es.Close(); err != nil {
		t.Fatal(err)
	}
	if err := WriteRecovery(empty, &RecoveryRecord{UnlockID: vaultID(t, empty), PublicKey: []byte("p"), EphemeralPub: []byte("e"), Ciphertext: []byte("c")}); err != nil {
		t.Fatal(err)
	}
	if _, err := JoinVault(empty, m, "f1", nil); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadUnlockMaterial(empty); err != nil || UnlockID(got.Verify) != UnlockID(m.Verify) {
		t.Errorf("empty vault's key record: %v", err)
	}
	if r, err := ReadRecovery(empty); err == nil && r != nil {
		t.Errorf("recovery record kept: %+v", r)
	}
	db, err := openDB(empty)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // test
	for _, table := range []string{"sync_state", "sync_restored", "history_forgotten"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil || n != 0 { //nolint:gosec // table is one of the three
			t.Errorf("%s: %d rows kept from the earlier sync (%v)", table, n, err)
		}
	}
	if got := computerOf(t, empty); got == "" || got == emptyID {
		t.Errorf("the sync ID kept from the earlier sync: %q", got)
	}
}

func folderOf(t *testing.T, path string) string {
	t.Helper()
	return syncInfoOf(t, path, "folder_id")
}

func computerOf(t *testing.T, path string) string {
	t.Helper()
	return syncInfoOf(t, path, "computer_id")
}

func syncInfoOf(t *testing.T, path, column string) string {
	t.Helper()
	db, err := openDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // test
	var v string
	if err := db.QueryRow(`SELECT ` + column + ` FROM sync_info WHERE id = 1`).Scan(&v); err != nil { //nolint:gosec // a column name the test gives
		t.Fatalf("%s: %v", column, err)
	}
	return v
}

func mustOtherKey(t *testing.T) UnlockMaterial {
	t.Helper()
	_, m := newKeyFor(t, "another-password-1")
	return m
}

// Starting on another sync folder forgets what was agreed with the one
// before; the same folder keeps it, as do restored marks.
func TestSyncStartFolder(t *testing.T) {
	a, _ := syncPair(t)
	if err := a.SyncStartFolder("f1"); err != nil {
		t.Fatal(err)
	}
	uid := uidOf(t, a, vault.Key{Kind: vault.KindPassword, Service: "bank"})
	rec, rev, err := a.SyncRecord(uid, "x")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.SyncAgree(uid, rev, rec, syncfolder.Hash{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec(`INSERT INTO sync_restored (uid, rev) VALUES (?, ?)`, uid, rev); err != nil {
		t.Fatal(err)
	}
	if err := a.SyncStartFolder("f1"); err != nil {
		t.Fatal(err)
	}
	if it := syncItem(t, a, uid); it.Agreed == nil {
		t.Error("the same folder: what was agreed is forgotten")
	}
	if err := a.SyncStartFolder("f2"); err != nil {
		t.Fatal(err)
	}
	if it := syncItem(t, a, uid); it.Agreed != nil || !it.Restored {
		t.Errorf("another folder: %+v, want nothing agreed and still restored", it)
	}
	if got, err := a.SyncFolderID(); err != nil || got != "f2" {
		t.Errorf("SyncFolderID = %q, %v", got, err)
	}
}

// A vault with nothing left but what it agreed (every entry deleted for
// good while it was away) rejoins its folder, keeping those deletions; one
// restored from a backup made before it synced, every entry marked
// restored, joins with its entries.
func TestJoinVault_Rejoins(t *testing.T) {
	a, _ := syncPair(t)
	if err := a.SyncStartFolder("f1"); err != nil {
		t.Fatal(err)
	}
	k := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	uid := uidOf(t, a, k)
	rec, rev, err := a.SyncRecord(uid, "x")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.SyncAgree(uid, rev, rec, syncfolder.Hash{1}); err != nil {
		t.Fatal(err)
	}
	all, err := a.List(&vault.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	var keys []vault.Key
	for _, e := range all {
		keys = append(keys, e.Key)
	}
	if err := a.PurgeMany(keys); err != nil {
		t.Fatal(err)
	}
	path := a.Path()
	m, err := ReadUnlockMaterial(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CanJoin(path, mustOtherKey(t), "f1"); !errors.Is(err, ErrRejoinOtherKey) {
		t.Errorf("all deleted, the folder's key another: %v; want it switched, not joined afresh", err)
	}
	if rejoin, err := JoinVault(path, m, "f1", nil); err != nil || !rejoin {
		t.Fatalf("all deleted: %v, %v; want it rejoining", rejoin, err)
	}
	if it := syncItem(t, a, uid); it.Agreed == nil {
		t.Error("the deletion it agreed was forgotten")
	}

	b, _ := syncPair(t)
	if _, err := b.db.Exec(`INSERT INTO sync_restored (uid, rev) SELECT uid, rev FROM entries`); err != nil {
		t.Fatal(err)
	}
	mb, err := ReadUnlockMaterial(b.Path())
	if err != nil {
		t.Fatal(err)
	}
	if rejoin, err := CanJoin(b.Path(), mb, "f1"); err != nil || !rejoin {
		t.Errorf("restored before it synced: %v, %v; want it joining", rejoin, err)
	}
	if _, err := b.db.Exec(`DELETE FROM sync_restored`); err != nil {
		t.Fatal(err)
	}
	if _, err := CanJoin(b.Path(), mb, "f1"); !errors.Is(err, ErrVaultNotEmpty) {
		t.Errorf("not restored, never synced: %v, want ErrVaultNotEmpty", err)
	}
}

// A password change made here is kept as one to send, the key the folder
// has remembered across a second change; taking the folder's drops it.
func TestRekey_SyncChange(t *testing.T) {
	p, s := rekeyVault(t)
	if err := s.SyncStartFolder("f1"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.SyncKeyChange(); err != nil || got != "" {
		t.Fatalf("before: %q, %v", got, err)
	}
	folderID := vaultID(t, p)
	key, rec := newKeyFor(t, "new-password-1")
	if _, err := s.Rekey(key, rec, rewrapTo, RekeyOptions{Sync: RekeySend}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.SyncKeyChange(); err != nil || got != folderID {
		t.Errorf("after a change here: %q, %v; want the folder's key %q", got, err, folderID)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(p, NewKeySourceOracle(NewMasterPasswordSource(p, staticPrompt("new-password-1"))))
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close() //nolint:errcheck // test
	key2, rec2 := newKeyFor(t, "new-password-2")
	if _, err := s2.Rekey(key2, rec2, rewrapTo, RekeyOptions{Sync: RekeySend}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s2.SyncKeyChange(); got != folderID { //nolint:errcheck // compared
		t.Errorf("after a second change: %q; want the folder's key still", got)
	}
	s3, err := Open(p, NewKeySourceOracle(NewMasterPasswordSource(p, staticPrompt("new-password-2"))))
	if err != nil {
		t.Fatal(err)
	}
	defer s3.Close() //nolint:errcheck // test
	key3, rec3 := newKeyFor(t, "new-password-3")
	if _, err := s3.Rekey(key3, rec3, rewrapTo, RekeyOptions{Sync: RekeyAdopt}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s3.SyncKeyChange(); got != "" { //nolint:errcheck // compared
		t.Errorf("after taking the folder's: %q; want none to send", got)
	}
}
