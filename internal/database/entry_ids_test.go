package database

import (
	"encoding/hex"
	"testing"

	"github.com/bashhack/sesh/internal/vault"
)

// idOf is the uid and rev of the live entry k.
func idOf(t *testing.T, s *Store, k vault.Key) (uid string, rev int64) {
	t.Helper()
	if err := s.db.QueryRow(`SELECT uid, rev FROM entries WHERE kind = ? AND service = ? AND username = ?`,
		string(k.Kind), k.Service, k.Username).Scan(&uid, &rev); err != nil {
		t.Fatalf("%s: %v", k, err)
	}
	return uid, rev
}

// quietEmpty fails t unless quiet_writes is empty, as outside a write.
func quietEmpty(t *testing.T, s *Store) {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM quiet_writes`).Scan(&n); err != nil || n != 0 {
		t.Errorf("quiet_writes holds %d rows, %v; want none outside a write", n, err)
	}
}

// An entry's uid is random, made with it, and kept through an overwrite, a
// rename, the trash and back (under another name too).
func TestEntryIDs_KeptThroughChanges(t *testing.T) {
	s := newTestStore(t)
	s.SetTrashDays(30)
	gh := vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}
	if err := s.Put(gh, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(vault.Key{Kind: vault.KindPassword, Service: "gitlab"}, []byte("x")); err != nil {
		t.Fatal(err)
	}
	uid, _ := idOf(t, s, gh)
	if b, err := hex.DecodeString(uid); err != nil || len(b) != 16 {
		t.Fatalf("uid %q: want 16 random bytes in hex", uid)
	}
	if other, _ := idOf(t, s, vault.Key{Kind: vault.KindPassword, Service: "gitlab"}); other == uid {
		t.Fatal("two entries share a uid")
	}
	same := func(what string, k vault.Key) {
		t.Helper()
		if got, _ := idOf(t, s, k); got != uid {
			t.Errorf("after %s: uid %q, want %q", what, got, uid)
		}
	}
	if err := s.Put(gh, []byte("two")); err != nil {
		t.Fatal(err)
	}
	same("an overwrite", gh)
	renamed := vault.Key{Kind: vault.KindPassword, Service: "github-work", Username: "alice"}
	if _, err := s.Edit(gh, EntryEdit{To: &renamed}); err != nil {
		t.Fatal(err)
	}
	same("a rename", renamed)
	restore := func(as vault.Key) {
		t.Helper()
		if err := s.Delete(renamed); err != nil {
			t.Fatal(err)
		}
		var trashed string
		if err := s.db.QueryRow(`SELECT uid FROM trash`).Scan(&trashed); err != nil || trashed != uid {
			t.Fatalf("in the trash: uid %q, %v; want %q", trashed, err, uid)
		}
		items, err := s.Trash()
		if err != nil || len(items) != 1 {
			t.Fatalf("trash: %v, %v", items, err)
		}
		if _, err := s.RestoreFromTrash(items[0].ID, as); err != nil {
			t.Fatal(err)
		}
	}
	restore(vault.Key{})
	same("the trash and back", renamed)
	elsewhere := vault.Key{Kind: vault.KindPassword, Service: "github-old", Username: "alice"}
	restore(elsewhere)
	same("the trash and back under another name", elsewhere)
}

// Every kind of change to an entry raises its rev: its secret, details,
// settings, name, folder, tags, the trash and back, and forgetting or
// restoring an earlier secret.
func TestEntryRev_EveryChange(t *testing.T) {
	s := newTestStore(t)
	s.SetTrashDays(30)
	s.SetHistoryKeep(10)
	k := vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}
	code := vault.Key{Kind: vault.KindTOTP, Service: "github", Username: "alice"}
	if err := s.Put(k, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(code, []byte("JBSWY3DPEHPK3PXP")); err != nil {
		t.Fatal(err)
	}
	folder, tags := "work", []string{"a", "b"}
	digits := vault.Settings{}
	digits.TOTP.Digits = 8
	for _, step := range []struct {
		do   func() error
		name string
		key  vault.Key
	}{
		{name: "a new secret", do: func() error { return s.Put(k, []byte("two")) }},
		{name: "another, kept in history", do: func() error { return s.Put(k, []byte("three")) }},
		{name: "save with details", do: func() error {
			return s.SaveWithDetails(&vault.Entry{Key: k}, []byte("four"), &vault.Details{URL: "https://github.com"})
		}},
		{name: "details", do: func() error { return s.SetDetails(k, &vault.Details{URL: "https://github.com", Notes: []byte("n")}) }},
		{name: "settings", key: code, do: func() error { return s.SetSettings(code, &digits) }},
		{name: "edit: folder", do: func() error { _, err := s.Edit(k, EntryEdit{Folder: &folder}); return err }},
		{name: "edit: tags", do: func() error { _, err := s.Edit(k, EntryEdit{Tags: &tags}); return err }},
		{name: "move to a folder", do: func() error { _, err := s.MoveToFolder([]vault.Key{k}, "home"); return err }},
		{name: "rename the folder", do: func() error { _, _, err := s.RenameFolder("home", "house"); return err }},
		{name: "add a tag", do: func() error { _, err := s.AddTag([]vault.Key{k}, "c"); return err }},
		{name: "rename a tag", do: func() error { _, _, err := s.RenameTag("c", "d"); return err }},
		{name: "remove a tag", do: func() error { _, err := s.RemoveTag([]vault.Key{k}, "d"); return err }},
		{name: "restore an earlier secret", do: func() error { _, err := s.RestoreVersion(k, 2); return err }},
		{name: "forget an earlier secret", do: func() error { return s.ForgetVersions(k, 2) }},
		{name: "forget another, by version", do: func() error {
			v, err := s.History(k)
			if err != nil {
				return err
			}
			return s.ForgetVersionOf(k, v[0])
		}},
	} {
		key := k
		if step.key != (vault.Key{}) {
			key = step.key
		}
		_, before := idOf(t, s, key)
		if err := step.do(); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		if _, after := idOf(t, s, key); after <= before {
			t.Errorf("%s: rev %d, then %d; want it raised", step.name, before, after)
		}
	}
	_, before := idOf(t, s, k)
	if err := s.Delete(k); err != nil {
		t.Fatal(err)
	}
	var trashed int64
	if err := s.db.QueryRow(`SELECT rev FROM trash`).Scan(&trashed); err != nil || trashed <= before {
		t.Errorf("into the trash: rev %d, then %d (%v); want it raised", before, trashed, err)
	}
	items, err := s.Trash()
	if err != nil || len(items) != 1 {
		t.Fatalf("trash: %v, %v", items, err)
	}
	if _, err := s.RestoreFromTrash(items[0].ID, vault.Key{}); err != nil {
		t.Fatal(err)
	}
	if _, back := idOf(t, s, k); back <= trashed {
		t.Errorf("out of the trash: rev %d, then %d; want it raised", trashed, back)
	}
	quietEmpty(t, s)
}

// Writes that change how entries are kept, not what they hold, leave their
// rev: a new master password, trimming history to history.keep, a restore
// from a backup. A change after them still counts.
func TestEntryRev_QuietWrites(t *testing.T) {
	p, s := rekeyVault(t)
	s.SetHistoryKeep(10)
	bank := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	for _, secret := range []string{"b2", "b3", "b4"} {
		if err := s.Put(bank, []byte(secret)); err != nil {
			t.Fatal(err)
		}
	}
	// A tag, so a restore that counted its writes would raise the rev.
	if _, err := s.AddTag([]vault.Key{bank}, "money"); err != nil {
		t.Fatal(err)
	}
	uid, rev := idOf(t, s, bank)
	unchanged := func(what string) {
		t.Helper()
		if gotUID, got := idOf(t, s, bank); gotUID != uid || got != rev {
			t.Errorf("after %s: uid %q rev %d, want %q rev %d", what, gotUID, got, uid, rev)
		}
		quietEmpty(t, s)
	}
	if n, err := s.PruneHistory(1); err != nil || n != 2 {
		t.Fatalf("PruneHistory: %d, %v", n, err)
	}
	unchanged("trimming history")
	b := backupOf(t, p)
	if err := s.Put(bank, []byte("b5")); err != nil {
		t.Fatal(err)
	}
	if err := RestoreInPlace(p, b); err != nil {
		t.Fatal(err)
	}
	unchanged("a restore")
	if err := s.Put(bank, []byte("b6")); err != nil {
		t.Fatal(err)
	}
	if _, after := idOf(t, s, bank); after <= rev {
		t.Errorf("a change after them: rev %d, then %d; want it raised", rev, after)
	}
	_, rev = idOf(t, s, bank)
	key, rec := newKeyFor(t, "new-password-1")
	if _, err := s.Rekey(key, rec, rewrapTo); err != nil {
		t.Fatal(err)
	}
	unchanged("a new master password")
}
