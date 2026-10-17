package database

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/vault"
)

// trashVault is a store that keeps deleted entries 30 days, holding
// password/github/alice with a note and two tags, in folder work.
func trashVault(t *testing.T) (*Store, vault.Key) {
	t.Helper()
	s := newTestStore(t)
	s.SetTrashDays(30)
	k := vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}
	d := vault.Details{URL: "https://github.com", Notes: []byte("main account"), Fields: []vault.Field{{Name: "pin", Value: []byte("4321"), Secret: true}}}
	if err := s.SaveWithDetails(&vault.Entry{Key: k, Folder: "work", Tags: []string{"code", "urgent"}}, []byte("gh-pw"), &d); err != nil {
		t.Fatal(err)
	}
	return s, k
}

// Deleting moves an entry to the trash, out of sight, and restoring brings
// it back as it was: secret, details, folder, tags and times.
func TestTrash_DeleteAndRestore(t *testing.T) {
	s, k := trashVault(t)
	before, err := s.Lookup(k)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(k); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(k); !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("Get after delete: %v", err)
	}
	if all, err := s.List(&vault.Filter{}); err != nil || len(all) != 0 {
		t.Errorf("List after delete = %v, %v", all, err)
	}
	trashed, err := s.Trash()
	if err != nil || len(trashed) != 1 || trashed[0].Key != k || trashed[0].Folder != "work" || strings.Join(trashed[0].Tags, ",") != "code,urgent" ||
		time.Since(trashed[0].DeletedAt) > time.Minute {
		t.Fatalf("Trash = %+v, %v", trashed, err)
	}
	got, err := s.RestoreFromTrash(trashed[0].ID, vault.Key{})
	if err != nil || got.Key != k || got.TagsLost {
		t.Fatalf("restore = %v, %v", got, err)
	}
	after, err := s.Lookup(k)
	if err != nil || after.Folder != "work" || strings.Join(after.Tags, ",") != "code,urgent" || !after.CreatedAt.Equal(before.CreatedAt) || !after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Errorf("restored = %+v, %v; was %+v", after, err, before)
	}
	if secret, err := s.Get(k); err != nil || string(secret) != "gh-pw" {
		t.Errorf("secret = %q, %v", secret, err)
	}
	if d, err := s.Details(k, "all"); err != nil || string(d.Notes) != "main account" || string(d.Fields[0].Value) != "4321" {
		t.Errorf("details = %+v, %v", d, err)
	}
	if trashed, err := s.Trash(); err != nil || len(trashed) != 0 {
		t.Errorf("Trash after restore = %+v, %v", trashed, err)
	}
}

// Restoring onto a name in use is refused; --as restores it under another
// of the same kind, its secret and details sealed for that name.
func TestTrash_RestoreClashAndAs(t *testing.T) {
	s, k := trashVault(t)
	if err := s.Delete(k); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(k, []byte("new-pw")); err != nil {
		t.Fatal(err)
	}
	trashed, err := s.Trash()
	if err != nil {
		t.Fatal(err)
	}
	id := trashed[0].ID
	if _, err := s.RestoreFromTrash(id, vault.Key{}); !errors.Is(err, ErrNameTaken) || err.Error() != "password/github/alice already exists: rename or delete it first, or restore with --as <new name>" {
		t.Errorf("onto a name in use: %v", err)
	}
	if _, err := s.RestoreFromTrash(id, vault.Key{Kind: vault.KindNote, Service: "github"}); err == nil || !strings.Contains(err.Error(), "only under an ID that starts password/") {
		t.Errorf("as another kind: %v", err)
	}
	if _, err := s.RestoreFromTrash(id, k); !errors.Is(err, ErrNameTaken) || err.Error() != "password/github/alice already exists: rename or delete it first, or restore under another name" {
		t.Errorf("--as a name in use: %v", err)
	}
	as := vault.Key{Kind: vault.KindPassword, Service: "github-old", Username: "alice"}
	if got, err := s.RestoreFromTrash(id, as); err != nil || got.Key != as {
		t.Fatalf("restore --as = %v, %v", got, err)
	}
	if secret, err := s.Get(as); err != nil || string(secret) != "gh-pw" {
		t.Errorf("restored secret = %q, %v", secret, err)
	}
	if d, err := s.Details(as, "all"); err != nil || string(d.Notes) != "main account" {
		t.Errorf("restored details = %+v, %v", d, err)
	}
	if secret, err := s.Get(k); err != nil || string(secret) != "new-pw" {
		t.Errorf("the entry in the way = %q, %v", secret, err)
	}
	if _, err := s.RestoreFromTrash(id, vault.Key{}); !errors.Is(err, ErrNotInTrash) {
		t.Errorf("restoring twice: %v", err)
	}
}

// Removing one, emptying, expiring and purging delete for good; a store
// keeping no trash deletes for good too.
func TestTrash_RemoveEmptyExpirePurge(t *testing.T) {
	s, k := trashVault(t)
	other := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	third := vault.Key{Kind: vault.KindPassword, Service: "mail"}
	for _, key := range []vault.Key{other, third} {
		if err := s.Put(key, []byte("pw")); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DeleteMany([]vault.Key{k, other, third}); err != nil {
		t.Fatal(err)
	}
	trashed, err := s.Trash()
	if err != nil || len(trashed) != 3 {
		t.Fatalf("Trash = %+v, %v", trashed, err)
	}
	if got, err := s.RemoveFromTrash(trashed[0].ID); err != nil || len(got) != 1 || got[0] != trashed[0].Key {
		t.Errorf("remove = %v, %v", got, err)
	}
	if _, err := s.RemoveFromTrash(trashed[0].ID); !errors.Is(err, ErrNotInTrash) {
		t.Errorf("remove twice: %v", err)
	}
	if n, err := s.ExpireTrash(time.Now().Add(-time.Hour)); err != nil || n != 0 {
		t.Errorf("expire nothing yet = %d, %v", n, err)
	}
	if n, err := s.ExpireTrash(time.Now().Add(time.Hour)); err != nil || n != 2 {
		t.Errorf("expire = %d, %v", n, err)
	}
	if err := s.Put(k, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	if err := s.PurgeMany([]vault.Key{k}); err != nil {
		t.Fatal(err)
	}
	if trashed, err := s.Trash(); err != nil || len(trashed) != 0 {
		t.Errorf("Trash after purge = %+v, %v", trashed, err)
	}
	if err := s.Put(k, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(k); err != nil {
		t.Fatal(err)
	}
	if n, err := s.EmptyTrash(); err != nil || n != 1 {
		t.Errorf("empty = %d, %v", n, err)
	}
	s.SetTrashDays(0)
	if err := s.Put(k, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(k); err != nil {
		t.Fatal(err)
	}
	if trashed, err := s.Trash(); err != nil || len(trashed) != 0 {
		t.Errorf("Trash with none kept = %+v, %v", trashed, err)
	}
	events, err := s.AuditEvents(0)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, e := range events {
		if e.EventType == "delete" || e.EventType == "trash" || e.EventType == "purge" {
			kinds = append(kinds, e.EventType+": "+e.Detail)
		}
	}
	for _, want := range []string{"trash: Moved to the trash", "purge: Removed from the trash", "purge: Kept its days in the trash", "delete: Delete", "purge: Trash emptied"} {
		if !strings.Contains(strings.Join(kinds, "\n"), want) {
			t.Errorf("audit missing %q in %q", want, kinds)
		}
	}
}

// What's removed from the trash leaves no trace in the file.
func TestTrash_RemoveLeavesNoTrace(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(dbPath, &mockKeySource{key: bytes.Repeat([]byte{0xAB}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	s.SetTrashDays(30)
	k := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	if err := s.Put(k, []byte("bank-password")); err != nil {
		t.Fatal(err)
	}
	var sealed []byte
	if err := s.db.QueryRow(`SELECT encrypted_data FROM entries`).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(k); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EmptyTrash(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, sealed) {
		t.Error("the removed entry's encrypted secret is still in the vault file")
	}
}

// A new master password re-encrypts the trash too: what's in it restores
// and reads afterwards. Verify checks it.
func TestTrash_RekeyAndVerify(t *testing.T) {
	p, s := rekeyVault(t)
	s.SetTrashDays(30)
	k := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	if err := s.Delete(k); err != nil {
		t.Fatal(err)
	}
	r, err := s.Verify()
	if err != nil || r.Entries != 0 || r.Trashed != 1 || len(r.TrashProblems) != 0 {
		t.Fatalf("Verify = %+v, %v", r, err)
	}
	key, rec := newKeyFor(t, "new-password-1")
	if res, err := s.Rekey(key, rec, rewrapTo, RekeyOptions{}); err != nil || res.Entries != 0 || res.Trashed != 1 {
		t.Fatalf("Rekey = %+v, %v", res, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(p, NewKeySourceOracle(NewMasterPasswordSource(p, staticPrompt("new-password-1"))))
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close() //nolint:errcheck // test cleanup
	trashed, err := s2.Trash()
	if err != nil || len(trashed) != 1 {
		t.Fatalf("Trash = %+v, %v", trashed, err)
	}
	if _, err := s2.RestoreFromTrash(trashed[0].ID, vault.Key{Kind: vault.KindPassword, Service: "bank-2"}); err != nil {
		t.Fatal(err)
	}
	if secret, err := s2.Get(vault.Key{Kind: vault.KindPassword, Service: "bank-2"}); err != nil || string(secret) != "bank-secret" {
		t.Errorf("after the new password, restored secret = %q, %v", secret, err)
	}
}

// An entry in the trash that doesn't decrypt is a trash problem, with its
// trash id.
func TestTrash_VerifyFindsDamage(t *testing.T) {
	_, s := rekeyVault(t)
	s.SetTrashDays(30)
	k := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	if err := s.Delete(k); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE trash SET encrypted_data = x'00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'`); err != nil {
		t.Fatal(err)
	}
	r, err := s.Verify()
	if err != nil || len(r.Problems) != 0 || len(r.TrashProblems) != 1 || r.TrashProblems[0].Key != k || r.TrashProblems[0].TrashID == 0 || r.TrashProblems[0].Kind != ProblemSecret {
		t.Errorf("Verify = %+v, %v", r, err)
	}
}

// A trash row whose times or tags are damaged still lists, is named by
// Verify, and can be removed, alone or by emptying; removing is all or
// none, and an id named twice is removed once.
func TestTrash_DamagedRow(t *testing.T) {
	_, s := rekeyVault(t)
	s.SetTrashDays(30)
	for _, svc := range []string{"a", "b", "c"} {
		if err := s.Put(vault.Key{Kind: vault.KindPassword, Service: svc}, []byte("pw")); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DeleteMany([]vault.Key{{Kind: vault.KindPassword, Service: "bank"}, {Kind: vault.KindPassword, Service: "a"}, {Kind: vault.KindPassword, Service: "b"}, {Kind: vault.KindPassword, Service: "c"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE trash SET created_at = 'garbage' WHERE service = 'a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE trash SET tags = 'nope', deleted_at = 'garbage' WHERE service = 'b'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE trash SET tags = 'nope' WHERE service = 'bank'`); err != nil {
		t.Fatal(err)
	}
	trashed, err := s.Trash()
	if err != nil || len(trashed) != 4 {
		t.Fatalf("Trash = %+v, %v", trashed, err)
	}
	ids := map[string]int64{}
	for i := range trashed {
		ids[trashed[i].Service] = trashed[i].ID
	}
	r, err := s.Verify()
	var problems []string
	for _, p := range r.TrashProblems {
		problems = append(problems, p.Key.Service+":"+problemName(p.Kind))
	}
	if err != nil || strings.Join(problems, " ") != "a:times b:times bank:tags" {
		t.Errorf("Verify trash problems = %v, %v", problems, err)
	}
	if _, err := s.RemoveFromTrash(ids["a"], ids["a"], 999); !errors.Is(err, ErrNotInTrash) {
		t.Errorf("remove with an id not in the trash: %v", err)
	}
	if trashed, err := s.Trash(); err != nil || len(trashed) != 4 {
		t.Errorf("a remove that failed removed some: %d left, %v", len(trashed), err)
	}
	if gone, err := s.RemoveFromTrash(ids["a"], ids["a"], ids["c"]); err != nil || len(gone) != 2 {
		t.Errorf("remove = %v, %v", gone, err)
	}
	if n, err := s.EmptyTrash(); err != nil || n != 2 {
		t.Errorf("empty = %d, %v", n, err)
	}
}

func problemName(k ProblemKind) string {
	switch k {
	case ProblemTimes:
		return "times"
	case ProblemTags:
		return "tags"
	case ProblemSecret:
		return "secret"
	}
	return "other"
}

// A new master password stops at an entry in the trash that doesn't
// decrypt, and says it's in the trash, with how to remove it.
func TestTrash_RekeyNamesDamagedTrash(t *testing.T) {
	_, s := rekeyVault(t)
	s.SetTrashDays(30)
	if err := s.Delete(vault.Key{Kind: vault.KindPassword, Service: "bank"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE trash SET encrypted_data = x'00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'`); err != nil {
		t.Fatal(err)
	}
	key, rec := newKeyFor(t, "new-password-1")
	_, err := s.Rekey(key, rec, rewrapTo, RekeyOptions{})
	if err == nil || !strings.Contains(err.Error(), "decrypt password/bank") || !strings.Contains(err.Error(), "it's in the trash, id 1: sesh trash remove 1 deletes it for good") {
		t.Errorf("Rekey = %v", err)
	}
}

// An entry whose tags were damaged in the trash restores without them, and
// says so.
func TestTrash_RestoreWithDamagedTags(t *testing.T) {
	s, k := trashVault(t)
	if err := s.Delete(k); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE trash SET tags = 'nope'`); err != nil {
		t.Fatal(err)
	}
	trashed, err := s.Trash()
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.RestoreFromTrash(trashed[0].ID, vault.Key{})
	if err != nil || got.Key != k || !got.TagsLost {
		t.Fatalf("restore = %+v, %v", got, err)
	}
	if e, err := s.Lookup(k); err != nil || len(e.Tags) != 0 || e.Folder != "work" {
		t.Errorf("restored = %+v, %v", e, err)
	}
}
