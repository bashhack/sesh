package database

import (
	"errors"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/vault"
)

// versions is k's history as its secrets, newest first.
func versions(t *testing.T, s *Store, k vault.Key) []string {
	t.Helper()
	vs, err := s.History(k)
	if err != nil {
		t.Fatalf("History(%s): %v", k, err)
	}
	var out []string
	for i := range vs {
		secret, err := s.ReadVersion(k, i+2, "test")
		if err != nil {
			t.Fatalf("ReadVersion(%s, %d): %v", k, i+2, err)
		}
		out = append(out, string(secret))
	}
	return out
}

func historyStore(t *testing.T, keep int) *Store {
	t.Helper()
	s := newTestStore(t)
	s.SetHistoryKeep(keep)
	s.SetTrashDays(30)
	return s
}

// Storing a new secret keeps the one it replaces; storing the same one
// again keeps nothing; only history.keep are kept, the newest.
func TestHistory_KeepsReplacedSecrets(t *testing.T) {
	s := historyStore(t, 3)
	k := vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}
	for _, pw := range []string{"one", "two", "two", "three"} {
		if err := s.Put(k, []byte(pw)); err != nil {
			t.Fatal(err)
		}
	}
	if got := strings.Join(versions(t, s, k), " "); got != "two one" {
		t.Errorf("history = %q, want two one", got)
	}
	for _, pw := range []string{"four", "five"} {
		if err := s.Put(k, []byte(pw)); err != nil {
			t.Fatal(err)
		}
	}
	if got := strings.Join(versions(t, s, k), " "); got != "four three two" {
		t.Errorf("history = %q, want the newest 3", got)
	}
	if _, err := s.ReadVersion(k, 5, "test"); !errors.Is(err, ErrNoVersion) || !strings.Contains(err.Error(), "versions 1 (the current secret) to 4") {
		t.Errorf("a version past the end: %v", err)
	}
	none := historyStore(t, 0)
	for _, pw := range []string{"one", "two"} {
		if err := none.Put(k, []byte(pw)); err != nil {
			t.Fatal(err)
		}
	}
	if got := versions(t, none, k); len(got) != 0 {
		t.Errorf("history with none kept = %q", got)
	}
}

// Editing the secret keeps the old one; renaming takes the history along,
// sealed for the new name.
func TestHistory_EditAndRename(t *testing.T) {
	s := historyStore(t, 10)
	k := vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}
	if err := s.Put(k, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Edit(k, EntryEdit{Secret: []byte("two")}); err != nil {
		t.Fatal(err)
	}
	to := vault.Key{Kind: vault.KindPassword, Service: "gh", Username: "alice"}
	if _, err := s.Edit(k, EntryEdit{To: &to, Secret: []byte("three")}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(versions(t, s, to), " "); got != "two one" {
		t.Errorf("history after rename = %q", got)
	}
	if err := s.Put(k, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if got := versions(t, s, k); len(got) != 0 {
		t.Errorf("a new entry under the old name has history %q", got)
	}
}

// Restoring a version makes it the secret, the replaced one going into the
// history; forgetting one deletes it.
func TestHistory_RestoreAndForget(t *testing.T) {
	s := historyStore(t, 10)
	k := vault.Key{Kind: vault.KindAPIKey, Service: "openai"}
	for _, pw := range []string{"one", "two", "three"} {
		if err := s.Put(k, []byte(pw)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.RestoreVersion(k, 3); err != nil {
		t.Fatal(err)
	}
	if secret, err := s.Get(k); err != nil || string(secret) != "one" {
		t.Errorf("current = %q, %v", secret, err)
	}
	if got := strings.Join(versions(t, s, k), " "); got != "three two one" {
		t.Errorf("history after restore = %q", got)
	}
	if err := s.ForgetVersions(k, 4); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(versions(t, s, k), " "); got != "three two" {
		t.Errorf("history after forget = %q", got)
	}
}

// The history goes into the trash with its entry, comes back with it
// (under a new name too), and goes for good with it.
func TestHistory_ThroughTheTrash(t *testing.T) {
	s := historyStore(t, 10)
	k := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	for _, pw := range []string{"one", "two"} {
		if err := s.Put(k, []byte(pw)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Delete(k); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(k, []byte("other")); err != nil {
		t.Fatal(err)
	}
	if got := versions(t, s, k); len(got) != 0 {
		t.Errorf("a new entry with a trashed one's name has history %q", got)
	}
	trashed, err := s.Trash()
	if err != nil {
		t.Fatal(err)
	}
	as := vault.Key{Kind: vault.KindPassword, Service: "bank-old"}
	if _, err := s.RestoreFromTrash(trashed[0].ID, as); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(versions(t, s, as), " "); got != "one" {
		t.Errorf("history restored under a new name = %q", got)
	}
	if err := s.Delete(as); err != nil {
		t.Fatal(err)
	}
	trashed, err = s.Trash()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RestoreFromTrash(trashed[0].ID, vault.Key{}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(versions(t, s, as), " "); got != "one" {
		t.Errorf("history restored = %q", got)
	}
	if err := s.Delete(as); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EmptyTrash(); err != nil {
		t.Fatal(err)
	}
	if err := s.PurgeMany([]vault.Key{k}); err != nil {
		t.Fatal(err)
	}
	var left int
	if err := s.db.QueryRow(`SELECT count(*) FROM history`).Scan(&left); err != nil || left != 0 {
		t.Errorf("history left after deleting for good: %d, %v", left, err)
	}
}

// A new master password re-seals the history; Verify counts it and names
// an earlier secret that doesn't decrypt by its version.
func TestHistory_RekeyAndVerify(t *testing.T) {
	p, s := rekeyVault(t)
	s.SetHistoryKeep(10)
	k := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	if err := s.Put(k, []byte("bank-secret-2")); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(k, []byte("bank-secret")); err != nil {
		t.Fatal(err)
	}
	r, err := s.Verify()
	if err != nil || r.History != 2 || len(r.HistoryProblems) != 0 {
		t.Fatalf("Verify = %+v, %v", r, err)
	}
	key, rec := newKeyFor(t, "new-password-1")
	if _, err := s.Rekey(key, rec, rewrapTo); err != nil {
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
	if got := strings.Join(versions(t, s2, k), " "); got != "bank-secret-2 bank-secret" {
		t.Errorf("history after a new password = %q", got)
	}
	if _, err := s2.db.Exec(`UPDATE history SET encrypted_data = x'00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff' WHERE id = (SELECT min(id) FROM history)`); err != nil {
		t.Fatal(err)
	}
	r, err = s2.Verify()
	if err != nil || len(r.HistoryProblems) != 1 || r.HistoryProblems[0].Key != k || r.HistoryProblems[0].Version != 3 || r.HistoryProblems[0].Kind != ProblemSecret {
		t.Errorf("Verify = %+v, %v", r.HistoryProblems, err)
	}
}

// Storing over an entry whose secret doesn't decrypt works, as it does
// with no history: the damaged secret isn't kept.
func TestHistory_StoreOverDamagedEntry(t *testing.T) {
	s := historyStore(t, 10)
	k := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	if err := s.Put(k, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE entries SET encrypted_data = x'00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'`); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(k, []byte("two")); err != nil {
		t.Fatalf("store over a damaged entry: %v", err)
	}
	if _, err := s.Edit(k, EntryEdit{Secret: []byte("three")}); err != nil {
		t.Fatalf("edit after: %v", err)
	}
	if got := strings.Join(versions(t, s, k), " "); got != "two" {
		t.Errorf("history = %q, want only the readable one", got)
	}
}

// Forgetting several versions resolves them all first, so the numbers
// doctor printed delete what they named.
func TestHistory_ForgetSeveral(t *testing.T) {
	s := historyStore(t, 10)
	k := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	for _, pw := range []string{"a", "b", "c", "d", "e", "f"} {
		if err := s.Put(k, []byte(pw)); err != nil {
			t.Fatal(err)
		}
	}
	// Versions: 2 e, 3 d, 4 c, 5 b, 6 a.
	if err := s.ForgetVersions(k, 3, 5); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(versions(t, s, k), " "); got != "e c a" {
		t.Errorf("history = %q, want e c a", got)
	}
	if err := s.ForgetVersions(k, 2, 9); !errors.Is(err, ErrNoVersion) {
		t.Errorf("a version past the end: %v", err)
	}
	if got := strings.Join(versions(t, s, k), " "); got != "e c a" {
		t.Errorf("a forget that failed forgot some: %q", got)
	}
}

// Pruning keeps the newest of each entry's history, live or in the trash;
// 0 keeps none.
func TestHistory_Prune(t *testing.T) {
	s := historyStore(t, 10)
	k := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	gone := vault.Key{Kind: vault.KindPassword, Service: "old"}
	for _, pw := range []string{"a", "b", "c", "d"} {
		for _, key := range []vault.Key{k, gone} {
			if err := s.Put(key, []byte(pw)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := s.Delete(gone); err != nil {
		t.Fatal(err)
	}
	if n, err := s.PruneHistory(2); err != nil || n != 2 {
		t.Errorf("prune to 2 = %d, %v", n, err)
	}
	if got := strings.Join(versions(t, s, k), " "); got != "c b" {
		t.Errorf("history = %q", got)
	}
	var trashed int
	if err := s.db.QueryRow(`SELECT count(*) FROM history WHERE trash_id IS NOT NULL`).Scan(&trashed); err != nil || trashed != 2 {
		t.Errorf("trashed entry's history = %d, %v", trashed, err)
	}
	if n, err := s.PruneHistory(0); err != nil || n != 4 {
		t.Errorf("prune to 0 = %d, %v", n, err)
	}
}

// Restoring a version says whether the secret it replaced was kept.
func TestHistory_RestoreSaysWhatWasKept(t *testing.T) {
	s := historyStore(t, 10)
	k := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	for _, pw := range []string{"a", "b"} {
		if err := s.Put(k, []byte(pw)); err != nil {
			t.Fatal(err)
		}
	}
	if kept, err := s.RestoreVersion(k, 2); err != nil || !kept {
		t.Errorf("restore = %v, %v", kept, err)
	}
	s.SetHistoryKeep(0)
	if kept, err := s.RestoreVersion(k, 2); err != nil || kept {
		t.Errorf("restore with none kept = %v, %v", kept, err)
	}
}

// A damaged earlier secret stops a rename, naming its version and the
// command that forgets it.
func TestHistory_DamagedVersionStopsRename(t *testing.T) {
	s := historyStore(t, 10)
	k := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	for _, pw := range []string{"a", "b", "c"} {
		if err := s.Put(k, []byte(pw)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec(`UPDATE history SET encrypted_data = x'00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff' WHERE id = (SELECT min(id) FROM history)`); err != nil {
		t.Fatal(err)
	}
	to := vault.Key{Kind: vault.KindPassword, Service: "bank-2"}
	if _, err := s.Edit(k, EntryEdit{To: &to}); err == nil || !strings.Contains(err.Error(), "version 3") || !strings.Contains(err.Error(), "sesh history password/bank --forget 3") {
		t.Errorf("rename = %v", err)
	}
}

// changingOracle runs change before its first encryption, as another sesh
// command writing meanwhile would.
type changingOracle struct {
	CryptoOracle
	change func()
}

func (o *changingOracle) EncryptEntry(plain, aad []byte) ([]byte, []byte, error) {
	if c := o.change; c != nil {
		o.change = nil
		c()
	}
	return o.CryptoOracle.EncryptEntry(plain, aad)
}

// A store that another command's store lands in the middle of is refused,
// whether the entry was there before or not, so that one's secret isn't
// replaced without being kept.
func TestHistory_ConcurrentStore(t *testing.T) {
	for name, before := range map[string]bool{"new entry": false, "existing entry": true} {
		t.Run(name, func(t *testing.T) {
			s := historyStore(t, 10)
			k := vault.Key{Kind: vault.KindPassword, Service: "bank"}
			if before {
				if err := s.Put(k, []byte("mine")); err != nil {
					t.Fatal(err)
				}
			}
			o := &changingOracle{CryptoOracle: s.oracle}
			o.change = func() {
				data, salt, err := o.CryptoOracle.EncryptEntry([]byte("theirs"), entryAAD(k))
				if err == nil {
					_, err = s.db.Exec(`INSERT INTO entries (kind, service, username, encrypted_data, salt, created_at, updated_at) VALUES ('password', 'bank', '', ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
						ON CONFLICT (kind, service, username) DO UPDATE SET encrypted_data = excluded.encrypted_data, salt = excluded.salt`, data, salt)
				}
				if err != nil {
					t.Error(err)
				}
			}
			s.oracle = o
			if err := s.Put(k, []byte("mine")); !errors.Is(err, ErrEntryChanged) {
				t.Errorf("store across another's = %v", err)
			}
		})
	}
}

// A new master password stops at an earlier secret that doesn't decrypt,
// naming its version and the command that forgets it.
func TestHistory_RekeyNamesDamagedVersion(t *testing.T) {
	_, s := rekeyVault(t)
	s.SetHistoryKeep(10)
	k := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	if err := s.Put(k, []byte("newer")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE history SET encrypted_data = x'00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'`); err != nil {
		t.Fatal(err)
	}
	key, rec := newKeyFor(t, "new-password-1")
	if _, err := s.Rekey(key, rec, rewrapTo); err == nil || !strings.Contains(err.Error(), "(version 2: sesh history password/bank --forget 2 forgets it)") {
		t.Errorf("Rekey = %v", err)
	}
}
