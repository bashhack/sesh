package database

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/syncfolder"
)

// testRecoveryRecord is a recovery key record for the vault s, its public
// key pub (not a real one: nothing here unwraps it).
func testRecoveryRecord(t *testing.T, s *Store, pub byte) *RecoveryRecord {
	t.Helper()
	id, err := s.SyncKeyID()
	if err != nil {
		t.Fatal(err)
	}
	return &RecoveryRecord{UnlockID: id, PublicKey: bytes.Repeat([]byte{pub}, 65), EphemeralPub: []byte{1}, Ciphertext: []byte{2}, CreatedAt: time.Now().UTC()}
}

// Taking the folder's recovery key record sets the vault's and what it saw
// together, unless the vault's changed since the sync looked; another
// folder forgets what was seen.
func TestSyncTakeRecovery(t *testing.T) {
	a, _ := syncPair(t)
	if err := a.SyncStartFolder("f1"); err != nil {
		t.Fatal(err)
	}
	if err := RemoveRecovery(a.path); err != nil {
		t.Fatal(err)
	}
	if seen, err := a.SyncRecovery(); err != nil || seen.Count != 0 || seen.PublicKey != nil {
		t.Fatalf("seen at first: %+v, %v", seen, err)
	}
	rec := testRecoveryRecord(t, a, 5)
	r := syncfolder.Recovery{Count: 2, PublicKey: rec.PublicKey, Computer: "laptop", Made: rec.CreatedAt}
	if err := a.SyncTakeRecovery(&SeenRecovery{Recovery: r}, rec, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := a.Recovery(); err != nil || !bytes.Equal(got.PublicKey, rec.PublicKey) {
		t.Fatalf("the vault's record: %+v, %v", got, err)
	}
	if seen, err := a.SyncRecovery(); err != nil || !seen.Same(&r) || seen.Computer != "laptop" || !seen.Made.Equal(r.Made) || seen.Mine || seen.Earlier {
		t.Fatalf("seen: %+v, %v", seen, err)
	}
	if seen, err := VaultSyncRecovery(a.path); err != nil || !seen.Same(&r) {
		t.Errorf("seen, read without unlocking: %+v, %v", seen, err)
	}

	// The vault's record changed meanwhile: nothing is taken.
	removed := syncfolder.Recovery{Count: 3, Computer: "desktop"}
	if err := a.SyncTakeRecovery(&SeenRecovery{Recovery: removed}, nil, nil); !errors.Is(err, ErrRecoveryChanged) {
		t.Fatalf("taken over a change: %v", err)
	}
	if seen, err := a.SyncRecovery(); err != nil || !seen.Same(&r) {
		t.Errorf("seen after a refused take: %+v, %v", seen, err)
	}
	if err := a.SyncTakeRecovery(&SeenRecovery{Recovery: removed}, nil, rec.PublicKey); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Recovery(); !errors.Is(err, ErrNoRecovery) {
		t.Errorf("a removal taken: %v", err)
	}

	// A record for another key record isn't kept.
	other := testRecoveryRecord(t, a, 6)
	other.UnlockID = "another"
	if err := a.SyncTakeRecovery(&SeenRecovery{Recovery: r}, other, nil); !errors.Is(err, ErrVaultKeyChanged) {
		t.Errorf("a record for another key: %v", err)
	}

	if err := a.SyncRecoverySent(&r); err != nil {
		t.Fatal(err)
	}
	if seen, err := a.SyncRecovery(); err != nil || !seen.Mine {
		t.Errorf("seen, sent from here: %+v, %v", seen, err)
	}
	if err := a.SyncStartFolder("f2"); err != nil {
		t.Fatal(err)
	}
	if seen, err := a.SyncRecovery(); err != nil || seen.Count != 0 || seen.PublicKey != nil {
		t.Errorf("seen, another folder: %+v, %v", seen, err)
	}
}

// A restore takes the backup's recovery key record as the one the vault
// saw, so it isn't sent as a change.
func TestRestore_RecoverySeen(t *testing.T) {
	a, _ := syncPair(t)
	if err := a.SyncStartFolder("f1"); err != nil {
		t.Fatal(err)
	}
	if err := RemoveRecovery(a.path); err != nil {
		t.Fatal(err)
	}
	old := testRecoveryRecord(t, a, 5)
	first := SeenRecovery{}
	first.Count, first.PublicKey = 1, old.PublicKey
	if err := a.SyncTakeRecovery(&first, old, nil); err != nil {
		t.Fatal(err)
	}
	backup := a.path + ".backup"
	if err := CopyTo(a.path, backup); err != nil {
		t.Fatal(err)
	}
	next := testRecoveryRecord(t, a, 6)
	sent := SeenRecovery{Mine: true}
	sent.Count, sent.PublicKey = 2, next.PublicKey
	if err := a.SyncTakeRecovery(&sent, next, old.PublicKey); err != nil {
		t.Fatal(err)
	}
	if err := RestoreInPlace(a.path, backup); err != nil {
		t.Fatal(err)
	}
	seen, err := VaultSyncRecovery(a.path)
	if err != nil || seen.Count != 2 || !bytes.Equal(seen.PublicKey, old.PublicKey) || seen.Mine || !seen.Earlier {
		t.Errorf("seen after the restore: %+v, %v", seen, err)
	}
}
