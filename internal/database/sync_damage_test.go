package database

import (
	"path/filepath"
	"testing"

	"github.com/bashhack/sesh/internal/syncfolder"
	"github.com/bashhack/sesh/internal/vault"
)

// A backup made before a password change, restored in place, leaves sync
// and a new master password working.
func TestSync_RestorePreRekeyBackup(t *testing.T) {
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
	backup := filepath.Join(t.TempDir(), "b.db")
	if err := CopyTo(p, backup); err != nil {
		t.Fatal(err)
	}
	key, kr := newKeyFor(t, "new-password-1")
	if _, err := s.Rekey(key, kr, rewrapTo); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := RestoreInPlace(p, backup); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(p, NewKeySourceOracle(NewMasterPasswordSource(p, staticPrompt("old-password-1"))))
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close() //nolint:errcheck // test cleanup
	if _, err := s2.Get(k); err != nil {
		t.Fatalf("restored vault: %v", err)
	}
	if _, err := s2.SyncBase(uid); err != nil {
		t.Errorf("SyncBase after restoring a pre-rekey backup: %v", err)
	}
	key2, kr2 := newKeyFor(t, "new-password-2")
	if _, err := s2.Rekey(key2, kr2, rewrapTo); err != nil {
		t.Errorf("Rekey after restoring a pre-rekey backup: %v", err)
	}
}

// A new master password drops an agreed version that doesn't open
// (damaged), rather than refusing the change: the entry merges as never
// synced.
func TestSync_RekeyDropsWhatDoesntOpen(t *testing.T) {
	_, s := rekeyVault(t)
	uid := uidOf(t, s, vault.Key{Kind: vault.KindPassword, Service: "bank"})
	rec, rev, err := s.SyncRecord(uid, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SyncAgree(uid, rev, rec, syncfolder.Hash{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE sync_state SET base = ? WHERE uid = ?`, []byte("damaged"), uid); err != nil {
		t.Fatal(err)
	}
	key, kr := newKeyFor(t, "new-password-1")
	if _, err := s.Rekey(key, kr, rewrapTo); err != nil {
		t.Fatalf("Rekey: %v", err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sync_state`).Scan(&n); err != nil || n != 0 {
		t.Errorf("sync_state rows %d, %v; want the damaged one dropped", n, err)
	}
}
