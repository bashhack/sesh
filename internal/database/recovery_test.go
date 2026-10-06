package database

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRecovery_WriteReadRemove(t *testing.T) {
	p := vaultPath(t.TempDir())
	if _, err := ReadRecovery(p); !errors.Is(err, ErrNoVault) {
		t.Fatalf("no vault: err = %v, want ErrNoVault", err)
	}
	if err := WriteRecovery(p, &RecoveryRecord{UnlockID: "id"}); !errors.Is(err, ErrNoVault) {
		t.Fatalf("writing with no vault: err = %v, want ErrNoVault", err)
	}
	if _, err := NewMasterPasswordSource(p, staticPrompt("first-password-1", "first-password-1")).GetEncryptionKey(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRecovery(p); !errors.Is(err, ErrNoRecovery) {
		t.Fatalf("none yet: err = %v, want ErrNoRecovery", err)
	}
	made := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	for _, id := range []string{"first", "second"} {
		if err := WriteRecovery(p, &RecoveryRecord{UnlockID: id, PublicKey: []byte("pub"), EphemeralPub: []byte("eph"), Ciphertext: []byte("ct"), CreatedAt: made}); err != nil {
			t.Fatal(err)
		}
	}
	r, err := ReadRecovery(p)
	if err != nil || r.UnlockID != "second" || string(r.Ciphertext) != "ct" || !r.CreatedAt.Equal(made) {
		t.Fatalf("read back %+v, %v; want the second record", r, err)
	}
	if err := RemoveRecovery(p); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRecovery(p); !errors.Is(err, ErrNoRecovery) {
		t.Errorf("after remove: err = %v", err)
	}
	if err := RemoveRecovery(p); err != nil {
		t.Errorf("removing none: %v", err)
	}
	if err := WriteRecovery(p, &RecoveryRecord{UnlockID: "id", PublicKey: []byte{}, EphemeralPub: []byte{}, Ciphertext: []byte{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRecovery(p); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Errorf("an incomplete record: err = %v", err)
	}
}
