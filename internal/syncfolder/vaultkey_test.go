package syncfolder_test

import (
	"bytes"
	"testing"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/syncfolder"
)

// vaultKey seals as the vault does, with its per-entry keys.
type vaultKey []byte

func (k vaultKey) EncryptEntry(plaintext, aad []byte) ([]byte, []byte, error) {
	return database.EncryptEntry(k, plaintext, aad)
}

func (k vaultKey) DecryptEntry(data, salt, aad []byte) ([]byte, error) {
	return database.DecryptEntry(k, data, salt, aad)
}

// Files sealed with the vault's own encryption open with its key, and not
// with another.
func TestSealOpen_VaultKey(t *testing.T) {
	key := vaultKey(bytes.Repeat([]byte{7}, 32))
	h, err := syncfolder.NewHeader("00112233445566778899aabbccddeeff", database.UnlockID([]byte("verify")))
	if err != nil {
		t.Fatal(err)
	}
	b, err := syncfolder.Seal(key, h, &syncfolder.Record{Service: "bank", Secret: []byte("s3cret"), Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, r, err := syncfolder.Open(key, b); err != nil || r.Service != "bank" || string(r.Secret) != "s3cret" {
		t.Fatalf("open: %+v, %v", r, err)
	}
	if _, _, err := syncfolder.Open(vaultKey(bytes.Repeat([]byte{8}, 32)), b); err == nil {
		t.Error("opened with another key")
	}
}
