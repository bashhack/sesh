package database

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// vaultPath is the vault file in dir.
func vaultPath(dir string) string { return filepath.Join(dir, "passwords.db") }

// writeRawKeyRecord gives the vault in dir a key record with these values,
// unchecked.
func writeRawKeyRecord(t *testing.T, dir string, salt []byte, kdf, params string, verify []byte) {
	t.Helper()
	db, err := openDB(vaultPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // test cleanup
	if _, err := db.Exec(`INSERT INTO vault_key (id, salt, kdf, kdf_params, verify, created_at) VALUES (1, ?, ?, ?, ?, CURRENT_TIMESTAMP)`, salt, kdf, params, verify); err != nil {
		t.Fatal(err)
	}
}

const goodParams = `{"time":3,"memory":65536,"threads":4,"key_len":32}`

func TestMasterPasswordSource_FirstRunCreatesTheVault(t *testing.T) {
	dir := t.TempDir()
	src := NewMasterPasswordSource(vaultPath(dir), staticPrompt("correct-horse-battery-staple", "correct-horse-battery-staple"))

	key, err := src.GetEncryptionKey()
	if err != nil {
		t.Fatalf("GetEncryptionKey: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key))
	}
	m, err := ReadUnlockMaterial(vaultPath(dir))
	if err != nil {
		t.Fatalf("the vault should have its key record after the first run: %v", err)
	}
	if m.Params != DefaultArgon2idParams() || len(m.Salt) != 32 {
		t.Errorf("key record = %+v, want the default settings and a 32-byte salt", m)
	}
	if _, err := Decrypt(key, m.Verify); err != nil {
		t.Errorf("the verify blob doesn't open with the key: %v", err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 {
		t.Errorf("the vault folder holds %v (%v), want only the vault", entries, err)
	}
}

func TestMasterPasswordSource_VaultIsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	src := NewMasterPasswordSource(vaultPath(dir), staticPrompt("hunter2-password-secure", "hunter2-password-secure"))
	if _, err := src.GetEncryptionKey(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(vaultPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("vault permissions should be 0600, got %o", perm)
	}
}

func TestMasterPasswordSource_VaultHoldsNoPassword(t *testing.T) {
	dir := t.TempDir()
	password := "super-secret-password-12345"
	src := NewMasterPasswordSource(vaultPath(dir), staticPrompt(password, password))
	if _, err := src.GetEncryptionKey(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(vaultPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(password)) {
		t.Fatal("the vault holds the master password in plaintext")
	}
}

func TestMasterPasswordSource_BadKeyRecord(t *testing.T) {
	salt, verify := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 40)
	tests := map[string]struct {
		kdf, params, wantSub string
		salt, verify         []byte
	}{
		"unknown kdf":   {"scrypt", goodParams, `uses "scrypt"`, salt, verify},
		"zero memory":   {kdfArgon2id, `{"time":3,"memory":0,"threads":4,"key_len":32}`, "memory setting", salt, verify},
		"huge memory":   {kdfArgon2id, `{"time":3,"memory":2147483647,"threads":4,"key_len":32}`, "memory setting", salt, verify},
		"zero threads":  {kdfArgon2id, `{"time":3,"memory":65536,"threads":0,"key_len":32}`, "threads setting", salt, verify},
		"huge time":     {kdfArgon2id, `{"time":999,"memory":65536,"threads":4,"key_len":32}`, "time setting", salt, verify},
		"wrong key_len": {kdfArgon2id, `{"time":3,"memory":65536,"threads":4,"key_len":16}`, "key_len", salt, verify},
		"not JSON":      {kdfArgon2id, `{`, "unmarshal argon2id params", salt, verify},
		"short salt":    {kdfArgon2id, goodParams, "salt too short", []byte{1, 2, 3}, verify},
		"short verify":  {kdfArgon2id, goodParams, "verify blob too short", salt, []byte{1, 2, 3}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeRawKeyRecord(t, dir, tc.salt, tc.kdf, tc.params, tc.verify)
			prompts := 0
			prompt := func(string) ([]byte, error) {
				prompts++
				return []byte("any-password-1"), nil
			}
			_, err := NewMasterPasswordSource(vaultPath(dir), prompt, WithMaxAttempts(3)).GetEncryptionKey()
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("err = %v, want %q", err, tc.wantSub)
			}
			// Only a wrong password is asked again; a bad record isn't asked at all.
			if prompts != 0 {
				t.Errorf("asked for a password %d times", prompts)
			}
		})
	}
}

// A vault created by another sesh while this one asked for a password is
// opened with the password typed here, if it's that vault's.
func TestMasterPasswordSource_CreationRace(t *testing.T) {
	tests := map[string]struct {
		other   string
		wantErr string
	}{
		"same password":      {other: "shared-password-1"},
		"different password": {other: "other-password-22", wantErr: "created this vault at the same time"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			var otherKey []byte
			prompt := func(p string) ([]byte, error) {
				if strings.HasPrefix(p, "Confirm") && otherKey == nil {
					k, err := NewMasterPasswordSource(vaultPath(dir), staticPrompt(tc.other, tc.other)).GetEncryptionKey()
					if err != nil {
						t.Fatalf("the other sesh: %v", err)
					}
					otherKey = k
				}
				return []byte("shared-password-1"), nil
			}
			key, err := NewMasterPasswordSource(vaultPath(dir), prompt).GetEncryptionKey()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(key, otherKey) {
				t.Error("the key isn't the vault's")
			}
		})
	}
}

// A vault with entries but no key record is refused before any prompt: a
// new key couldn't read them.
func TestMasterPasswordSource_EntriesWithoutKeyRecord(t *testing.T) {
	dir := t.TempDir()
	db, err := openDB(vaultPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO entries (kind, service, encrypted_data, salt, created_at, updated_at) VALUES ('password', 'github', x'00', x'00', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	called := false
	prompt := func(string) ([]byte, error) { called = true; return []byte("any-password-1"), nil }
	_, err = NewMasterPasswordSource(vaultPath(dir), prompt).GetEncryptionKey()
	if err == nil || !strings.Contains(err.Error(), "holds entries but not the record its key is made from") {
		t.Fatalf("err = %v, want the missing key record named", err)
	}
	if called {
		t.Error("asked for a password")
	}
}

// A vault file with no key record and no entries, such as one left by a
// creation that stopped, is created over.
func TestMasterPasswordSource_EmptyVaultFileIsCreated(t *testing.T) {
	dir := t.TempDir()
	db, err := openDB(vaultPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadUnlockMaterial(vaultPath(dir)); !errors.Is(err, ErrNoVault) {
		t.Fatalf("ReadUnlockMaterial = %v, want ErrNoVault", err)
	}
	if _, err := NewMasterPasswordSource(vaultPath(dir), staticPrompt("new-password-1", "new-password-1")).GetEncryptionKey(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadUnlockMaterial(vaultPath(dir)); err != nil {
		t.Fatal(err)
	}
}

func TestReadUnlockMaterial_NoVault(t *testing.T) {
	p := vaultPath(t.TempDir())
	if _, err := ReadUnlockMaterial(p); !errors.Is(err, ErrNoVault) {
		t.Fatalf("err = %v, want ErrNoVault", err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Errorf("reading made a vault file (stat: %v)", err)
	}
}

// A second record is never written over the first.
func TestWriteKeyRecord_OnlyOnce(t *testing.T) {
	dir := t.TempDir()
	db, err := openDB(vaultPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // test cleanup
	m := UnlockMaterial{Salt: bytes.Repeat([]byte{1}, 32), Verify: bytes.Repeat([]byte{2}, 40), Params: DefaultArgon2idParams()}
	if ok, err := writeKeyRecord(db, m); err != nil || !ok {
		t.Fatalf("first write = %v, %v", ok, err)
	}
	other := m
	other.Salt = bytes.Repeat([]byte{3}, 32)
	if ok, err := writeKeyRecord(db, other); err != nil || ok {
		t.Fatalf("second write = %v, %v; want not written", ok, err)
	}
	got, err := readKeyRecord(db, vaultPath(dir))
	if err != nil || !bytes.Equal(got.Salt, m.Salt) {
		t.Errorf("record = %+v, %v; want the first", got, err)
	}
}
