package database

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func staticPrompt(passwords ...string) PasswordPromptFunc {
	i := 0
	return func(_ string) ([]byte, error) {
		if i >= len(passwords) {
			return nil, errors.New("no more passwords")
		}
		pw := []byte(passwords[i])
		i++
		return pw, nil
	}
}

func TestMasterPasswordSource_FirstRunCreatesSidecar(t *testing.T) {
	dir := t.TempDir()
	src := NewMasterPasswordSource(dir, staticPrompt("correct-horse-battery-staple", "correct-horse-battery-staple"))

	key, err := src.GetEncryptionKey()
	if err != nil {
		t.Fatalf("GetEncryptionKey: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key))
	}

	if _, err := os.Stat(filepath.Join(dir, sidecarFileName)); err != nil {
		t.Fatalf("sidecar should exist after first run: %v", err)
	}
}

func TestMasterPasswordSource_SidecarPermissions(t *testing.T) {
	dir := t.TempDir()
	src := NewMasterPasswordSource(dir, staticPrompt("hunter2-password-secure", "hunter2-password-secure"))

	if _, err := src.GetEncryptionKey(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(dir, sidecarFileName))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("sidecar permissions should be 0600, got %o", perm)
	}
}

func TestMasterPasswordSource_SecondRunReturnsSameKey(t *testing.T) {
	dir := t.TempDir()
	password := "my-master-password"

	src1 := NewMasterPasswordSource(dir, staticPrompt(password, password))
	key1, err := src1.GetEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}

	src2 := NewMasterPasswordSource(dir, staticPrompt(password))
	key2, err := src2.GetEncryptionKey()
	if err != nil {
		t.Fatalf("second unlock: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Fatal("same password should yield same key across runs")
	}
}

func TestMasterPasswordSource_WrongPasswordRejected(t *testing.T) {
	dir := t.TempDir()

	src1 := NewMasterPasswordSource(dir, staticPrompt("original", "original"))
	if _, err := src1.GetEncryptionKey(); err != nil {
		t.Fatal(err)
	}

	src2 := NewMasterPasswordSource(dir, staticPrompt("wrong-password"))
	_, err := src2.GetEncryptionKey()
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestMasterPasswordSource_MismatchedConfirmation(t *testing.T) {
	dir := t.TempDir()
	src := NewMasterPasswordSource(dir, staticPrompt("first-password", "different-password"))

	_, err := src.GetEncryptionKey()
	if err == nil {
		t.Fatal("expected error for mismatched confirmation")
	}

	if _, err := os.Stat(filepath.Join(dir, sidecarFileName)); !os.IsNotExist(err) {
		t.Fatal("sidecar should not be created when confirmation fails")
	}
}

func TestMasterPasswordSource_RejectsTooShortPassword(t *testing.T) {
	dir := t.TempDir()
	src := NewMasterPasswordSource(dir, staticPrompt("short", "short"))

	_, err := src.GetEncryptionKey()
	if err == nil {
		t.Fatal("expected error for too-short password")
	}
}

func TestMasterPasswordSource_Name(t *testing.T) {
	src := NewMasterPasswordSource("/tmp", staticPrompt())
	if src.Name() != "master-password" {
		t.Errorf("expected 'master-password', got %q", src.Name())
	}
	if !src.RequiresUserInput() {
		t.Error("RequiresUserInput should return true")
	}
}

func TestMasterPasswordSource_UnsupportedVersion(t *testing.T) {
	dir := t.TempDir()
	bad := []byte(`{"version": 99, "algorithm": "argon2id", "salt": "", "params": {"time":3,"memory":65536,"threads":4,"key_len":32}, "verify": ""}`)
	if err := os.WriteFile(filepath.Join(dir, sidecarFileName), bad, 0o600); err != nil {
		t.Fatal(err)
	}

	src := NewMasterPasswordSource(dir, staticPrompt("any-password"))
	_, err := src.GetEncryptionKey()
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestMasterPasswordSource_UnsupportedAlgorithm(t *testing.T) {
	dir := t.TempDir()
	bad := []byte(`{"version": 1, "algorithm": "scrypt", "salt": "", "params": {"time":3,"memory":65536,"threads":4,"key_len":32}, "verify": ""}`)
	if err := os.WriteFile(filepath.Join(dir, sidecarFileName), bad, 0o600); err != nil {
		t.Fatal(err)
	}

	src := NewMasterPasswordSource(dir, staticPrompt("any-password"))
	_, err := src.GetEncryptionKey()
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

func TestMasterPasswordSource_RejectsOutOfRangeParams(t *testing.T) {
	tests := map[string]string{
		"zero memory":   `{"version":1,"algorithm":"argon2id","salt":"","verify":"","params":{"time":3,"memory":0,"threads":4,"key_len":32}}`,
		"huge memory":   `{"version":1,"algorithm":"argon2id","salt":"","verify":"","params":{"time":3,"memory":2147483647,"threads":4,"key_len":32}}`,
		"zero threads":  `{"version":1,"algorithm":"argon2id","salt":"","verify":"","params":{"time":3,"memory":65536,"threads":0,"key_len":32}}`,
		"huge time":     `{"version":1,"algorithm":"argon2id","salt":"","verify":"","params":{"time":999,"memory":65536,"threads":4,"key_len":32}}`,
		"wrong key_len": `{"version":1,"algorithm":"argon2id","salt":"","verify":"","params":{"time":3,"memory":65536,"threads":4,"key_len":16}}`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, sidecarFileName), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			src := NewMasterPasswordSource(dir, staticPrompt("any-password"))
			_, err := src.GetEncryptionKey()
			if err == nil {
				t.Fatal("expected error for out-of-range params")
			}
		})
	}
}

func TestMasterPasswordSource_SidecarHasNoSecrets(t *testing.T) {
	dir := t.TempDir()
	password := "super-secret-password-12345"
	src := NewMasterPasswordSource(dir, staticPrompt(password, password))

	if _, err := src.GetEncryptionKey(); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(filepath.Join(dir, sidecarFileName))
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Contains(b, []byte(password)) {
		t.Fatal("sidecar contains the master password in plaintext")
	}
}
