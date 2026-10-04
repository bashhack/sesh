package database

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

var (
	keyA = bytes.Repeat([]byte{0xAA}, 32)
	keyB = bytes.Repeat([]byte{0xBB}, 32)
)

// openWithKey opens the vault at dbPath with key, closing it at cleanup.
func openWithKey(t *testing.T, dbPath string, key []byte) *Store {
	t.Helper()
	s, err := Open(dbPath, &mockKeySource{key: key})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

func hasKeyCheck(t *testing.T, s *Store) bool {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM vault_key`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

// wantWrongKey fails unless err is a WrongKeyError for the given sources.
func wantWrongKey(t *testing.T, err error, vaultSource, source string) {
	t.Helper()
	var wk *WrongKeyError
	if !errors.As(err, &wk) {
		t.Fatalf("err = %v, want a WrongKeyError", err)
	}
	if wk.VaultSource != vaultSource || wk.Source != source {
		t.Errorf("WrongKeyError = %+v, want vault source %q, source %q", wk, vaultSource, source)
	}
}

func TestCheckKey_NewVaultRecordsAndChecksItsKey(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "passwords.db")
	if err := openWithKey(t, dbPath, keyA).CheckKey("password"); err != nil {
		t.Fatalf("first CheckKey: %v", err)
	}

	if err := openWithKey(t, dbPath, keyA).CheckKey("password"); err != nil {
		t.Errorf("same key, same source: %v", err)
	}
	wantWrongKey(t, openWithKey(t, dbPath, keyB).CheckKey("password"), "password", "password")
	wantWrongKey(t, openWithKey(t, dbPath, keyB).CheckKey("keychain"), "password", "keychain")
}

func TestCheckKey_VaultFromBeforeTheCheck(t *testing.T) {
	t.Run("right key records the check", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "passwords.db")
		if err := openWithKey(t, dbPath, keyA).SetSecret("me", "sesh-password/password/x", []byte("v")); err != nil {
			t.Fatal(err)
		}
		s := openWithKey(t, dbPath, keyA)
		if err := s.CheckKey("password"); err != nil {
			t.Fatalf("CheckKey: %v", err)
		}
		if !hasKeyCheck(t, s) {
			t.Error("no check value recorded")
		}
	})
	t.Run("wrong key is refused and records nothing", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "passwords.db")
		if err := openWithKey(t, dbPath, keyA).SetSecret("me", "sesh-password/password/x", []byte("v")); err != nil {
			t.Fatal(err)
		}
		s := openWithKey(t, dbPath, keyB)
		wantWrongKey(t, s.CheckKey("password"), "", "password")
		if hasKeyCheck(t, s) {
			t.Error("a refused key recorded a check value")
		}
	})
}

func TestVerifyKey_NeverWrites(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "passwords.db")
	s := openWithKey(t, dbPath, keyA)
	if err := s.SetSecret("me", "sesh-password/password/x", []byte("v")); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyKey("password"); err != nil {
		t.Fatalf("VerifyKey with the right key: %v", err)
	}
	if hasKeyCheck(t, s) {
		t.Error("VerifyKey recorded a check value")
	}
	wantWrongKey(t, openWithKey(t, dbPath, keyB).VerifyKey("password"), "", "password")
}

func TestRecordedKeySource(t *testing.T) {
	s := newTestStore(t)
	if got, err := RecordedKeySource(s.Path()); err != nil || got != "" {
		t.Fatalf("before any key check = %q, %v; want none", got, err)
	}
	if err := s.CheckKey("keychain"); err != nil {
		t.Fatal(err)
	}
	if got, err := RecordedKeySource(s.Path()); err != nil || got != "keychain" {
		t.Errorf("after a keychain key check = %q, %v", got, err)
	}
	if got, err := RecordedKeySource(filepath.Join(t.TempDir(), "missing.db")); err == nil {
		t.Errorf("a missing vault = %q, want an error", got)
	}
}

// Folder names with characters that mean something in a URI.
func TestRecordedKeySource_UnusualPaths(t *testing.T) {
	for _, dir := range []string{"a#b", "c%20d", "e?f", "g h"} {
		t.Run(dir, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), dir, "passwords.db")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			s, err := Open(path, &mockKeySource{key: bytes.Repeat([]byte{0xAB}, 32)})
			if err != nil {
				t.Skipf("the vault itself doesn't open at this path: %v", err)
			}
			if err := s.CheckKey("keychain"); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if got, err := RecordedKeySource(path); err != nil || got != "keychain" {
				t.Errorf("RecordedKeySource = %q, %v; want keychain", got, err)
			}
		})
	}
}
