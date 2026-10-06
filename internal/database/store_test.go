package database

import (
	"bytes"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// mockKeySource is an in-memory key source for testing.
type mockKeySource struct {
	err error
	key []byte
}

func (m *mockKeySource) GetEncryptionKey() ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	cp := make([]byte, len(m.key))
	copy(cp, m.key)
	return cp, nil
}

func (m *mockKeySource) EncryptEntry(plaintext, aad []byte) ([]byte, []byte, error) {
	if m.err != nil {
		return nil, nil, m.err
	}
	return EncryptEntry(m.key, plaintext, aad)
}

func (m *mockKeySource) DecryptEntry(encryptedData, salt, aad []byte) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return DecryptEntry(m.key, encryptedData, salt, aad)
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	ks := &mockKeySource{key: bytes.Repeat([]byte{0xAB}, 32)}
	s, err := Open(dbPath, ks)
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

func TestOpenAndMigrate(t *testing.T) {
	s := newTestStore(t)

	for _, tbl := range []string{"entries", "vault_key", "audit_log", "schema_migrations"} {
		var n int
		if err := s.db.QueryRow("SELECT COUNT(*) FROM " + tbl).Scan(&n); err != nil {
			t.Errorf("table %q should exist: %v", tbl, err)
		}
	}

	var v int
	if err := s.db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != currentSchemaVersion {
		t.Fatalf("expected schema version %d, got %d", currentSchemaVersion, v)
	}
}

func TestOpen_RejectsNewerSchemaVersion(t *testing.T) {
	// Simulate the downgrade scenario: a database written by a future
	// sesh build leaves a schema_migrations row past what this binary
	// knows how to handle. Silently accepting it would let queries hit
	// an unsupported schema shape.
	dbPath := filepath.Join(t.TempDir(), "test.db")
	ks := &mockKeySource{key: bytes.Repeat([]byte{0xAB}, 32)}

	s, err := Open(dbPath, ks)
	if err != nil {
		t.Fatalf("initial Open: %v", err)
	}
	if _, err := s.db.Exec(
		`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
		currentSchemaVersion+1, time.Now().UTC(),
	); err != nil {
		t.Fatalf("seed future version: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	_, err = Open(dbPath, ks)
	if err == nil {
		t.Fatal("expected error when opening DB with schema version newer than binary supports")
	}
	if !strings.Contains(err.Error(), "newer than this binary supports") {
		t.Errorf("error should mention version mismatch, got: %v", err)
	}
}

func TestMigrationsIdempotent(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	ks := &mockKeySource{key: bytes.Repeat([]byte{0xAB}, 32)}

	s1, err := Open(dbPath, ks)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("s1.Close: %v", err)
	}

	s2, err := Open(dbPath, ks)
	if err != nil {
		t.Fatalf("second Open should succeed: %v", err)
	}
	if err := s2.Close(); err != nil {
		t.Fatalf("s2.Close: %v", err)
	}
}

func TestPutGet(t *testing.T) {
	tests := map[string]struct {
		key    vault.Key
		secret []byte
	}{
		"totp secret": {key: vault.Key{Kind: vault.KindTOTP, Service: "github"}, secret: []byte("JBSWY3DPEHPK3PXP")},
		"password":    {key: vault.Key{Kind: vault.KindPassword, Service: "demo", Username: "bob"}, secret: []byte("hunter2")},
		"aws mfa":     {key: vault.AWSKey("prod"), secret: []byte("GEZDGNBVGY3TQOJQ")},
	}

	s := newTestStore(t)
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if err := s.Put(tc.key, tc.secret); err != nil {
				t.Fatalf("Put: %v", err)
			}
			got, err := s.Get(tc.key)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if !bytes.Equal(got, tc.secret) {
				t.Fatalf("got %q, want %q", got, tc.secret)
			}
		})
	}
}

func TestPut_SizeLimit(t *testing.T) {
	s := newTestStore(t)
	k := vault.Key{Kind: vault.KindNote, Service: "big"}

	if err := s.Put(k, make([]byte, MaxSecretSize)); err != nil {
		t.Fatalf("secret at the limit: %v", err)
	}
	if err := s.Put(k, make([]byte, MaxSecretSize+1)); !errors.Is(err, ErrSecretTooLarge) {
		t.Fatalf("expected ErrSecretTooLarge, got: %v", err)
	}
}

func TestGet_NotFound(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Get(vault.Key{Kind: vault.KindPassword, Service: "nonexistent"}); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestList_ByKind(t *testing.T) {
	s := newTestStore(t)
	for _, k := range []vault.Key{
		{Kind: vault.KindTOTP, Service: "github"},
		{Kind: vault.KindTOTP, Service: "gitlab"},
		{Kind: vault.KindPassword, Service: "github"},
	} {
		if err := s.Put(k, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := s.List(vault.Filter{Kind: vault.KindTOTP})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Service != "github" || entries[1].Service != "gitlab" {
		t.Fatalf("List(totp) = %+v, want github then gitlab", entries)
	}
}

func TestDelete(t *testing.T) {
	s := newTestStore(t)
	k := vault.Key{Kind: vault.KindPassword, Service: "svc"}
	if err := s.Put(k, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(k); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(k); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
	}
	if err := s.Delete(k); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("Delete of a missing entry = %v, want ErrNotFound", err)
	}
}

func TestSettings_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	want := vault.Settings{AWSMFADevice: "arn:aws:iam::1:mfa/me", TOTP: totp.Params{Digits: 8, Algorithm: "SHA256", Period: 60, Issuer: "Bank"}}
	k := vault.AWSKey("prod")
	if err := s.Save(&vault.Entry{Key: k, Settings: want}, []byte("GEZDGNBVGY3TQOJQ")); err != nil {
		t.Fatal(err)
	}
	if e, err := s.Lookup(k); err != nil || e.Settings != want {
		t.Errorf("Lookup = %+v, %v; want settings %+v", e.Settings, err, want)
	}
	entries, err := s.List(vault.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Settings != want {
		t.Errorf("List = %+v, want one entry with settings %+v", entries, want)
	}
	// No settings are stored as none.
	plain := vault.Key{Kind: vault.KindPassword, Service: "x"}
	if err := s.Put(plain, []byte("v")); err != nil {
		t.Fatal(err)
	}
	var col sql.NullString
	if err := s.db.QueryRow(`SELECT settings FROM entries WHERE service = 'x'`).Scan(&col); err != nil || col.Valid {
		t.Errorf("settings column = %+v, %v; want NULL", col, err)
	}
}

func TestSettings_CorruptColumnIsAnError(t *testing.T) {
	s := newTestStore(t)
	k := vault.Key{Kind: vault.KindTOTP, Service: "bank"}
	if err := s.Put(k, []byte("JBSWY3DPEHPK3PXP")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE entries SET settings = '{not json' WHERE service = 'bank'`); err != nil {
		t.Fatal(err)
	}
	// Silently reading none would give TOTP codes from the wrong settings.
	if _, err := s.Lookup(k); err == nil || !strings.Contains(err.Error(), "settings of totp/bank") {
		t.Errorf("Lookup = %v, want an error naming the entry's settings", err)
	}
	if _, err := s.List(vault.Filter{}); err == nil {
		t.Error("List succeeded over a corrupt settings column")
	}
}

func TestAuditLogWritten(t *testing.T) {
	s := newTestStore(t)
	if err := s.Put(vault.Key{Kind: vault.KindPassword, Service: "svc"}, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE event_type = 'modify' AND entry_id = 'password/svc'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 audit entry for password/svc, got %d", count)
	}
}

func TestSave_PreservesTimestamps(t *testing.T) {
	s := newTestStore(t)

	// Historic timestamps — "this entry was first stored ~1 year ago and
	// last updated ~6 months ago". Whole seconds, so SQLite's datetime
	// round-trip can't blur them.
	created := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)
	updated := time.Date(2025, 7, 15, 10, 0, 0, 0, time.UTC)
	k := vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}
	if err := s.Save(&vault.Entry{Key: k, CreatedAt: created, UpdatedAt: updated}, []byte("hunter2")); err != nil {
		t.Fatalf("Save: %v", err)
	}

	entries, err := s.List(vault.Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || !entries[0].CreatedAt.Equal(created) || !entries[0].UpdatedAt.Equal(updated) {
		t.Errorf("entries = %+v, want created %v, updated %v", entries, created, updated)
	}
}

func TestSave_ZeroTimestampsFallBackToNow(t *testing.T) {
	s := newTestStore(t)

	before := time.Now().UTC().Add(-time.Second)
	if err := s.Save(&vault.Entry{Kind: vault.KindPassword, Service: "a"}, []byte("x")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	after := time.Now().UTC().Add(time.Second)

	entries, err := s.List(vault.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	for _, got := range []time.Time{entries[0].CreatedAt, entries[0].UpdatedAt} {
		if got.Before(before) || got.After(after) {
			t.Errorf("zero-timestamp fallback: %v, want in [%v, %v]", got, before, after)
		}
	}
}

// The options in Open's file URI still apply.
func TestOpen_AppliesItsOptions(t *testing.T) {
	s := newTestStore(t)
	var mode string
	var fk int
	if err := s.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
		t.Errorf("journal_mode = %q, %v; want wal", mode, err)
	}
	if err := s.db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
		t.Errorf("foreign_keys = %d, %v; want 1", fk, err)
	}
}

// A deleted entry leaves none of its encrypted secret in the vault file.
func TestDelete_LeavesNoTrace(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(dbPath, &mockKeySource{key: bytes.Repeat([]byte{0xAB}, 32)})
	if err != nil {
		t.Fatal(err)
	}
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
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, sealed) {
		t.Error("the deleted entry's encrypted secret is still in the vault file")
	}
}
