package database

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/keychain"
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

func (m *mockKeySource) StoreEncryptionKey(key []byte) error { return nil }
func (m *mockKeySource) RequiresUserInput() bool             { return false }
func (m *mockKeySource) Name() string                        { return "mock" }

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

	tables := []string{"passwords", "key_metadata", "audit_log", "schema_migrations"}
	for _, tbl := range tables {
		var n int
		err := s.db.QueryRow("SELECT COUNT(*) FROM " + tbl).Scan(&n)
		if err != nil {
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

func TestSetGetSecret(t *testing.T) {
	tests := map[string]struct {
		account string
		service string
		secret  []byte
	}{
		"totp secret": {
			account: "alice",
			service: "sesh-totp/github",
			secret:  []byte("JBSWY3DPEHPK3PXP"),
		},
		"password": {
			account: "bob",
			service: "sesh-password/demo",
			secret:  []byte("hunter2"),
		},
		"mfa serial": {
			account: "carol",
			service: "sesh-aws-serial/prod",
			secret:  []byte("arn:aws:iam::123456:mfa/carol"),
		},
	}

	s := newTestStore(t)

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if err := s.SetSecret(tc.account, tc.service, tc.secret); err != nil {
				t.Fatalf("SetSecret: %v", err)
			}

			got, err := s.GetSecret(tc.account, tc.service)
			if err != nil {
				t.Fatalf("GetSecret: %v", err)
			}

			if !bytes.Equal(got, tc.secret) {
				t.Fatalf("got %q, want %q", got, tc.secret)
			}
		})
	}
}

func TestSetSecretUpsert(t *testing.T) {
	s := newTestStore(t)

	if err := s.SetSecret("alice", "svc", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSecret("alice", "svc", []byte("v2")); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetSecret("alice", "svc")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "v2" {
		t.Fatalf("expected v2, got %q", got)
	}
}

func TestGetSecretNotFound(t *testing.T) {
	s := newTestStore(t)

	_, err := s.GetSecret("alice", "nonexistent")
	if !errors.Is(err, keychain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestSetGetSecretString(t *testing.T) {
	s := newTestStore(t)

	if err := s.SetSecretString("bob", "sesh-password/demo", "hunter2"); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetSecretString("bob", "sesh-password/demo")
	if err != nil {
		t.Fatal(err)
	}
	if got != "hunter2" {
		t.Fatalf("got %q, want %q", got, "hunter2")
	}
}

func TestGetMFASerialBytes(t *testing.T) {
	tests := map[string]struct {
		profile string
		service string
	}{
		"with profile": {
			profile: "prod",
			service: "sesh-aws-serial/prod",
		},
		"empty profile": {
			profile: "",
			service: "sesh-aws-serial",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			s := newTestStore(t)
			serial := []byte("arn:aws:iam::123456:mfa/alice")

			if err := s.SetSecret("alice", tc.service, serial); err != nil {
				t.Fatal(err)
			}

			got, err := s.GetMFASerialBytes("alice", tc.profile)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, serial) {
				t.Fatalf("got %q, want %q", got, serial)
			}
		})
	}
}

func TestListEntries(t *testing.T) {
	s := newTestStore(t)

	secrets := map[string]string{
		"sesh-totp/github": "secret1",
		"sesh-totp/gitlab": "secret2",
		"sesh-aws/prod":    "secret3",
	}
	for svc, sec := range secrets {
		if err := s.SetSecret("alice", svc, []byte(sec)); err != nil {
			t.Fatal(err)
		}
	}

	entries, err := s.ListEntries("sesh-totp")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 totp entries, got %d", len(entries))
	}

	for _, e := range entries {
		if !strings.HasPrefix(e.Service, "sesh-totp") {
			t.Errorf("unexpected service: %s", e.Service)
		}
	}
}

func TestDeleteEntry(t *testing.T) {
	s := newTestStore(t)

	if err := s.SetSecret("alice", "svc", []byte("secret")); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteEntry("alice", "svc"); err != nil {
		t.Fatal(err)
	}

	_, err := s.GetSecret("alice", "svc")
	if err == nil {
		t.Fatal("expected not-found after delete")
	}
}

func TestDeleteEntryNotFound(t *testing.T) {
	s := newTestStore(t)

	err := s.DeleteEntry("alice", "nonexistent")
	if !errors.Is(err, keychain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestSetDescription(t *testing.T) {
	s := newTestStore(t)

	// SetDescription only updates existing rows — create the entry first.
	if err := s.SetSecret("alice", "sesh-totp/github", []byte("secret")); err != nil {
		t.Fatal(err)
	}

	if err := s.SetDescription("sesh-totp/github", "alice", "GitHub TOTP"); err != nil {
		t.Fatal(err)
	}

	entries, err := s.ListEntries("sesh-totp")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Description != "GitHub TOTP" {
		t.Fatalf("expected description 'GitHub TOTP', got %q", entries[0].Description)
	}
}

func TestSetDescriptionNotFoundWithoutEntry(t *testing.T) {
	s := newTestStore(t)

	// Calling SetDescription without a prior SetSecret surfaces ErrNotFound —
	// matching DeleteEntry's contract so caller typos/races don't go silent.
	err := s.SetDescription("sesh-totp/github", "alice", "desc")
	if !errors.Is(err, keychain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}

	entries, err := s.ListEntries("sesh-totp")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries (no row exists), got %d", len(entries))
	}
}

func TestSearchEntries(t *testing.T) {
	s := newTestStore(t)

	// Seed data
	for _, svc := range []string{"sesh-password/github", "sesh-password/gitlab", "sesh-aws/prod"} {
		if err := s.SetSecret("alice", svc, []byte("secret")); err != nil {
			t.Fatal(err)
		}
	}
	// Set a description to test metadata search
	if err := s.SetDescription("sesh-password/github", "alice", "My GitHub token"); err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		query    string
		expected int
	}{
		"match service prefix": {query: "github", expected: 1},
		"match multiple":       {query: "git", expected: 2},
		"match metadata":       {query: "token", expected: 1},
		"match account":        {query: "alice", expected: 3},
		"no match":             {query: "nonexistent", expected: 0},
		"special chars quotes": {query: `he said "hello"`, expected: 0},
		"special chars star":   {query: "foo*bar", expected: 0},
		"special chars paren":  {query: "foo(bar)", expected: 0},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			entries, err := s.SearchEntries(tc.query)
			if err != nil {
				t.Fatalf("SearchEntries(%q): %v", tc.query, err)
			}
			if len(entries) != tc.expected {
				t.Errorf("expected %d results, got %d", tc.expected, len(entries))
			}
		})
	}
}

func TestAuditLogWritten(t *testing.T) {
	s := newTestStore(t)

	if err := s.SetSecret("alice", "svc", []byte("secret")); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE event_type = 'modify'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 audit entry, got %d", count)
	}
}

func TestInitKeyMetadata(t *testing.T) {
	s := newTestStore(t)

	if err := s.InitKeyMetadata(); err != nil {
		t.Fatal(err)
	}

	meta, err := s.GetActiveKeyMetadata()
	if err != nil {
		t.Fatal(err)
	}
	if meta == nil {
		t.Fatal("expected key metadata after init")
	}
	if meta.Version != 1 {
		t.Fatalf("expected version 1, got %d", meta.Version)
	}
	if meta.Algorithm != "argon2id" {
		t.Fatalf("expected argon2id, got %q", meta.Algorithm)
	}

	// Calling again should be a no-op.
	if err := s.InitKeyMetadata(); err != nil {
		t.Fatal(err)
	}
}

func TestInferEntryType(t *testing.T) {
	tests := map[string]struct {
		service string
		want    EntryType
	}{
		"totp secret":          {service: "sesh-totp/github", want: EntryTypeTOTP},
		"aws totp":             {service: "sesh-aws/prod", want: EntryTypeTOTP},
		"mfa serial":           {service: "sesh-aws-serial/prod", want: EntryTypeMFA},
		"password via manager": {service: "sesh-password/password/github/alice", want: EntryTypePassword},
		"totp via manager":     {service: "sesh-password/totp/github/alice", want: EntryTypeTOTP},
		"api_key via manager":  {service: "sesh-password/api_key/stripe/admin", want: EntryTypeAPIKey},
		"note via manager":     {service: "sesh-password/secure_note/personal/codes", want: EntryTypeNote},
		"password bare prefix": {service: "sesh-password/demo", want: EntryTypePassword},
		"unknown":              {service: "unknown-service", want: EntryTypePassword},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := inferEntryType(tc.service)
			if got != tc.want {
				t.Errorf("inferEntryType(%q) = %q, want %q", tc.service, got, tc.want)
			}
		})
	}
}

func TestExtractPrefix(t *testing.T) {
	tests := map[string]struct {
		service string
		want    string
	}{
		"with slash":   {service: "sesh-totp/github", want: "sesh-totp"},
		"nested slash": {service: "sesh-aws-serial/prod", want: "sesh-aws-serial"},
		"no slash":     {service: "sesh-metadata", want: "sesh-metadata"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := extractPrefix(tc.service)
			if got != tc.want {
				t.Errorf("extractPrefix(%q) = %q, want %q", tc.service, got, tc.want)
			}
		})
	}
}

func TestSetSecretAt_PreservesTimestamps(t *testing.T) {
	s := newTestStore(t)

	// Historic timestamps — "this entry was first stored ~1 year ago and
	// last updated ~6 months ago". Truncate to seconds so we don't fight
	// SQLite's datetime column round-trip precision.
	created := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)
	updated := time.Date(2025, 7, 15, 10, 0, 0, 0, time.UTC)

	if err := s.SetSecretAt("alice", "sesh-password/password/github/alice", []byte("hunter2"), created, updated); err != nil {
		t.Fatalf("SetSecretAt: %v", err)
	}

	entries, err := s.ListEntries("sesh-password")
	if err != nil {
		t.Fatalf("ListEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if !entries[0].CreatedAt.Equal(created) {
		t.Errorf("CreatedAt = %v, want %v", entries[0].CreatedAt, created)
	}
	if !entries[0].UpdatedAt.Equal(updated) {
		t.Errorf("UpdatedAt = %v, want %v", entries[0].UpdatedAt, updated)
	}
}

func TestSetSecretAt_ZeroTimestampsFallBackToNow(t *testing.T) {
	s := newTestStore(t)

	before := time.Now().UTC().Add(-time.Second)
	if err := s.SetSecretAt("alice", "sesh-password/password/a/alice", []byte("x"), time.Time{}, time.Time{}); err != nil {
		t.Fatalf("SetSecretAt: %v", err)
	}
	after := time.Now().UTC().Add(time.Second)

	entries, err := s.ListEntries("sesh-password")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	got := entries[0].CreatedAt
	if got.Before(before) || got.After(after) {
		t.Errorf("zero-timestamp fallback: CreatedAt = %v, want in [%v, %v]", got, before, after)
	}
}

func TestSetDescriptionAt_PreservesTimestamp(t *testing.T) {
	s := newTestStore(t)

	created := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)
	updated := time.Date(2025, 7, 15, 10, 0, 0, 0, time.UTC)
	if err := s.SetSecretAt("alice", "sesh-password/password/github/alice", []byte("hunter2"), created, updated); err != nil {
		t.Fatal(err)
	}

	// SetDescriptionAt with the same updated_at must not bump the stamp
	// forward to "now" — that would defeat timestamp preservation on
	// import (which calls SetSecret + SetDescription in sequence).
	if err := s.SetDescriptionAt("sesh-password/password/github/alice", "alice", "GitHub password", updated); err != nil {
		t.Fatalf("SetDescriptionAt: %v", err)
	}

	entries, err := s.ListEntries("sesh-password")
	if err != nil {
		t.Fatal(err)
	}
	if !entries[0].UpdatedAt.Equal(updated) {
		t.Errorf("UpdatedAt after SetDescriptionAt = %v, want %v", entries[0].UpdatedAt, updated)
	}
	if entries[0].Description != "GitHub password" {
		t.Errorf("Description = %q, want %q", entries[0].Description, "GitHub password")
	}
}

func TestSetDescriptionAt_MissingEntryReturnsErrNotFound(t *testing.T) {
	s := newTestStore(t)
	err := s.SetDescriptionAt("sesh-password/password/ghost/alice", "alice", "", time.Now())
	if !errors.Is(err, keychain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSearchEntries_EmptyAndWhitespaceQueryShortCircuit(t *testing.T) {
	// Seed a row so we'd know if the guard was missing — an empty query
	// would produce an invalid FTS5 expression (`""*`) and surface as an
	// error rather than silently returning no rows.
	s := newTestStore(t)
	if err := s.SetSecret("alice", "sesh-password/github", []byte("secret")); err != nil {
		t.Fatal(err)
	}

	for _, q := range []string{"", " ", "\t\n  "} {
		got, err := s.SearchEntries(q)
		if err != nil {
			t.Errorf("SearchEntries(%q): unexpected error %v", q, err)
		}
		if got != nil {
			t.Errorf("SearchEntries(%q) = %v, want nil", q, got)
		}
	}
}
