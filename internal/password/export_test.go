package password

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/keychain"
)

// inMemoryStore implements keychain.Provider (and optionally
// keychain.TimestampedStore via the timestampedInMemoryStore wrapper below)
// against a map so we can unit test Manager's export/import paths without
// standing up SQLite.
type inMemoryStore struct {
	// Maps first (pointer-heavy), mutex last for govet's fieldalignment.
	secrets    map[string][]byte // key = service|account
	descs      map[string]string
	createdAts map[string]time.Time
	updatedAts map[string]time.Time
	mu         sync.Mutex
}

func newInMemoryStore() *inMemoryStore {
	return &inMemoryStore{
		secrets:    make(map[string][]byte),
		descs:      make(map[string]string),
		createdAts: make(map[string]time.Time),
		updatedAts: make(map[string]time.Time),
	}
}

func (s *inMemoryStore) key(account, service string) string { return service + "|" + account }

func (s *inMemoryStore) GetSecret(account, service string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.secrets[s.key(account, service)]
	if !ok {
		return nil, fmt.Errorf("%w: %s/%s", keychain.ErrNotFound, service, account)
	}
	return append([]byte{}, v...), nil
}

func (s *inMemoryStore) SetSecret(account, service string, secret []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[s.key(account, service)] = append([]byte{}, secret...)
	return nil
}

func (s *inMemoryStore) GetSecretString(account, service string) (string, error) {
	b, err := s.GetSecret(account, service)
	return string(b), err
}

func (s *inMemoryStore) SetSecretString(account, service, secret string) error {
	return s.SetSecret(account, service, []byte(secret))
}

func (s *inMemoryStore) GetMFASerialBytes(_, _ string) ([]byte, error) {
	return nil, keychain.ErrNotFound
}

func (s *inMemoryStore) ListEntries(prefix string) ([]keychain.KeychainEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []keychain.KeychainEntry
	for k := range s.secrets {
		svc, acct, _ := strings.Cut(k, "|")
		if !strings.HasPrefix(svc, prefix) {
			continue
		}
		out = append(out, keychain.KeychainEntry{
			Service:     svc,
			Account:     acct,
			Description: s.descs[k],
		})
	}
	return out, nil
}

func (s *inMemoryStore) DeleteEntry(account, service string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.secrets, s.key(account, service))
	delete(s.descs, s.key(account, service))
	return nil
}

func (s *inMemoryStore) SetDescription(service, account, description string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.descs[s.key(account, service)] = description
	return nil
}

// timestampedInMemoryStore wraps inMemoryStore with the TimestampedStore
// interface so tests can verify Manager's WithTimestamps path.
type timestampedInMemoryStore struct {
	*inMemoryStore
}

var _ keychain.TimestampedStore = (*timestampedInMemoryStore)(nil)

func (s *timestampedInMemoryStore) SetSecretAt(account, service string, secret []byte, createdAt, updatedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.key(account, service)
	s.secrets[k] = append([]byte{}, secret...)
	s.createdAts[k] = createdAt
	s.updatedAts[k] = updatedAt
	return nil
}

func (s *timestampedInMemoryStore) SetDescriptionAt(service, account, description string, updatedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.key(account, service)
	s.descs[k] = description
	s.updatedAts[k] = updatedAt
	return nil
}

func TestStorePassword_WithTimestamps_UsesTimestampedPath(t *testing.T) {
	store := &timestampedInMemoryStore{inMemoryStore: newInMemoryStore()}
	mgr := NewManager(store, "alice")

	created := time.Date(2025, 3, 10, 12, 0, 0, 0, time.UTC)
	updated := time.Date(2025, 9, 15, 18, 30, 0, 0, time.UTC)

	if err := mgr.StorePassword("github", "alice", []byte("pw1"), EntryTypePassword, WithTimestamps(created, updated)); err != nil {
		t.Fatal(err)
	}

	// Backend recorded the explicit timestamps via SetSecretAt /
	// SetDescriptionAt rather than time.Now().
	k := store.key("alice", "sesh-password/password/github/alice")
	if got := store.createdAts[k]; !got.Equal(created) {
		t.Errorf("createdAt = %v, want %v", got, created)
	}
	if got := store.updatedAts[k]; !got.Equal(updated) {
		t.Errorf("updatedAt = %v, want %v", got, updated)
	}
}

func TestStorePassword_WithTimestamps_AsymmetricZeroFieldsNormalizeToNow(t *testing.T) {
	// WithTimestamps(zero, updatedAt) must be honored at the Manager
	// boundary: the zero field should be replaced with "now" before
	// reaching the backend, not forwarded raw.
	store := &timestampedInMemoryStore{inMemoryStore: newInMemoryStore()}
	mgr := NewManager(store, "alice")

	updated := time.Date(2025, 9, 15, 18, 30, 0, 0, time.UTC)
	before := time.Now().UTC().Add(-time.Second)

	if err := mgr.StorePassword("github", "alice", []byte("pw1"), EntryTypePassword, WithTimestamps(time.Time{}, updated)); err != nil {
		t.Fatal(err)
	}

	k := store.key("alice", "sesh-password/password/github/alice")
	after := time.Now().UTC().Add(time.Second)

	if got := store.createdAts[k]; got.Before(before) || got.After(after) {
		t.Errorf("zero createdAt should normalize to now, got %v (expected in [%v, %v])", got, before, after)
	}
	if got := store.updatedAts[k]; !got.Equal(updated) {
		t.Errorf("updatedAt = %v, want %v", got, updated)
	}
}

func TestStorePassword_WithoutTimestamps_UsesDefaultPath(t *testing.T) {
	// With the non-timestamped inMemoryStore, WithTimestamps should still
	// succeed silently — Manager type-asserts and falls back to the
	// untimestamped path when the backend doesn't support it.
	store := newInMemoryStore()
	mgr := NewManager(store, "alice")

	if err := mgr.StorePassword("github", "alice", []byte("pw1"), EntryTypePassword,
		WithTimestamps(time.Now(), time.Now())); err != nil {
		t.Fatalf("StorePassword: %v", err)
	}
	k := store.key("alice", "sesh-password/password/github/alice")
	if string(store.secrets[k]) != "pw1" {
		t.Errorf("secret = %q, want %q", store.secrets[k], "pw1")
	}
}

func TestExport_RejectsUnknownFormat(t *testing.T) {
	mgr := NewManager(newInMemoryStore(), "user")
	var buf bytes.Buffer
	_, err := mgr.Export(&buf, ExportOptions{Format: ExportFormat("yaml")})
	if err == nil {
		t.Fatal("expected error for unknown format, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported export format") {
		t.Errorf("error = %v, want contains 'unsupported export format'", err)
	}
}

func TestImport_RejectsUnknownFormat(t *testing.T) {
	mgr := NewManager(newInMemoryStore(), "user")
	_, err := mgr.Import(strings.NewReader("{}"), ImportOptions{Format: ExportFormat("xml")})
	if err == nil {
		t.Fatal("expected error for unknown format, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported import format") {
		t.Errorf("error = %v, want contains 'unsupported import format'", err)
	}
}

func TestExport_AcceptsEmptyFormatAsJSON(t *testing.T) {
	// Empty Format is a valid zero value (the default) and should be
	// treated as JSON — matches how callers that omit --format behave.
	store := newInMemoryStore()
	mgr := NewManager(store, "user")
	if err := mgr.StorePasswordString("github", "alice", "pw1", EntryTypePassword); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	count, err := mgr.Export(&buf, ExportOptions{})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
	if !strings.HasPrefix(buf.String(), "[") {
		t.Errorf("output should look like a JSON array, got: %q", buf.String())
	}
}

// failingWriter errors once more than budget bytes have been written.
type failingWriter struct {
	budget int
	failed bool
}

func (f *failingWriter) Write(p []byte) (int, error) {
	if f.failed {
		return 0, errors.New("writer closed")
	}
	if len(p) <= f.budget {
		f.budget -= len(p)
		return len(p), nil
	}
	n := f.budget
	f.budget = 0
	f.failed = true
	return n, errors.New("write budget exhausted")
}

func TestExport_StreamsPartialCountOnWriterFailure(t *testing.T) {
	mgr := NewManager(newInMemoryStore(), "user")
	const total = 5
	for _, svc := range []string{"a", "b", "c", "d", "e"} {
		if err := mgr.StorePasswordString(svc, "alice", "secret-"+svc, EntryTypePassword); err != nil {
			t.Fatal(err)
		}
	}

	// A buffered-then-write implementation returns count=total regardless
	// of writer success; streaming must return a strictly smaller count
	// when the writer fails mid-way.
	fw := &failingWriter{budget: 200}
	count, err := mgr.Export(fw, ExportOptions{Format: FormatJSON})
	if err == nil {
		t.Fatal("expected error from truncated writer, got nil")
	}
	if count >= total {
		t.Fatalf("non-streaming: got count=%d (want < %d) after write failure", count, total)
	}
}
