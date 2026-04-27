package migration

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/keychain/mocks"
)

// entryStore is a simple in-memory credential store for testing migration.
type entryStore struct {
	data         map[string][]byte
	descriptions map[string]string
	accounts     map[string]string
}

func newEntryStore() *entryStore {
	return &entryStore{
		data:         make(map[string][]byte),
		descriptions: make(map[string]string),
		accounts:     make(map[string]string),
	}
}

func (s *entryStore) add(service string, secret []byte, description string) {
	s.data[service] = secret
	s.accounts[service] = "testuser"
	if description != "" {
		s.descriptions[service] = description
	}
}

func (s *entryStore) provider() *mocks.MockProvider {
	return &mocks.MockProvider{
		ListEntriesFunc: func(prefix string) ([]keychain.KeychainEntry, error) {
			var entries []keychain.KeychainEntry
			for svc := range s.data {
				serviceType, _, _ := strings.Cut(svc, "/")
				if serviceType == prefix {
					entries = append(entries, keychain.KeychainEntry{
						Service:     svc,
						Account:     s.accounts[svc],
						Description: s.descriptions[svc],
					})
				}
			}
			return entries, nil
		},
		GetSecretFunc: func(account, service string) ([]byte, error) {
			v, ok := s.data[service]
			if !ok {
				return nil, keychain.ErrNotFound
			}
			cp := make([]byte, len(v))
			copy(cp, v)
			return cp, nil
		},
		SetSecretFunc: func(account, service string, secret []byte) error {
			cp := make([]byte, len(secret))
			copy(cp, secret)
			s.data[service] = cp
			s.accounts[service] = account
			return nil
		},
		SetDescriptionFunc: func(service, account, description string) error {
			s.descriptions[service] = description
			return nil
		},
	}
}

func TestPlan(t *testing.T) {
	source := newEntryStore()
	source.add("sesh-totp/github", []byte("totp-secret"), "TOTP for GitHub")
	source.add("sesh-aws/prod", []byte("aws-secret"), "")
	source.add("sesh-aws-serial/prod", []byte("arn:aws:iam::123:mfa/user"), "")
	source.add("sesh-password/api_key/stripe/admin", []byte("sk_test_fake"), "Stripe API key")
	source.add("sesh-other/leave-me", []byte("ignored"), "")

	plan, err := Plan(source.provider())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 4 {
		t.Fatalf("expected 4 entries in plan, got %d: %+v", len(plan), plan)
	}
}

func TestMigrate(t *testing.T) {
	source := newEntryStore()
	source.add("sesh-totp/github", []byte("totp-secret-1"), "TOTP for GitHub")
	source.add("sesh-totp/gitlab", []byte("totp-secret-2"), "")
	source.add("sesh-aws/prod", []byte("aws-secret"), "")
	source.add("sesh-aws-serial/prod", []byte("arn:aws:iam::123:mfa/user"), "")
	source.add("sesh-password/password/github/alice", []byte("hunter2"), "GitHub password")

	dest := newEntryStore()

	result, err := Migrate(source.provider(), dest.provider())
	if err != nil {
		t.Fatal(err)
	}
	if result.Migrated != 5 {
		t.Fatalf("expected 5 migrated, got %d", result.Migrated)
	}
	if result.Skipped != 0 {
		t.Fatalf("expected 0 skipped, got %d", result.Skipped)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("expected 0 errors, got %v", result.Errors)
	}
	if string(dest.data["sesh-totp/github"]) != "totp-secret-1" {
		t.Fatalf("expected totp-secret-1, got %q", dest.data["sesh-totp/github"])
	}
	if dest.descriptions["sesh-totp/github"] != "TOTP for GitHub" {
		t.Fatalf("expected description preserved, got %q", dest.descriptions["sesh-totp/github"])
	}
	// Password-provider entries must be migrated too so users switching
	// backends don't silently leave credentials behind on the keychain.
	if string(dest.data["sesh-password/password/github/alice"]) != "hunter2" {
		t.Fatalf("password entry not migrated: %q", dest.data["sesh-password/password/github/alice"])
	}
}

func TestMigrateSkipsExisting(t *testing.T) {
	source := newEntryStore()
	source.add("sesh-totp/github", []byte("source-secret"), "")

	dest := newEntryStore()
	dest.add("sesh-totp/github", []byte("existing-secret"), "")

	result, err := Migrate(source.provider(), dest.provider())
	if err != nil {
		t.Fatal(err)
	}
	if result.Migrated != 0 {
		t.Fatalf("expected 0 migrated, got %d", result.Migrated)
	}
	if result.Skipped != 1 {
		t.Fatalf("expected 1 skipped, got %d", result.Skipped)
	}
	if string(dest.data["sesh-totp/github"]) != "existing-secret" {
		t.Fatal("existing entry should not be overwritten")
	}
}

func TestMigrateReportsAmbiguousDestError(t *testing.T) {
	// An ambiguous error from dest.GetSecret (not ErrNotFound) must not be
	// mistaken for "entry doesn't exist" — otherwise the migrator would
	// happily overwrite real data on transient I/O or decrypt failures.
	source := newEntryStore()
	source.add("sesh-totp/github", []byte("source-secret"), "")

	sentinel := errors.New("transient decrypt failure")
	setCalled := false
	dest := &mocks.MockProvider{
		GetSecretFunc: func(account, service string) ([]byte, error) {
			return nil, sentinel
		},
		SetSecretFunc: func(account, service string, secret []byte) error {
			setCalled = true
			return nil
		},
	}

	result, err := Migrate(source.provider(), dest)
	if err != nil {
		t.Fatal(err)
	}
	if setCalled {
		t.Fatal("SetSecret must not be called when GetSecret returned an ambiguous error")
	}
	if result.Migrated != 0 {
		t.Fatalf("expected 0 migrated, got %d", result.Migrated)
	}
	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error, got %v", result.Errors)
	}
	if !strings.Contains(result.Errors[0], "transient decrypt failure") {
		t.Fatalf("error should mention the underlying cause, got %q", result.Errors[0])
	}
}

// prefixMatchStore simulates a SQLite-backed source whose ListEntries is
// a byte-prefix range query — so ListEntries("sesh-aws") also returns
// any entries under "sesh-aws-serial" (since one is a prefix of the
// other). Used to verify Plan/Migrate dedupe by (service, account).
type prefixMatchStore struct {
	data map[string][]byte
}

func (s *prefixMatchStore) GetSecret(_, service string) ([]byte, error) {
	v, ok := s.data[service]
	if !ok {
		return nil, keychain.ErrNotFound
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, nil
}
func (s *prefixMatchStore) SetSecret(_, _ string, _ []byte) error       { return nil }
func (s *prefixMatchStore) GetSecretString(_, _ string) (string, error) { return "", nil }
func (s *prefixMatchStore) SetSecretString(_, _, _ string) error        { return nil }
func (s *prefixMatchStore) GetMFASerialBytes(_, _ string) ([]byte, error) {
	return nil, keychain.ErrNotFound
}
func (s *prefixMatchStore) ListEntries(prefix string) ([]keychain.KeychainEntry, error) {
	var out []keychain.KeychainEntry
	for svc := range s.data {
		if strings.HasPrefix(svc, prefix) {
			out = append(out, keychain.KeychainEntry{Service: svc, Account: "testuser"})
		}
	}
	return out, nil
}
func (s *prefixMatchStore) DeleteEntry(_, _ string) error       { return nil }
func (s *prefixMatchStore) SetDescription(_, _, _ string) error { return nil }

func TestPlanDedupesOverlappingPrefixes(t *testing.T) {
	// "sesh-aws" is a byte-prefix of "sesh-aws-serial"; with a
	// prefix-range-matching source, a naive Plan would return the serial
	// entry under both the AWS prefix and the AWS-serial prefix.
	src := &prefixMatchStore{
		data: map[string][]byte{
			"sesh-aws/prod":                  []byte("x"),
			"sesh-aws-serial/prod":           []byte("y"),
			"sesh-totp/github":               []byte("z"),
			"sesh-password/password/a/alice": []byte("p"),
		},
	}

	plan, err := Plan(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 4 {
		t.Fatalf("expected 4 unique entries in plan, got %d: %+v", len(plan), plan)
	}
}

func TestMigrateDedupesOverlappingPrefixes(t *testing.T) {
	src := &prefixMatchStore{
		data: map[string][]byte{
			"sesh-aws/prod":        []byte("x"),
			"sesh-aws-serial/prod": []byte("y"),
		},
	}

	var setCount int
	dest := &mocks.MockProvider{
		GetSecretFunc: func(_, _ string) ([]byte, error) { return nil, keychain.ErrNotFound },
		SetSecretFunc: func(_, _ string, _ []byte) error { setCount++; return nil },
	}

	result, err := Migrate(src, dest)
	if err != nil {
		t.Fatal(err)
	}
	if result.Migrated != 2 {
		t.Errorf("Migrated = %d, want 2 (one per unique entry)", result.Migrated)
	}
	if result.Skipped != 0 {
		t.Errorf("Skipped = %d, want 0 — a dedupe miss would visit aws-serial twice and skip the second pass", result.Skipped)
	}
	if setCount != 2 {
		t.Errorf("SetSecret call count = %d, want 2", setCount)
	}
}

func TestMigratePreservesTimestampsWhenDestSupportsThem(t *testing.T) {
	createdAt := time.Date(2024, 3, 15, 10, 30, 0, 0, time.UTC)
	updatedAt := time.Date(2025, 1, 20, 14, 0, 0, 0, time.UTC)

	source := &mocks.MockProvider{
		ListEntriesFunc: func(prefix string) ([]keychain.KeychainEntry, error) {
			if prefix != "sesh-totp" {
				return nil, nil
			}
			return []keychain.KeychainEntry{{
				Service:     "sesh-totp/github",
				Account:     "alice",
				Description: "TOTP for GitHub",
				CreatedAt:   createdAt,
				UpdatedAt:   updatedAt,
			}}, nil
		},
		GetSecretFunc: func(_, _ string) ([]byte, error) {
			return []byte("totp-secret"), nil
		},
	}

	var gotCreated, gotUpdated, gotDescUpdated time.Time
	dest := &mocks.MockProvider{
		GetSecretFunc: func(_, _ string) ([]byte, error) { return nil, keychain.ErrNotFound },
		SetSecretAtFunc: func(_, _ string, _ []byte, c, u time.Time) error {
			gotCreated, gotUpdated = c, u
			return nil
		},
		SetDescriptionAtFunc: func(_, _, _ string, u time.Time) error {
			gotDescUpdated = u
			return nil
		},
	}

	result, err := Migrate(source, dest)
	if err != nil {
		t.Fatal(err)
	}
	if result.Migrated != 1 {
		t.Fatalf("Migrated = %d, want 1", result.Migrated)
	}
	if !gotCreated.Equal(createdAt) {
		t.Errorf("CreatedAt = %v, want %v", gotCreated, createdAt)
	}
	if !gotUpdated.Equal(updatedAt) {
		t.Errorf("UpdatedAt on SetSecretAt = %v, want %v", gotUpdated, updatedAt)
	}
	if !gotDescUpdated.Equal(updatedAt) {
		t.Errorf("UpdatedAt on SetDescriptionAt = %v, want %v", gotDescUpdated, updatedAt)
	}
}

// bareDest implements keychain.Provider but explicitly NOT
// keychain.TimestampedStore — used to exercise Migrate's fallback path.
type bareDest struct {
	lastDescription  string
	setSecretCalls   int
	descriptionCalls int
}

func (d *bareDest) GetSecret(_, _ string) ([]byte, error) {
	return nil, keychain.ErrNotFound
}

func (d *bareDest) SetSecret(_, _ string, _ []byte) error {
	d.setSecretCalls++
	return nil
}

func (d *bareDest) GetSecretString(_, _ string) (string, error)            { return "", nil }
func (d *bareDest) SetSecretString(_, _, _ string) error                   { return nil }
func (d *bareDest) GetMFASerialBytes(_, _ string) ([]byte, error)          { return nil, keychain.ErrNotFound }
func (d *bareDest) ListEntries(_ string) ([]keychain.KeychainEntry, error) { return nil, nil }
func (d *bareDest) DeleteEntry(_, _ string) error                          { return nil }
func (d *bareDest) SetDescription(_, _, description string) error {
	d.descriptionCalls++
	d.lastDescription = description
	return nil
}

func TestMigrateFallsBackToBareSetSecretWhenDestNotTimestamped(t *testing.T) {
	source := &mocks.MockProvider{
		ListEntriesFunc: func(prefix string) ([]keychain.KeychainEntry, error) {
			if prefix != "sesh-totp" {
				return nil, nil
			}
			return []keychain.KeychainEntry{{
				Service:     "sesh-totp/github",
				Account:     "alice",
				Description: "TOTP",
				CreatedAt:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
				UpdatedAt:   time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC),
			}}, nil
		},
		GetSecretFunc: func(_, _ string) ([]byte, error) { return []byte("s"), nil },
	}

	dest := &bareDest{}
	result, err := Migrate(source, dest)
	if err != nil {
		t.Fatal(err)
	}
	if result.Migrated != 1 {
		t.Fatalf("Migrated = %d, want 1", result.Migrated)
	}
	if dest.setSecretCalls != 1 {
		t.Errorf("SetSecret calls = %d, want 1 (fallback path)", dest.setSecretCalls)
	}
	if dest.descriptionCalls != 1 {
		t.Errorf("SetDescription calls = %d, want 1", dest.descriptionCalls)
	}
	if dest.lastDescription != "TOTP" {
		t.Errorf("description = %q, want TOTP", dest.lastDescription)
	}
}

func TestMigrateEmpty(t *testing.T) {
	source := newEntryStore()
	dest := newEntryStore()

	result, err := Migrate(source.provider(), dest.provider())
	if err != nil {
		t.Fatal(err)
	}
	if result.Migrated != 0 || result.Skipped != 0 || len(result.Errors) != 0 {
		t.Fatalf("expected empty result, got %+v", result)
	}
}
