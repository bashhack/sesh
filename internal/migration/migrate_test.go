package migration

import (
	"errors"
	"strings"
	"testing"

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
	source.add("sesh-password/pw/thing", []byte("should-not-appear"), "")

	plan, err := Plan(source.provider())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 3 {
		t.Fatalf("expected 3 entries in plan, got %d", len(plan))
	}
}

func TestMigrate(t *testing.T) {
	source := newEntryStore()
	source.add("sesh-totp/github", []byte("totp-secret-1"), "TOTP for GitHub")
	source.add("sesh-totp/gitlab", []byte("totp-secret-2"), "")
	source.add("sesh-aws/prod", []byte("aws-secret"), "")
	source.add("sesh-aws-serial/prod", []byte("arn:aws:iam::123:mfa/user"), "")

	dest := newEntryStore()

	result, err := Migrate(source.provider(), dest.provider())
	if err != nil {
		t.Fatal(err)
	}
	if result.Migrated != 4 {
		t.Fatalf("expected 4 migrated, got %d", result.Migrated)
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
