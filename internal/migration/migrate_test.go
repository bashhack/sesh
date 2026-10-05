package migration

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

var (
	ghKey   = vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}
	bankKey = vault.Key{Kind: vault.KindTOTP, Service: "bank", Username: "me"}
	awsKey  = vault.AWSKey("prod")
)

// sourceVault is a store holding a password, a TOTP entry with code
// settings, and an AWS entry with its device, all with set times.
func sourceVault(t *testing.T) (*vault.MemStore, []vault.Entry) {
	t.Helper()
	created := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2025, 6, 7, 8, 9, 10, 0, time.UTC)
	entries := []vault.Entry{
		{Key: ghKey, CreatedAt: created, UpdatedAt: updated},
		{Key: bankKey, Settings: vault.Settings{TOTP: totp.Params{Digits: 8, Algorithm: "SHA256"}}, CreatedAt: created, UpdatedAt: updated},
		{Key: awsKey, Settings: vault.Settings{AWSMFADevice: "arn:aws:iam::1:mfa/me"}, CreatedAt: created, UpdatedAt: updated},
	}
	s := vault.NewMemStore()
	for i := range entries {
		if err := s.Save(&entries[i], []byte("secret-"+entries[i].Service)); err != nil {
			t.Fatal(err)
		}
	}
	return s, entries
}

// failing is a MemStore whose methods fail for the keys in its maps.
type failing struct {
	*vault.MemStore
	get, lookup, save map[vault.Key]error
}

func (f *failing) Get(k vault.Key) ([]byte, error) {
	if err := f.get[k]; err != nil {
		return nil, err
	}
	return f.MemStore.Get(k)
}

func (f *failing) Lookup(k vault.Key) (vault.Entry, error) {
	if err := f.lookup[k]; err != nil {
		return vault.Entry{}, err
	}
	return f.MemStore.Lookup(k)
}

func (f *failing) Save(e *vault.Entry, secret []byte) error {
	if err := f.save[e.Key]; err != nil {
		return err
	}
	return f.MemStore.Save(e, secret)
}

func TestPlan(t *testing.T) {
	src, want := sourceVault(t)
	plan, err := Plan(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != len(want) {
		t.Fatalf("Plan = %+v, want %d entries", plan, len(want))
	}
	got := map[vault.Key]bool{}
	for i := range plan {
		got[plan[i].Key] = true
	}
	for i := range want {
		if !got[want[i].Key] {
			t.Errorf("Plan is missing %s", want[i].Key)
		}
	}
}

func TestMigrate_CopiesEverything(t *testing.T) {
	src, want := sourceVault(t)
	dest := vault.NewMemStore()
	res, err := Migrate(src, dest)
	if err != nil {
		t.Fatal(err)
	}
	if res.Migrated != len(want) || res.Skipped != 0 || len(res.Errors) != 0 {
		t.Fatalf("Migrate = %+v, want %d copied", res, len(want))
	}
	for i := range want {
		w := &want[i]
		got, err := dest.Lookup(w.Key)
		if err != nil {
			t.Fatalf("%s: %v", w.Key, err)
		}
		if got.Settings != w.Settings || !got.CreatedAt.Equal(w.CreatedAt) || !got.UpdatedAt.Equal(w.UpdatedAt) {
			t.Errorf("%s copied as %+v, want %+v", w.Key, got, *w)
		}
		if secret, err := dest.Get(w.Key); err != nil || string(secret) != "secret-"+w.Service {
			t.Errorf("%s: secret %q, %v", w.Key, secret, err)
		}
	}
}

func TestMigrate_SkipsWhatDestHasWithoutReadingIt(t *testing.T) {
	mem, _ := sourceVault(t)
	// Reading the skipped entry's secret from the source would fail.
	src := &failing{MemStore: mem, get: map[vault.Key]error{ghKey: errors.New("read a skipped secret")}}
	dest := vault.NewMemStore()
	if err := dest.Put(ghKey, []byte("already-there")); err != nil {
		t.Fatal(err)
	}
	res, err := Migrate(src, dest)
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped != 1 || res.Migrated != 2 || len(res.Errors) != 0 {
		t.Errorf("Migrate = %+v, want 1 skipped, 2 copied, no errors", res)
	}
	if got, err := dest.Get(ghKey); err != nil || string(got) != "already-there" {
		t.Errorf("the existing entry became %q, %v; want it kept", got, err)
	}
}

func TestMigrate_PerEntryErrors(t *testing.T) {
	for name, tt := range map[string]struct {
		srcGet, destLookup, destSave map[vault.Key]error
		wantSub                      string
	}{
		"dest lookup fails": {destLookup: map[vault.Key]error{ghKey: errors.New("vault locked")}, wantSub: "failed to check destination: vault locked"},
		"source read fails": {srcGet: map[vault.Key]error{ghKey: errors.New("bad ciphertext")}, wantSub: "failed to read: bad ciphertext"},
		"dest write fails":  {destSave: map[vault.Key]error{ghKey: errors.New("disk full")}, wantSub: "failed to write: disk full"},
	} {
		t.Run(name, func(t *testing.T) {
			mem, _ := sourceVault(t)
			src := &failing{MemStore: mem, get: tt.srcGet}
			destMem := vault.NewMemStore()
			dest := &failing{MemStore: destMem, lookup: tt.destLookup, save: tt.destSave}
			res, err := Migrate(src, dest)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Errors) != 1 || !strings.Contains(res.Errors[0], ghKey.String()) || !strings.Contains(res.Errors[0], tt.wantSub) {
				t.Errorf("Errors = %q, want one naming %s and containing %q", res.Errors, ghKey, tt.wantSub)
			}
			if res.Migrated != 2 {
				t.Errorf("Migrated = %d, want the other 2 copied", res.Migrated)
			}
			if _, err := destMem.Lookup(ghKey); !errors.Is(err, vault.ErrNotFound) {
				t.Errorf("the failed entry is in dest: %v", err)
			}
		})
	}
}

func TestMigrate_Empty(t *testing.T) {
	res, err := Migrate(vault.NewMemStore(), vault.NewMemStore())
	if err != nil || res.Migrated != 0 || res.Skipped != 0 || len(res.Errors) != 0 {
		t.Errorf("Migrate of an empty vault = %+v, %v", res, err)
	}
}

// listFailing is a store that can't list its entries.
type listFailing struct{ *vault.MemStore }

func (listFailing) List(vault.Filter) ([]vault.Entry, error) {
	return nil, errors.New("vault unreadable")
}

func TestMigrate_SourceListFails(t *testing.T) {
	if _, err := Plan(listFailing{vault.NewMemStore()}); err == nil || !strings.Contains(err.Error(), "vault unreadable") {
		t.Errorf("Plan = %v, want the list error", err)
	}
	if _, err := Migrate(listFailing{vault.NewMemStore()}, vault.NewMemStore()); err == nil || !strings.Contains(err.Error(), "vault unreadable") {
		t.Errorf("Migrate = %v, want the list error", err)
	}
}
