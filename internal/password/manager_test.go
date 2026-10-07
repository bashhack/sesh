package password

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

func newTestManager(t *testing.T) (*Manager, *vault.MemStore) {
	t.Helper()
	store := vault.NewMemStore()
	return NewManager(store), store
}

// failingStore is a MemStore whose chosen methods fail.
type failingStore struct {
	*vault.MemStore
	lookupErr, saveErr error
}

func (f *failingStore) Put(k vault.Key, secret []byte) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	return f.MemStore.Put(k, secret)
}

func (f *failingStore) Save(e *vault.Entry, secret []byte) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	return f.MemStore.Save(e, secret)
}

func (f *failingStore) Exists(k vault.Key) error {
	if f.lookupErr != nil {
		return f.lookupErr
	}
	return f.MemStore.Exists(k)
}

func (f *failingStore) Lookup(k vault.Key) (vault.Entry, error) {
	if f.lookupErr != nil {
		return vault.Entry{}, f.lookupErr
	}
	return f.MemStore.Lookup(k)
}

func TestStoreAndGetPassword(t *testing.T) {
	m, store := newTestManager(t)
	if err := m.StorePasswordString("github", "alice", "pw-1", EntryTypePassword); err != nil {
		t.Fatal(err)
	}
	if err := m.StorePasswordString("openai", "", "sk-1", EntryTypeAPIKey); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		service, username string
		kind              EntryType
		want              string
	}{
		{"github", "alice", EntryTypePassword, "pw-1"},
		{"openai", "", EntryTypeAPIKey, "sk-1"},
	} {
		got, err := m.GetPasswordString(tt.service, tt.username, tt.kind)
		if err != nil || got != tt.want {
			t.Errorf("GetPasswordString(%s, %s, %s) = %q, %v; want %q", tt.service, tt.username, tt.kind, got, err, tt.want)
		}
	}
	if _, err := store.Get(vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}); err != nil {
		t.Errorf("the entry isn't in the store under its key: %v", err)
	}

	// Storing again replaces the secret.
	if err := m.StorePasswordString("github", "alice", "pw-2", EntryTypePassword); err != nil {
		t.Fatal(err)
	}
	if got, err := m.GetPasswordString("github", "alice", EntryTypePassword); err != nil || got != "pw-2" {
		t.Errorf("after storing again: %q, %v; want pw-2", got, err)
	}
}

func TestGetPassword_Missing(t *testing.T) {
	m, _ := newTestManager(t)
	// Same name, another kind, is another entry.
	if err := m.StorePasswordString("github", "alice", "pw", EntryTypePassword); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetPassword("github", "alice", EntryTypeAPIKey); !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("GetPassword of a missing entry = %v, want ErrNotFound", err)
	}
}

func TestStoreTOTPSecret(t *testing.T) {
	m, store := newTestManager(t)
	k := vault.Key{Kind: vault.KindTOTP, Service: "bank", Username: "me"}

	if err := m.StoreTOTPSecret("bank", "me", "jbsw y3dp ehpk 3pxp"); err != nil {
		t.Fatal(err)
	}
	if got, err := m.GetPasswordString("bank", "me", EntryTypeTOTP); err != nil || got != "JBSWY3DPEHPK3PXP" {
		t.Errorf("stored secret = %q, %v; want it normalized", got, err)
	}

	params := totp.Params{Digits: 8, Algorithm: "SHA256"}
	if err := m.StoreTOTPSecretWithParams("bank", "me", "JBSWY3DPEHPK3PXP", params, vault.Filing{}); err != nil {
		t.Fatal(err)
	}
	if e, err := store.Lookup(k); err != nil || e.Settings.TOTP != params {
		t.Errorf("code settings = %+v, %v; want %+v", e.Settings.TOTP, err, params)
	}

	// Storing again with the usual settings clears them, but keeps the
	// entry's other settings.
	if err := store.SetSettings(k, vault.Settings{TOTP: params, AWSMFADevice: "arn:aws:iam::1:mfa/me"}); err != nil {
		t.Fatal(err)
	}
	before, err := store.Lookup(k)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.StoreTOTPSecret("bank", "me", "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatal(err)
	}
	e, err := store.Lookup(k)
	if err != nil {
		t.Fatal(err)
	}
	if !e.CreatedAt.Equal(before.CreatedAt) {
		t.Errorf("created %v, want %v kept", e.CreatedAt, before.CreatedAt)
	}
	if e.Settings != (vault.Settings{AWSMFADevice: "arn:aws:iam::1:mfa/me"}) {
		t.Errorf("settings = %+v, want the code settings cleared and the device kept", e.Settings)
	}

	if err := m.StoreTOTPSecret("bank", "me", "not base32!"); err == nil || !strings.Contains(err.Error(), "invalid TOTP secret") {
		t.Errorf("an invalid secret: err = %v", err)
	}
}

// A failed store leaves the entry as it was, never the new secret with the
// old code settings.
func TestStoreTOTPSecret_FailureLeavesTheEntry(t *testing.T) {
	k := vault.Key{Kind: vault.KindTOTP, Service: "bank", Username: "me"}
	old := vault.Settings{TOTP: totp.Params{Digits: 8}}
	for name, store := range map[string]*failingStore{
		"write fails": {MemStore: vault.NewMemStore(), saveErr: errors.New("disk full")},
	} {
		t.Run(name, func(t *testing.T) {
			if err := store.MemStore.Save(&vault.Entry{Key: k, Settings: old}, []byte("OLDSECRETOLDSECR")); err != nil {
				t.Fatal(err)
			}
			err := NewManager(store).StoreTOTPSecretWithParams("bank", "me", "JBSWY3DPEHPK3PXP", totp.Params{}, vault.Filing{})
			secret, gerr := store.Get(k)
			e, lerr := store.Lookup(k)
			if gerr != nil || lerr != nil {
				t.Fatal(gerr, lerr)
			}
			switch {
			case err == nil && (string(secret) != "JBSWY3DPEHPK3PXP" || e.Settings != vault.Settings{}):
				t.Errorf("stored without error but entry = %q, %+v; want the new secret and settings", secret, e.Settings)
			case err != nil && (string(secret) != "OLDSECRETOLDSECR" || e.Settings != old):
				t.Errorf("err = %v, but entry = %q, %+v; want it unchanged", err, secret, e.Settings)
			case err != nil && !strings.Contains(err.Error(), "disk full"):
				t.Errorf("err = %v, want the cause", err)
			}
		})
	}
}

func TestGenerateTOTPCode_UsesTheCodeSettings(t *testing.T) {
	m, _ := newTestManager(t)
	params := totp.Params{Digits: 8, Algorithm: "SHA256"}
	if err := m.StoreTOTPSecretWithParams("bank", "me", "JBSWY3DPEHPK3PXP", params, vault.Filing{}); err != nil {
		t.Fatal(err)
	}
	before, after, err := totp.GenerateConsecutiveCodesBytesWithParams([]byte("JBSWY3DPEHPK3PXP"), params)
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.GenerateTOTPCode("bank", "me")
	if err != nil {
		t.Fatal(err)
	}
	if got != before && got != after {
		t.Errorf("code = %q, want the 8-digit SHA-256 code (%s or %s)", got, before, after)
	}
	if _, err := m.GenerateTOTPCode("nope", ""); err == nil {
		t.Error("a missing entry gave a code")
	}
}

func TestListEntries(t *testing.T) {
	m, store := newTestManager(t)
	created := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	if err := store.Save(&vault.Entry{Kind: vault.KindAPIKey, Service: "openai", CreatedAt: created, UpdatedAt: created}, []byte("k")); err != nil {
		t.Fatal(err)
	}
	if err := m.StorePasswordString("github", "alice", "pw", EntryTypePassword); err != nil {
		t.Fatal(err)
	}
	entries, err := m.ListEntries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("ListEntries = %+v, want 2 entries", entries)
	}
	want := Entry{ID: "api_key/openai", Service: "openai", Type: EntryTypeAPIKey, CreatedAt: created, UpdatedAt: created}
	if !reflect.DeepEqual(entries[0], want) {
		t.Errorf("first entry = %+v, want %+v", entries[0], want)
	}
	if entries[1].ID != "password/github/alice" || entries[1].Username != "alice" {
		t.Errorf("second entry = %+v, want password/github/alice", entries[1])
	}
}

func TestListEntriesFiltered(t *testing.T) {
	m, store := newTestManager(t)
	day := func(n int) time.Time { return time.Date(2026, 1, n, 0, 0, 0, 0, time.UTC) }
	for i, k := range []vault.Key{
		{Kind: vault.KindPassword, Service: "github", Username: "user1"}, // created day 3, updated day 1
		{Kind: vault.KindAPIKey, Service: "stripe"},                      // created day 2, updated day 2
		{Kind: vault.KindPassword, Service: "gitlab", Username: "user2"}, // created day 1, updated day 3
	} {
		if err := store.Save(&vault.Entry{Key: k, CreatedAt: day(3 - i), UpdatedAt: day(i + 1)}, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	for name, tt := range map[string]struct {
		want   string
		filter ListFilter
	}{
		"all, by service":         {"github gitlab stripe", ListFilter{}},
		"by type":                 {"github gitlab", ListFilter{EntryType: EntryTypePassword}},
		"by service, any case":    {"gitlab", ListFilter{Service: "GitLab"}},
		"by creation":             {"gitlab stripe github", ListFilter{SortBy: SortByCreatedAt}},
		"by update":               {"github stripe gitlab", ListFilter{SortBy: SortByUpdatedAt}},
		"limit":                   {"github gitlab", ListFilter{Limit: 2}},
		"offset and limit":        {"gitlab", ListFilter{Offset: 1, Limit: 1}},
		"offset past the entries": {"", ListFilter{Offset: 10}},
	} {
		t.Run(name, func(t *testing.T) {
			entries, err := m.ListEntriesFiltered(&tt.filter)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for i := range entries {
				got = append(got, entries[i].Service)
			}
			if strings.Join(got, " ") != tt.want {
				t.Errorf("services = %v, want %s", got, tt.want)
			}
		})
	}
}

func TestGetPasswordsByService(t *testing.T) {
	m, _ := newTestManager(t)
	for _, e := range []struct {
		service, username string
		kind              EntryType
	}{
		{"github", "user1", EntryTypePassword},
		{"github", "ci", EntryTypeAPIKey},
		{"github", "backup", EntryTypeNote},
		{"stripe", "admin", EntryTypePassword},
		{"github", "user2", EntryTypePassword},
	} {
		if err := m.StorePasswordString(e.service, e.username, "x", e.kind); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := m.GetPasswordsByService("github")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Type != EntryTypePassword || entries[1].Type != EntryTypePassword {
		t.Errorf("GetPasswordsByService = %+v, want github's two passwords only", entries)
	}
}

func TestEntryExists(t *testing.T) {
	m, _ := newTestManager(t)
	if err := m.StorePasswordString("github", "alice", "pw", EntryTypePassword); err != nil {
		t.Fatal(err)
	}
	if ok, err := m.EntryExists("github", "alice", EntryTypePassword); !ok || err != nil {
		t.Errorf("EntryExists = %v, %v; want true", ok, err)
	}
	if ok, err := m.EntryExists("github", "alicia", EntryTypePassword); ok || err != nil {
		t.Errorf("EntryExists of another name = %v, %v; want false", ok, err)
	}

	failing := NewManager(&failingStore{MemStore: vault.NewMemStore(), lookupErr: errors.New("vault locked")})
	if ok, err := failing.EntryExists("github", "alice", EntryTypePassword); ok || err == nil || !strings.Contains(err.Error(), "vault locked") {
		t.Errorf("EntryExists when the store fails = %v, %v; want the error", ok, err)
	}
}

// Storing with a filing moves the entry and adds tags, keeping its
// settings and creation time; storing without one leaves it filed as it was.
func TestStorePassword_Files(t *testing.T) {
	m, store := newTestManager(t)
	k := vault.Key{Kind: vault.KindTOTP, Service: "bank", Username: "me"}
	created := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	settings := vault.Settings{TOTP: totp.Params{Digits: 8}}
	if err := store.Save(&vault.Entry{Key: k, Folder: "old", Tags: []string{"a"}, Settings: settings, CreatedAt: created}, []byte("JBSWY3DPEHPK3PXP")); err != nil {
		t.Fatal(err)
	}
	check := func(when, folder string, tags ...string) {
		t.Helper()
		e, err := store.Lookup(k)
		if err != nil {
			t.Fatal(err)
		}
		if e.Folder != folder || !slices.Equal(e.Tags, tags) || e.Settings != settings || !e.CreatedAt.Equal(created) {
			t.Errorf("%s: %+v; want folder %q, tags %q, settings and creation time kept", when, e, folder, tags)
		}
	}
	if err := m.StorePassword("bank", "me", []byte("GEZDGNBVGY3TQOJQ"), EntryTypeTOTP, vault.Filing{Tags: []string{"b"}}); err != nil {
		t.Fatal(err)
	}
	check("tags only", "old", "a", "b")
	if err := m.StorePassword("bank", "me", []byte("GEZDGNBVGY3TQOJQ"), EntryTypeTOTP, vault.Filing{Folder: "work", FolderSet: true}); err != nil {
		t.Fatal(err)
	}
	check("a folder", "work", "a", "b")
	if err := m.StorePassword("bank", "me", []byte("GEZDGNBVGY3TQOJQ"), EntryTypeTOTP, vault.Filing{}); err != nil {
		t.Fatal(err)
	}
	check("no filing", "work", "a", "b")
	if err := m.StorePassword("bank", "me", []byte("GEZDGNBVGY3TQOJQ"), EntryTypeTOTP, vault.Filing{FolderSet: true}); err != nil {
		t.Fatal(err)
	}
	check(`--folder ""`, "", "a", "b")
	if secret, err := store.Get(k); err != nil || string(secret) != "GEZDGNBVGY3TQOJQ" {
		t.Errorf("secret = %q, %v", secret, err)
	}

	// A new entry, and a bad tag.
	if err := m.StorePassword("new", "", []byte("pw"), EntryTypePassword, vault.Filing{Folder: "home", FolderSet: true, Tags: []string{"x"}}); err != nil {
		t.Fatal(err)
	}
	if e, err := m.LookupEntry("new", "", EntryTypePassword); err != nil || e.Folder != "home" || !slices.Equal(e.Tags, []string{"x"}) {
		t.Errorf("new entry = %+v, %v", e, err)
	}
	if err := m.StorePassword("new", "", []byte("pw"), EntryTypePassword, vault.Filing{Tags: []string{"a b"}}); err == nil || !strings.Contains(err.Error(), `the tag "a b" contains ' '`) {
		t.Errorf("a bad tag: err = %v", err)
	}
}

func TestStoreTOTPSecretWithParams_Files(t *testing.T) {
	m, store := newTestManager(t)
	if err := m.StoreTOTPSecretWithParams("bank", "me", "JBSWY3DPEHPK3PXP", totp.Params{Digits: 8}, vault.Filing{Folder: "money", FolderSet: true, Tags: []string{"2fa"}}); err != nil {
		t.Fatal(err)
	}
	e, err := store.Lookup(vault.Key{Kind: vault.KindTOTP, Service: "bank", Username: "me"})
	if err != nil || e.Folder != "money" || !slices.Equal(e.Tags, []string{"2fa"}) || e.Settings.TOTP.Digits != 8 {
		t.Errorf("entry = %+v, %v", e, err)
	}
}

func TestDeleteEntry(t *testing.T) {
	m, _ := newTestManager(t)
	if err := m.StorePasswordString("github", "alice", "pw", EntryTypePassword); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteEntry("github", "alice", EntryTypePassword); err != nil {
		t.Fatal(err)
	}
	if ok, err := m.EntryExists("github", "alice", EntryTypePassword); ok || err != nil {
		t.Errorf("EntryExists after deleting = %v, %v; want false", ok, err)
	}
	if err := m.DeleteEntry("github", "alice", EntryTypePassword); !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("deleting a missing entry = %v, want ErrNotFound", err)
	}
}

func TestGenerateTOTPCode_FailsIfTheCodeSettingsCantBeRead(t *testing.T) {
	mem := vault.NewMemStore()
	if err := mem.Put(vault.Key{Kind: vault.KindTOTP, Service: "bank"}, []byte("JBSWY3DPEHPK3PXP")); err != nil {
		t.Fatal(err)
	}
	m := NewManager(&failingStore{MemStore: mem, lookupErr: errors.New("settings unreadable")})
	if _, err := m.GenerateTOTPCode("bank", ""); err == nil || !strings.Contains(err.Error(), "settings unreadable") {
		t.Errorf("GenerateTOTPCode = %v, want the settings error rather than a code from the default settings", err)
	}
}

// A lookup that misses only by case says which entry it may have meant.
func TestLookups_SuggestANameInAnotherCase(t *testing.T) {
	m, _ := newTestManager(t)
	if err := m.StorePasswordString("GitHub", "alice", "pw", EntryTypePassword); err != nil {
		t.Fatal(err)
	}
	if err := m.StoreTOTPSecret("GitHub", "alice", "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatal(err)
	}
	_, err := m.GetPassword("github", "alice", EntryTypePassword)
	if !errors.Is(err, vault.ErrNotFound) || !strings.Contains(err.Error(), "did you mean GitHub (alice)? Names are case-sensitive") {
		t.Errorf("GetPassword = %v, want not found with the suggestion", err)
	}
	_, err = m.GenerateTOTPCode("github", "ALICE")
	if !errors.Is(err, vault.ErrNotFound) || !strings.Contains(err.Error(), "did you mean GitHub (alice)?") {
		t.Errorf("GenerateTOTPCode = %v, want not found with the suggestion", err)
	}
	if _, err := m.GetPassword("gitlab", "", EntryTypePassword); err == nil || strings.Contains(err.Error(), "did you mean") {
		t.Errorf("GetPassword of an unrelated name = %v, want plain not found", err)
	}
	twins, err := m.CaseTwins(vault.Key{Kind: vault.KindPassword, Service: "GITHUB", Username: "Alice"})
	if err != nil || len(twins) != 1 || twins[0].Service != "GitHub" {
		t.Errorf("CaseTwins = %v, %v; want GitHub (alice)", twins, err)
	}
}
