package database

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// A rename re-seals the secret under the new name and keeps everything else
// about the entry: folder, tags, settings, and both times.
func TestEdit_Rename(t *testing.T) {
	_, s := rekeyVault(t)
	old := vault.Key{Kind: vault.KindTOTP, Service: "bank", Username: "me"}
	made := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	settings := vault.Settings{TOTP: totp.Params{Digits: 8}}
	if err := s.Save(&vault.Entry{Key: old, Folder: "money", Tags: []string{"2fa"}, Settings: settings, CreatedAt: made, UpdatedAt: made}, []byte("JBSWY3DPEHPK3PXP")); err != nil {
		t.Fatal(err)
	}
	to := vault.Key{Kind: vault.KindTOTP, Service: "Bank", Username: "me"} // only the case changes
	detail, err := s.Edit(old, EntryEdit{To: &to})
	if err != nil || detail != "renamed from totp/bank/me" {
		t.Fatalf("Edit = %q, %v", detail, err)
	}
	if _, err := s.Lookup(old); !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("the old name still finds it: %v", err)
	}
	e, err := s.Lookup(to)
	if err != nil || e.Folder != "money" || !slices.Equal(e.Tags, []string{"2fa"}) || e.Settings != settings || !e.CreatedAt.Equal(made) || !e.UpdatedAt.Equal(made) {
		t.Errorf("renamed entry = %+v, %v; want everything kept", e, err)
	}
	if secret, err := s.Get(to); err != nil || string(secret) != "JBSWY3DPEHPK3PXP" {
		t.Errorf("secret under the new name = %q, %v", secret, err)
	}
}

// A new secret moves the update time; a new kind re-seals the secret.
func TestEdit_SecretAndKind(t *testing.T) {
	_, s := rekeyVault(t)
	k := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	before, err := s.Lookup(k)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if detail, err := s.Edit(k, EntryEdit{Secret: []byte("new-secret")}); err != nil || detail != "secret changed" {
		t.Fatalf("new secret: %q, %v", detail, err)
	}
	after, err := s.Lookup(k)
	if err != nil || !after.UpdatedAt.After(before.UpdatedAt) {
		t.Errorf("update time %v, before %v; want later", after.UpdatedAt, before.UpdatedAt)
	}
	to := vault.Key{Kind: vault.KindAPIKey, Service: "bank-api", Username: "ci"}
	if detail, err := s.Edit(k, EntryEdit{To: &to, Secret: []byte("sk-1")}); err != nil || detail != "renamed from password/bank and secret changed" {
		t.Fatalf("rename and new secret: %q, %v", detail, err)
	}
	if secret, err := s.Get(to); err != nil || string(secret) != "sk-1" {
		t.Errorf("secret = %q, %v", secret, err)
	}
}

func TestEdit_Refusals(t *testing.T) {
	_, s := rekeyVault(t)
	bank := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	other := vault.Key{Kind: vault.KindPassword, Service: "other"}
	if err := s.Put(other, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Edit(bank, EntryEdit{To: &other}); !errors.Is(err, ErrNameTaken) || !strings.Contains(err.Error(), "password/other") {
		t.Errorf("onto another entry's name: %v", err)
	}
	missing := vault.Key{Kind: vault.KindPassword, Service: "missing"}
	if _, err := s.Edit(missing, EntryEdit{Secret: []byte("x")}); !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("a missing entry: %v", err)
	}
	if _, err := s.Edit(bank, EntryEdit{}); err == nil {
		t.Error("an edit that changes nothing succeeded")
	}
	bad := vault.Key{Kind: vault.KindPassword, Service: "a/b"}
	if _, err := s.Edit(bank, EntryEdit{To: &bad}); err == nil {
		t.Error("a bad name was accepted")
	}
	if secret, err := s.Get(bank); err != nil || string(secret) != "bank-secret" {
		t.Errorf("bank after refusals = %q, %v; want it unchanged", secret, err)
	}
}

// meddlingOracle changes the entry, as another sesh command would, while the
// edit seals its secret.
type meddlingOracle struct {
	CryptoOracle
	meddle func()
}

func (o *meddlingOracle) UnlockID() (string, error) {
	return o.CryptoOracle.(interface{ UnlockID() (string, error) }).UnlockID()
}

func (o *meddlingOracle) EncryptEntry(plain, aad []byte) ([]byte, []byte, error) {
	o.meddle()
	return o.CryptoOracle.EncryptEntry(plain, aad)
}

// An entry changed while its edit was being sealed isn't overwritten.
func TestEdit_EntryChangedMeanwhile(t *testing.T) {
	p, s := rekeyVault(t)
	bank := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	other, err := Open(p, NewKeySourceOracle(NewMasterPasswordSource(p, staticPrompt("old-password-1", "old-password-1"))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() }) //nolint:errcheck // test cleanup
	base := NewKeySourceOracle(NewMasterPasswordSource(p, staticPrompt("old-password-1", "old-password-1")))
	o := &meddlingOracle{CryptoOracle: base, meddle: func() {
		if err := other.Put(bank, []byte("stored meanwhile")); err != nil {
			t.Error(err)
		}
	}}
	s2, err := Open(p, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s2.Close() }) //nolint:errcheck // test cleanup
	if _, err := s2.Edit(bank, EntryEdit{Secret: []byte("edited")}); !errors.Is(err, ErrEntryChanged) {
		t.Errorf("Edit = %v, want ErrEntryChanged", err)
	}
	if secret, err := other.Get(bank); err != nil || string(secret) != "stored meanwhile" {
		t.Errorf("bank = %q, %v; want the other command's secret kept", secret, err)
	}
}
