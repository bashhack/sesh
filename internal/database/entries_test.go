package database

import (
	"slices"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/vault"
	"github.com/bashhack/sesh/internal/vault/vaulttest"
)

func TestStore_IsAVaultStore(t *testing.T) {
	vaulttest.Run(t, func(t *testing.T) vault.Store { return newTestStore(t) })
}

// The audit log names each entry by its key's text form, for every event.
func TestStore_AuditNamesEntriesByKey(t *testing.T) {
	s := newTestStore(t)
	note := vault.Key{Kind: vault.KindNote, Service: "wifi"}
	totp := vault.AWSKey("prod")
	if err := s.Put(note, []byte("n")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(note); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(&vault.Entry{Key: totp}, []byte("GEZDGNBVGY3TQOJQ")); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(note); err != nil {
		t.Fatal(err)
	}
	events, err := s.AuditEvents(0)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, event := range slices.Backward(events) {
		got = append(got, event.EventType+" "+event.EntryID)
	}
	want := "modify secure_note/wifi, access secure_note/wifi, modify totp/aws/prod, delete secure_note/wifi"
	if strings.Join(got, ", ") != want {
		t.Errorf("audit events = %v, want %s", got, want)
	}
}

// Each secret is bound to its entry: one copied into another entry's row,
// by anyone who can write the file, doesn't decrypt there.
func TestStore_SecretsCantBeSwappedBetweenEntries(t *testing.T) {
	s := newTestStore(t)
	bank := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	blog := vault.Key{Kind: vault.KindPassword, Service: "blog"}
	if err := s.Put(bank, []byte("bank-password")); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(blog, []byte("blog-password")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE entries SET (encrypted_data, salt) = (SELECT encrypted_data, salt FROM entries WHERE service = 'bank') WHERE service = 'blog'`); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get(blog); err == nil {
		t.Errorf("Get(blog) = %q after copying bank's secret into its row, want an error", got)
	}
	if got, err := s.Get(bank); err != nil || string(got) != "bank-password" {
		t.Errorf("Get(bank) = %q, %v; want its own secret", got, err)
	}
}
