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
