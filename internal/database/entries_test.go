package database

import (
	"testing"

	"github.com/bashhack/sesh/internal/vault"
	"github.com/bashhack/sesh/internal/vault/vaulttest"
)

func TestStore_IsAVaultStore(t *testing.T) {
	vaulttest.Run(t, func(t *testing.T) vault.Store { return newTestStore(t) })
}

// Until each provider moves to vault.Store, both interfaces work on the
// same rows.
func TestStore_KeysNameTheStoredRows(t *testing.T) {
	s := newTestStore(t)
	if err := s.SetSecret("me", "sesh-password/password/github/alice", []byte("old-api")); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDescription("sesh-password/password/github/alice", "me", "password (alice) for github"); err != nil {
		t.Fatal(err)
	}
	k := vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}
	if got, err := s.Get(k); err != nil || string(got) != "old-api" {
		t.Errorf("Get = %q, %v; want the row the old interface wrote", got, err)
	}
	if e, err := s.Lookup(k); err != nil || !e.Settings.IsZero() {
		t.Errorf("Lookup = %+v, %v; a plain description isn't settings", e, err)
	}

	note := vault.Key{Kind: vault.KindNote, Service: "wifi"}
	if err := s.Put(note, []byte("new-api")); err != nil {
		t.Fatal(err)
	}
	// The password manager passes the OS user as the account, as Put does.
	acct, err := owner()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetSecret(acct, "sesh-password/secure_note/wifi"); err != nil || string(got) != "new-api" {
		t.Errorf("GetSecret = %q, %v; want the row Put wrote", got, err)
	}

	// The audit log names entries by their keys' text form.
	if _, err := s.Get(note); err != nil {
		t.Fatal(err)
	}
	var event, id string
	if err := s.db.QueryRow(`SELECT event_type, entry_id FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&event, &id); err != nil {
		t.Fatal(err)
	}
	if event != "access" || id != "secure_note/wifi" {
		t.Errorf("last audit event = %s %s, want access secure_note/wifi", event, id)
	}
}
