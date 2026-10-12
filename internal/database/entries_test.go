package database

import (
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/vault"
	"github.com/bashhack/sesh/internal/vault/vaulttest"
)

func TestStore_IsAVaultStore(t *testing.T) {
	vaulttest.Run(t, func(t *testing.T) vault.Store { return newTestStore(t) })
	t.Run("with a trash", func(t *testing.T) {
		vaulttest.Run(t, func(t *testing.T) vault.Store {
			s := newTestStore(t)
			s.SetTrashDays(30)
			return s
		})
	})
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
	from := vault.Key{Kind: vault.KindPassword, Service: "a", Username: "b"}
	for name, to := range map[string]vault.Key{
		"another service":  {Kind: vault.KindPassword, Service: "bank", Username: "b"},
		"another kind":     {Kind: vault.KindAPIKey, Service: "a", Username: "b"},
		"another username": {Kind: vault.KindPassword, Service: "a", Username: "c"},
		"no username":      {Kind: vault.KindPassword, Service: "a"},
		// Written straight into the file: its ID reads the same as from's.
		"a service with a slash": {Kind: vault.KindPassword, Service: "a/b"},
	} {
		t.Run(name, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.Put(from, []byte("from-secret")); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec(
				`INSERT INTO entries (kind, service, username, encrypted_data, salt, created_at, updated_at)
				 SELECT ?, ?, ?, encrypted_data, salt, created_at, updated_at FROM entries WHERE service = 'a' AND username = 'b'`,
				string(to.Kind), to.Service, to.Username,
			); err != nil {
				t.Fatal(err)
			}
			if got, err := s.Get(to); err == nil {
				t.Errorf("Get(%s) = %q from a copy of %s's secret, want an error", to, got, from)
			}
			if got, err := s.Get(from); err != nil || string(got) != "from-secret" {
				t.Errorf("Get(%s) = %q, %v; want its own secret", from, got, err)
			}
		})
	}
}

// The associated data is part of every stored secret, so its bytes must
// never change: a change would make every vault's entries unreadable.
func TestEntryAAD_Golden(t *testing.T) {
	for k, want := range map[vault.Key]string{
		{Kind: vault.KindPassword, Service: "github", Username: "alice"}: "736573682d656e7472792d76310000000870617373776f72640000000667697468756200000005616c696365",
		{Kind: vault.KindAPIKey, Service: "openai"}:                      "736573682d656e7472792d7631000000076170695f6b6579000000066f70656e616900000000",
	} {
		if got := hex.EncodeToString(entryAAD(k)); got != want {
			t.Errorf("entryAAD(%s) = %s, want %s", k, got, want)
		}
	}
}

// DeleteMany logs each deletion (vaulttest checks the rest).
func TestStore_DeleteManyLogsEach(t *testing.T) {
	s := newTestStore(t)
	a, b := vault.Key{Kind: vault.KindPassword, Service: "a"}, vault.Key{Kind: vault.KindAPIKey, Service: "b"}
	for _, k := range []vault.Key{a, b} {
		if err := s.Put(k, []byte("v")); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DeleteMany([]vault.Key{a, b}); err != nil {
		t.Fatal(err)
	}
	events, err := s.AuditEvents(0)
	if err != nil {
		t.Fatal(err)
	}
	deletes := 0
	for _, e := range events {
		if e.EventType == "delete" {
			deletes++
		}
	}
	if deletes != 2 {
		t.Errorf("logged %d deletions, want 2", deletes)
	}
}

// CodeKey reads a TOTP entry's key without an audit event, and no other
// kind of entry's secret.
func TestCodeKey(t *testing.T) {
	s := newTestStore(t)
	code := vault.Key{Kind: vault.KindTOTP, Service: "github"}
	pw := vault.Key{Kind: vault.KindPassword, Service: "github"}
	for _, k := range []vault.Key{code, pw} {
		if err := s.Put(k, []byte("JBSWY3DPEHPK3PXP")); err != nil {
			t.Fatal(err)
		}
	}
	var before, after int
	if err := s.db.QueryRow(`SELECT count(*) FROM audit_log WHERE event_type = 'access'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if got, err := s.CodeKey(code); err != nil || string(got) != "JBSWY3DPEHPK3PXP" {
		t.Errorf("CodeKey = %q, %v", got, err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM audit_log WHERE event_type = 'access'`).Scan(&after); err != nil || after != before {
		t.Errorf("access events %d → %d, %v", before, after, err)
	}
	if _, err := s.CodeKey(pw); err == nil || !strings.Contains(err.Error(), "isn't a TOTP entry") {
		t.Errorf("CodeKey of a password: %v", err)
	}
}

// DataVersion changes when another connection commits.
func TestDataVersion(t *testing.T) {
	s := newTestStore(t)
	v1, err := s.DataVersion()
	if err != nil {
		t.Fatal(err)
	}
	other, err := Open(s.path, s.oracle)
	if err != nil {
		t.Fatal(err)
	}
	defer other.db.Close() //nolint:errcheck // test cleanup
	if err := other.Put(vault.Key{Kind: vault.KindPassword, Service: "x"}, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	if v2, err := s.DataVersion(); err != nil || v2 == v1 {
		t.Errorf("DataVersion %d → %d, %v; want a change", v1, v2, err)
	}
}
