package database

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

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

// The fingerprint changes when an entry or its tags do, not when only the
// audit log is written.
func TestFingerprint(t *testing.T) {
	s := newTestStore(t)
	k := vault.Key{Kind: vault.KindPassword, Service: "x"}
	if err := s.Put(k, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	f1, err := s.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(k); err != nil { // an audit row only
		t.Fatal(err)
	}
	if f2, err := s.Fingerprint(); err != nil || f2 != f1 {
		t.Errorf("a read changed the fingerprint: %v", err)
	}
	if err := s.Save(&vault.Entry{Key: k, Tags: []string{"work"}}, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	if f3, err := s.Fingerprint(); err != nil || f3 == f1 {
		t.Errorf("a tag didn't change the fingerprint: %v", err)
	}
}

// EachSecret hands over every entry's secret, wiped after, and logs the run once.
func TestEachSecret(t *testing.T) {
	s := newTestStore(t)
	for _, k := range []vault.Key{{Kind: vault.KindPassword, Service: "a"}, {Kind: vault.KindAPIKey, Service: "b"}, {Kind: vault.KindNote, Service: "c"}} {
		if err := s.Put(k, []byte("secret of "+k.Service)); err != nil {
			t.Fatal(err)
		}
	}
	got := map[string]string{}
	var held [][]byte
	// One entry's secret damaged: handed over with its error, not stopping the rest.
	if _, err := s.db.Exec(`UPDATE entries SET encrypted_data = x'00112233445566778899aabbccddeeff00112233' WHERE service = 'b'`); err != nil {
		t.Fatal(err)
	}
	n, err := s.EachSecret("Health check", []vault.Kind{vault.KindPassword, vault.KindAPIKey}, func(e *vault.Entry, secret []byte, err error) error {
		if err != nil {
			got[e.Service] = "unreadable: " + err.Error()
			return nil
		}
		got[e.Service] = string(secret)
		held = append(held, secret)
		return nil
	})
	if err != nil || n != 1 || got["a"] != "secret of a" || !strings.HasPrefix(got["b"], "unreadable: ") || got["c"] != "" {
		t.Fatalf("EachSecret = %d, %v, %v", n, err, got)
	}
	for _, h := range held {
		if !bytes.Equal(h, make([]byte, len(h))) {
			t.Errorf("a secret wasn't wiped after its call: %q", h)
		}
	}
	events, err := s.AuditEvents(0)
	if err != nil {
		t.Fatal(err)
	}
	var reads []string
	for _, e := range events {
		if e.EventType == "access" {
			reads = append(reads, e.EntryID+"|"+e.Detail)
		}
	}
	if len(reads) != 1 || reads[0] != "|Health check: read 1 secret" {
		t.Errorf("audit reads = %q", reads)
	}
}

// Storing the secret an entry has keeps its update time, with history kept or not; a new one moves it.
func TestSameSecretKeepsUpdateTime(t *testing.T) {
	for _, keep := range []int{0, 10} {
		t.Run(fmt.Sprintf("history.keep %d", keep), func(t *testing.T) {
			s := newTestStore(t)
			s.SetHistoryKeep(keep)
			k := vault.Key{Kind: vault.KindPassword, Service: "bank"}
			if err := s.Put(k, []byte("one")); err != nil {
				t.Fatal(err)
			}
			then := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
			if _, err := s.db.Exec(`UPDATE entries SET updated_at = ? WHERE service = 'bank'`, then); err != nil {
				t.Fatal(err)
			}
			updated := func() time.Time {
				e, err := s.Lookup(k)
				if err != nil {
					t.Fatal(err)
				}
				return e.UpdatedAt.UTC()
			}
			if err := s.Put(k, []byte("one")); err != nil {
				t.Fatal(err)
			}
			if err := s.SaveWithDetails(&vault.Entry{Key: k}, []byte("one"), &vault.Details{}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Edit(k, &EntryEdit{Secret: []byte("one")}); !errors.Is(err, ErrNothingToChange) {
				t.Errorf("an edit to the same secret = %v; want nothing to change", err)
			}
			if got := updated(); !got.Equal(then) {
				t.Errorf("after the same secret again: updated %v; want %v", got, then)
			}
			to := vault.Key{Kind: vault.KindPassword, Service: "bank2"}
			if what, err := s.Edit(k, &EntryEdit{To: &to, Secret: []byte("one")}); err != nil || strings.Contains(what, "secret") {
				t.Errorf("a rename with the same secret = %q, %v", what, err)
			}
			if e, err := s.Lookup(to); err != nil || !e.UpdatedAt.UTC().Equal(then) {
				t.Errorf("renamed with the same secret: updated %v, %v", e.UpdatedAt, err)
			}
			if err := s.Put(to, []byte("two")); err != nil {
				t.Fatal(err)
			}
			if e, err := s.Lookup(to); err != nil || e.UpdatedAt.UTC().Equal(then) {
				t.Errorf("a new secret didn't move the update time: %v, %v", e.UpdatedAt, err)
			}
		})
	}
}

// openCountingOracle counts seals and openings, and runs onOpen (once) as the first opening starts.
type openCountingOracle struct {
	CryptoOracle
	onOpen         func()
	sealed, opened int
}

func (o *openCountingOracle) EncryptEntry(plain, aad []byte) ([]byte, []byte, error) {
	o.sealed++
	return o.CryptoOracle.EncryptEntry(plain, aad)
}

func (o *openCountingOracle) DecryptEntry(data, salt, aad []byte) ([]byte, error) {
	o.opened++
	if f := o.onOpen; f != nil {
		o.onOpen = nil
		f()
	}
	return o.CryptoOracle.DecryptEntry(data, salt, aad)
}

// The same secret again isn't sealed again; a time given is used; created_at stays too;
// a secret another command stores in between isn't dated by what it replaced.
func TestSameSecretDetails(t *testing.T) {
	s := newTestStore(t)
	k := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	if err := s.Put(k, []byte("one")); err != nil {
		t.Fatal(err)
	}
	then := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	if _, err := s.db.Exec(`UPDATE entries SET created_at = ?, updated_at = ? WHERE service = 'bank'`, then, then); err != nil {
		t.Fatal(err)
	}
	o := &openCountingOracle{CryptoOracle: s.oracle}
	s.oracle = o
	if err := s.Save(&vault.Entry{Key: k}, []byte("one")); err != nil {
		t.Fatal(err)
	}
	e, err := s.Lookup(k)
	if err != nil || o.sealed != 0 || o.opened != 1 || !e.CreatedAt.UTC().Equal(then) || !e.UpdatedAt.UTC().Equal(then) {
		t.Errorf("saved the same: sealed %d, opened %d, times %v %v, %v", o.sealed, o.opened, e.CreatedAt, e.UpdatedAt, err)
	}
	given := time.Date(2019, 5, 5, 0, 0, 0, 0, time.UTC)
	if err := s.Save(&vault.Entry{Key: k, UpdatedAt: given}, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if e, err := s.Lookup(k); err != nil || !e.UpdatedAt.UTC().Equal(given) {
		t.Errorf("a time given = %v, %v", e.UpdatedAt, err)
	}
	// Another command stores "two" while this one compares: the write is newer than 2019.
	o.onOpen = func() {
		data, salt, err := o.CryptoOracle.EncryptEntry([]byte("two"), entryAAD(k))
		if err == nil {
			_, err = s.db.Exec(`UPDATE entries SET encrypted_data = ?, salt = ? WHERE service = 'bank'`, data, salt)
		}
		if err != nil {
			t.Error(err)
		}
	}
	if err := s.Put(k, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if e, err := s.Lookup(k); err != nil || e.UpdatedAt.UTC().Equal(given) {
		t.Errorf("the same secret stored over another's: updated %v, %v", e.UpdatedAt, err)
	}
}

// An edit to the same secret with a rename opens the secret once; a damaged secret is still replaced.
func TestEditSameSecretOpensOnce(t *testing.T) {
	s := newTestStore(t)
	k := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	if err := s.Put(k, []byte("one")); err != nil {
		t.Fatal(err)
	}
	o := &openCountingOracle{CryptoOracle: s.oracle}
	s.oracle = o
	to := vault.Key{Kind: vault.KindPassword, Service: "bank2"}
	if _, err := s.Edit(k, &EntryEdit{To: &to, Secret: []byte("one")}); err != nil {
		t.Fatal(err)
	}
	if o.opened != 1 {
		t.Errorf("a rename with the same secret opened it %d times", o.opened)
	}
	if _, err := s.db.Exec(`UPDATE entries SET encrypted_data = x'00112233445566778899aabbccddeeff00112233' WHERE service = 'bank2'`); err != nil {
		t.Fatal(err)
	}
	if what, err := s.Edit(to, &EntryEdit{Secret: []byte("one")}); err != nil || !strings.Contains(what, "secret changed") {
		t.Errorf("replacing a damaged secret = %q, %v", what, err)
	}
	if got, err := s.Get(to); err != nil || string(got) != "one" {
		t.Errorf("after: %q, %v", got, err)
	}
}

// A write over damaged times mends them both, whether the secret changes or not.
func TestWriteMendsDamagedTimes(t *testing.T) {
	s := newTestStore(t)
	k := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	for _, write := range []func() error{
		func() error { return s.Put(k, []byte("one")) },
		func() error { return s.Save(&vault.Entry{Key: k}, []byte("one")) },
		func() error { return s.Put(k, []byte("two")) },
	} {
		if err := s.Put(k, []byte("one")); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`UPDATE entries SET created_at = 'not a time', updated_at = 'nor this' WHERE service = 'bank'`); err != nil {
			t.Fatal(err)
		}
		if err := write(); err != nil {
			t.Fatal(err)
		}
		if e, err := s.Lookup(k); err != nil || e.CreatedAt.IsZero() || e.UpdatedAt.IsZero() {
			t.Errorf("after the write: %+v, %v", e, err)
		}
	}
}

// GetChecked lets check see the entry before anything's decrypted: refused,
// nothing is read or recorded; let go on, the secret is the row's, and the
// read is recorded as reading says.
func TestGetChecked(t *testing.T) {
	_, s := rekeyVault(t)
	k := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	if err := s.SetDetails(k, &vault.Details{URL: "https://bank.example"}); err != nil {
		t.Fatal(err)
	}
	reads := func() int {
		t.Helper()
		var n int
		if err := s.db.QueryRow(`SELECT count(*) FROM audit_log WHERE event_type = 'access' AND entry_id = ?`, k.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := reads()
	refuse := errors.New("not this site")
	if _, secret, err := s.GetChecked(k, "secret, to fill it in", func(e *vault.Entry) error {
		if e.URL != "https://bank.example" {
			t.Errorf("check saw URL %q", e.URL)
		}
		return refuse
	}); !errors.Is(err, refuse) || secret != nil || reads() != before {
		t.Errorf("refused: %q, %v; reads %d, was %d", secret, err, reads(), before)
	}
	e, secret, err := s.GetChecked(k, "secret, to fill it in", func(*vault.Entry) error { return nil })
	if err != nil || string(secret) != "bank-secret" || e.URL != "https://bank.example" || reads() != before+1 {
		t.Errorf("let go on: %+v %q, %v; reads %d", e, secret, err, reads())
	}
	var detail string
	if err := s.db.QueryRow(`SELECT detail FROM audit_log WHERE event_type = 'access' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil || detail != "Read: secret, to fill it in" {
		t.Errorf("recorded %q, %v", detail, err)
	}
	if _, _, err := s.GetChecked(vault.Key{Kind: vault.KindPassword, Service: "gone"}, "x", func(*vault.Entry) error { return nil }); !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
}
