package database

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/vault"
)

// sqlExecDB runs q on s's database directly, as damage would.
func sqlExecDB(t *testing.T, s *Store, q string) {
	t.Helper()
	if _, err := s.db.Exec(q); err != nil {
		t.Fatal(err)
	}
}

func testDetails() vault.Details {
	return vault.Details{
		URL:   "https://bank.example/login",
		Notes: []byte("branch: main street"),
		Fields: []vault.Field{
			{Name: "account", Value: []byte("12345678")},
			{Name: "pin", Value: []byte("4321"), Secret: true},
		},
	}
}

func checkDetailsOf(t *testing.T, s *Store, k vault.Key, want *vault.Details) {
	t.Helper()
	got, err := s.Details(k)
	if err != nil {
		t.Fatalf("Details(%s): %v", k, err)
	}
	defer got.Zero()
	pin, _ := got.Field("pin")
	wantPin, _ := want.Field("pin")
	if got.URL != want.URL || string(got.Notes) != string(want.Notes) || len(got.Fields) != len(want.Fields) || string(pin.Value) != string(wantPin.Value) {
		t.Errorf("Details(%s) = %+v (notes %q), want %+v", k, got, got.Notes, want)
	}
}

// The sealed details open only on their own entry, and aren't the secret:
// moved to another row, or swapped with the secret, they don't decrypt.
func TestDetails_BoundToTheirEntry(t *testing.T) {
	_, s := rekeyVault(t)
	bank := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	d := testDetails()
	if err := s.SetDetails(bank, &d); err != nil {
		t.Fatal(err)
	}
	other := vault.Key{Kind: vault.KindPassword, Service: "other"}
	if err := s.Put(other, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	sqlExecDB(t, s, `UPDATE entries SET details = (SELECT details FROM entries WHERE service = 'bank'),
		sealed_details = (SELECT sealed_details FROM entries WHERE service = 'bank'),
		details_salt = (SELECT details_salt FROM entries WHERE service = 'bank') WHERE service = 'other'`)
	if _, err := s.Details(other); err == nil || !strings.Contains(err.Error(), "decrypt the details of password/other") {
		t.Errorf("Details of another entry's sealed details = %v, want a decrypt error", err)
	}
	sqlExecDB(t, s, `UPDATE entries SET encrypted_data = sealed_details, salt = details_salt WHERE service = 'bank'`)
	if _, err := s.Get(bank); err == nil {
		t.Error("the sealed details opened as the secret")
	}
}

// A rename re-seals the details under the new name with the secret.
func TestEdit_RenameKeepsDetails(t *testing.T) {
	_, s := rekeyVault(t)
	bank := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	d := testDetails()
	if err := s.SetDetails(bank, &d); err != nil {
		t.Fatal(err)
	}
	to := vault.Key{Kind: vault.KindAPIKey, Service: "bank-api"}
	if _, err := s.Edit(bank, EntryEdit{To: &to}); err != nil {
		t.Fatal(err)
	}
	checkDetailsOf(t, s, to, &d)
	// A new secret alone leaves them as they are.
	if _, err := s.Edit(to, EntryEdit{Secret: []byte("sk-2")}); err != nil {
		t.Fatal(err)
	}
	checkDetailsOf(t, s, to, &d)
}

// An entry with notes can't become a secure note, whose secret is the note.
func TestEdit_NotesBlockASecureNote(t *testing.T) {
	_, s := rekeyVault(t)
	bank := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	d := testDetails()
	if err := s.SetDetails(bank, &d); err != nil {
		t.Fatal(err)
	}
	to := vault.Key{Kind: vault.KindNote, Service: "bank"}
	if _, err := s.Edit(bank, EntryEdit{To: &to}); err == nil || !strings.Contains(err.Error(), "has notes, and a secure note can't") {
		t.Errorf("Edit to a secure note = %v, want refused", err)
	}
	d.Notes = nil
	if err := s.SetDetails(bank, &d); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Edit(bank, EntryEdit{To: &to}); err != nil {
		t.Errorf("Edit without notes: %v", err)
	}
}

// Details changed while an edit was being sealed aren't overwritten.
func TestEdit_DetailsChangedMeanwhile(t *testing.T) {
	p, s := rekeyVault(t)
	bank := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	d := testDetails()
	if err := s.SetDetails(bank, &d); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	other, err := Open(p, NewKeySourceOracle(NewMasterPasswordSource(p, staticPrompt("old-password-1", "old-password-1"))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() }) //nolint:errcheck // test cleanup
	meddled := false
	changed := vault.Details{URL: "https://changed.example", Notes: []byte("changed meanwhile")}
	o := &meddlingOracle{CryptoOracle: NewKeySourceOracle(NewMasterPasswordSource(p, staticPrompt("old-password-1", "old-password-1"))), meddle: func() {
		if meddled {
			return
		}
		meddled = true
		if err := other.SetDetails(bank, &changed); err != nil {
			t.Error(err)
		}
	}}
	s2, err := Open(p, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s2.Close() }) //nolint:errcheck // test cleanup
	to := vault.Key{Kind: vault.KindPassword, Service: "bank-2"}
	if _, err := s2.Edit(bank, EntryEdit{To: &to}); !errors.Is(err, ErrEntryChanged) {
		t.Errorf("Edit = %v, want ErrEntryChanged", err)
	}
	checkDetailsOf(t, other, bank, &changed)
}

// A new master password re-seals the details with the secrets; details
// set while it works are re-sealed in its transaction.
func TestRekey_ReSealsDetails(t *testing.T) {
	for _, during := range []bool{false, true} {
		p, s := rekeyVault(t)
		bank := vault.Key{Kind: vault.KindPassword, Service: "bank"}
		d := testDetails()
		if err := s.SetDetails(bank, &d); err != nil {
			t.Fatal(err)
		}
		var oldSealed []byte
		if err := s.db.QueryRow(`SELECT sealed_details FROM entries`).Scan(&oldSealed); err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		other, err := Open(p, NewKeySourceOracle(NewMasterPasswordSource(p, staticPrompt("old-password-1"))))
		if err != nil {
			t.Fatal(err)
		}
		want := d
		if during {
			want = vault.Details{URL: "https://set.meanwhile", Notes: []byte("set while it worked")}
		}
		o := &saveDuringOracle{CryptoOracle: NewKeySourceOracle(NewMasterPasswordSource(p, staticPrompt("old-password-1"))), save: func() {
			if during {
				if err := other.SetDetails(bank, &want); err != nil {
					t.Errorf("set details while the change works: %v", err)
				}
			}
		}}
		s, err = Open(p, o)
		if err != nil {
			t.Fatal(err)
		}
		key, rec := newKeyFor(t, "new-password-1")
		if _, err := s.Rekey(key, rec, rewrapTo); err != nil {
			t.Fatal(err)
		}
		if err := errors.Join(s.Close(), other.Close()); err != nil {
			t.Fatal(err)
		}
		after, err := Open(p, NewKeySourceOracle(NewMasterPasswordSource(p, staticPrompt("new-password-1"))))
		if err != nil {
			t.Fatal(err)
		}
		checkDetailsOf(t, after, bank, &want)
		if err := after.Close(); err != nil {
			t.Fatal(err)
		}
		if b, err := os.ReadFile(p); err != nil || bytes.Contains(b, oldSealed) {
			t.Errorf("during=%v: the old sealed details are still in the vault file (%v)", during, err)
		}
	}
}

// The check opens every entry's details too: sealed details that don't
// decrypt, a readable part that doesn't parse, the two disagreeing, and
// details breaking the rules are each a details problem.
func TestVerify_ReportsUnreadableDetails(t *testing.T) {
	_, s := rekeyVault(t)
	d := testDetails()
	for _, svc := range []string{"bank", "sealed", "plain", "disagree"} {
		k := vault.Key{Kind: vault.KindPassword, Service: svc}
		if err := s.Put(k, []byte("v")); err != nil {
			t.Fatal(err)
		}
		if err := s.SetDetails(k, &d); err != nil {
			t.Fatal(err)
		}
	}
	sqlExecDB(t, s, `UPDATE entries SET sealed_details = x'00112233445566778899aabbccddeeff00112233445566778899' WHERE service = 'sealed'`)
	sqlExecDB(t, s, `UPDATE entries SET details = '{' WHERE service = 'plain'`)
	sqlExecDB(t, s, `UPDATE entries SET details = '{"fields":[{"name":"account","value":"1"}]}' WHERE service = 'disagree'`)
	// Read back fine, but with a name no field can have.
	sqlExecDB(t, s, `UPDATE entries SET details = '{"notes":true,"fields":[{"name":"url","value":"x"},{"name":"pin","secret":true}]}' WHERE service = 'bank'`)
	r, err := s.Verify()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range r.Problems {
		if p.Kind != ProblemDetails {
			t.Errorf("%s: kind %d, want ProblemDetails", p.Key, p.Kind)
		}
		got = append(got, p.Key.Service+": "+p.Err.Error())
	}
	want := []string{
		`bank: the field name "url" is reserved`,
		"disagree: read the details of password/disagree: the notes don't match their record",
		"plain: read the details of password/plain",
		"sealed: its notes and secret fields don't decrypt with the vault's key",
	}
	if len(got) != len(want) || r.Entries != 4 {
		t.Fatalf("problems = %q of %d entries, want %d of 4", got, r.Entries, len(want))
	}
	for i := range want {
		if !strings.HasPrefix(got[i], want[i]) {
			t.Errorf("problem %d = %q, want it to start %q", i, got[i], want[i])
		}
	}
}

// A restore brings back the backup's details with its entries.
func TestRestore_BringsBackDetails(t *testing.T) {
	p, s := rekeyVault(t)
	bank := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	d := testDetails()
	if err := s.SetDetails(bank, &d); err != nil {
		t.Fatal(err)
	}
	b := backupOf(t, p)
	if err := s.SetDetails(bank, &vault.Details{URL: "https://later.example"}); err != nil {
		t.Fatal(err)
	}
	if err := RestoreInPlace(p, b); err != nil {
		t.Fatal(err)
	}
	checkDetailsOf(t, s, bank, &d)
}

// Reading sealed details is an access event; reading readable-only details
// isn't; setting them is a modify event.
func TestDetails_Audit(t *testing.T) {
	_, s := rekeyVault(t)
	bank := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	count := func(event string) int {
		var n int
		if err := s.db.QueryRow(`SELECT count(*) FROM audit_log WHERE event_type = ? AND detail LIKE '%Details'`, event).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if err := s.SetDetails(bank, &vault.Details{URL: "https://bank.example"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Details(bank); err != nil {
		t.Fatal(err)
	}
	if count("modify") != 1 || count("access") != 0 {
		t.Errorf("after a readable-only read: modify %d, access %d; want 1, 0", count("modify"), count("access"))
	}
	d := testDetails()
	if err := s.SetDetails(bank, &d); err != nil {
		t.Fatal(err)
	}
	checkDetailsOf(t, s, bank, &d)
	if count("modify") != 2 || count("access") != 1 {
		t.Errorf("after a sealed read: modify %d, access %d; want 2, 1", count("modify"), count("access"))
	}
}

// An edit changes details in its one transaction, with or without a
// rename, and says what changed.
func TestEdit_ChangesDetails(t *testing.T) {
	_, s := rekeyVault(t)
	bank := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	d := testDetails()
	if err := s.SetDetails(bank, &d); err != nil {
		t.Fatal(err)
	}
	url := "https://new.bank.example"
	detail, err := s.Edit(bank, EntryEdit{Details: &vault.DetailsChange{URL: &url, Set: []vault.Field{{Name: "pin", Value: []byte("9999"), Secret: true}}, Remove: []string{"account"}}})
	if err != nil || detail != "URL changed, field pin changed, field account removed" {
		t.Fatalf("Edit = %q, %v", detail, err)
	}
	want := vault.Details{URL: url, Notes: d.Notes, Fields: []vault.Field{{Name: "pin", Value: []byte("9999"), Secret: true}}}
	checkDetailsOf(t, s, bank, &want)

	// With a rename to a secure note, the notes must go in the same edit.
	to := vault.Key{Kind: vault.KindNote, Service: "bank"}
	if _, err := s.Edit(bank, EntryEdit{To: &to, Details: &vault.DetailsChange{URL: &url}}); err == nil || !strings.Contains(err.Error(), "a secure note can't have notes") {
		t.Errorf("rename to a note keeping notes = %v, want refused", err)
	}
	detail, err = s.Edit(bank, EntryEdit{To: &to, Details: &vault.DetailsChange{SetNotes: true}})
	if err != nil || detail != "renamed from password/bank and notes removed" {
		t.Fatalf("rename removing notes = %q, %v", detail, err)
	}
	want.Notes = nil
	checkDetailsOf(t, s, to, &want)

	// A change that changes nothing is nothing to do.
	if _, err := s.Edit(to, EntryEdit{Details: &vault.DetailsChange{URL: &url}}); err == nil || err.Error() != "nothing to change" {
		t.Errorf("a change to the same URL = %v, want nothing to change", err)
	}
	if _, err := s.Edit(to, EntryEdit{Details: &vault.DetailsChange{Remove: []string{"nope"}}}); err == nil || !strings.Contains(err.Error(), `there's no field "nope" to remove`) {
		t.Errorf("removing a missing field = %v", err)
	}
}
