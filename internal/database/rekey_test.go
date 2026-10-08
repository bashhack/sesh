package database

import (
	"bytes"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/vault"
)

// rekeyVault is a vault with one entry and a recovery key record, opened
// with the password "old-password-1".
func rekeyVault(t *testing.T) (string, *Store) {
	t.Helper()
	p := vaultPath(t.TempDir())
	s, err := Open(p, NewKeySourceOracle(NewMasterPasswordSource(p, staticPrompt("old-password-1", "old-password-1"))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() }) //nolint:errcheck // test cleanup
	if err := s.Put(vault.Key{Kind: vault.KindPassword, Service: "bank"}, []byte("bank-secret")); err != nil {
		t.Fatal(err)
	}
	if err := WriteRecovery(p, &RecoveryRecord{UnlockID: vaultID(t, p), PublicKey: []byte("pub"), EphemeralPub: []byte("eph"), Ciphertext: []byte("old-wrap"), CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return p, s
}

func newKeyFor(t *testing.T, pw string) ([]byte, UnlockMaterial) {
	t.Helper()
	key, rec, err := newKeyRecord([]byte(pw), newSourceParams())
	if err != nil {
		t.Fatal(err)
	}
	return key, rec
}

// opensWith reports whether pw opens the vault at p and its entry reads.
func opensWith(t *testing.T, p, pw string) bool {
	t.Helper()
	s, err := Open(p, NewKeySourceOracle(NewMasterPasswordSource(p, staticPrompt(pw))))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck // test cleanup
	got, err := s.Get(vault.Key{Kind: vault.KindPassword, Service: "bank"})
	return err == nil && string(got) == "bank-secret"
}

func rewrapTo(r *RecoveryRecord, newID string) (*RecoveryRecord, error) {
	nr := *r
	nr.UnlockID, nr.Ciphertext = newID, []byte("new-wrap")
	return &nr, nil
}

func TestStore_Rekey(t *testing.T) {
	p, s := rekeyVault(t)
	var sealed []byte
	if err := s.db.QueryRow(`SELECT encrypted_data FROM entries`).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	key, rec := newKeyFor(t, "new-password-1")
	res, err := s.Rekey(key, rec, rewrapTo)
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries != 1 || res.Recovery != RecoveryKept {
		t.Errorf("result = %+v", res)
	}
	events, err := s.AuditEvents(0)
	if err != nil || len(events) < 2 || events[0].EventType != "rekey" {
		t.Errorf("audit log = %+v, %v; want the earlier events and a rekey event", events, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if opensWith(t, p, "old-password-1") || !opensWith(t, p, "new-password-1") {
		t.Error("want the new password, and only it, to open the vault")
	}
	r, err := ReadRecovery(p)
	if err != nil || r.UnlockID != vaultID(t, p) || string(r.Ciphertext) != "new-wrap" {
		t.Errorf("recovery record = %+v, %v; want it re-wrapped to the new key record", r, err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, sealed) {
		t.Error("the entry's old ciphertext is still in the vault file")
	}
}

// A recovery's change removes the used recovery key record, and one made
// for another key record is removed too.
func TestStore_RekeyRemovesTheRecoveryRecord(t *testing.T) {
	for name, tc := range map[string]struct {
		stale bool
		want  RecoveryOutcome
	}{
		"recovery": {want: RecoveryRemoved},
		"stale":    {stale: true, want: RecoveryStale},
	} {
		t.Run(name, func(t *testing.T) {
			p, s := rekeyVault(t)
			rewrap := rewrapTo
			if tc.stale {
				if _, err := s.db.Exec(`UPDATE recovery SET unlock_id = 'another-key-record'`); err != nil {
					t.Fatal(err)
				}
			} else {
				rewrap = nil
			}
			key, rec := newKeyFor(t, "new-password-1")
			res, err := s.Rekey(key, rec, rewrap)
			if err != nil || res.Recovery != tc.want {
				t.Fatalf("Rekey = %+v, %v; want %v", res, err, tc.want)
			}
			if _, err := ReadRecovery(p); !errors.Is(err, ErrNoRecovery) {
				t.Errorf("recovery record after: err = %v", err)
			}
		})
	}
}

// A change that fails part way changes nothing.
func TestStore_RekeyIsAllOrNothing(t *testing.T) {
	p, s := rekeyVault(t)
	key, rec := newKeyFor(t, "new-password-1")
	_, err := s.Rekey(key, rec, func(*RecoveryRecord, string) (*RecoveryRecord, error) { return nil, errors.New("wrap failed") })
	if err == nil {
		t.Fatal("want the failure")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if !opensWith(t, p, "old-password-1") {
		t.Error("the old password no longer opens the vault")
	}
	if r, err := ReadRecovery(p); err != nil || string(r.Ciphertext) != "old-wrap" {
		t.Errorf("recovery record = %+v, %v; want it unchanged", r, err)
	}
}

// A command that unlocked the vault before another changed its password
// can't write under the old key, or change the password again; its reads
// say why they fail.
func TestStore_AfterAnotherRekey(t *testing.T) {
	p, s := rekeyVault(t)
	other, err := Open(p, NewKeySourceOracle(NewMasterPasswordSource(p, staticPrompt("old-password-1"))))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close() //nolint:errcheck // test cleanup
	if err := other.CheckKey(); err != nil {
		t.Fatal(err)
	}
	key, rec := newKeyFor(t, "new-password-1")
	if _, err := s.Rekey(key, rec, rewrapTo); err != nil {
		t.Fatal(err)
	}
	k := vault.Key{Kind: vault.KindPassword, Service: "bank"}
	for name, f := range map[string]func() error{
		"put":                func() error { return other.Put(k, []byte("v")) },
		"delete":             func() error { return other.Delete(k) },
		"delete many":        func() error { return other.DeleteMany([]vault.Key{k}) },
		"set":                func() error { return other.SetSettings(k, vault.Settings{AWSMFADevice: "arn"}) },
		"get":                func() error { _, err := other.Get(k); return err },
		"edit, a new secret": func() error { _, err := other.Edit(k, EntryEdit{Secret: []byte("v")}); return err },
		"edit, a rename": func() error {
			to := vault.Key{Kind: vault.KindPassword, Service: "bank-2"}
			_, err := other.Edit(k, EntryEdit{To: &to})
			return err
		},
		"rekey": func() error {
			key, rec := newKeyFor(t, "third-password-1")
			_, err := other.Rekey(key, rec, rewrapTo)
			return err
		},
	} {
		if err := f(); !errors.Is(err, ErrVaultKeyChanged) {
			t.Errorf("%s: err = %v, want ErrVaultKeyChanged", name, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if !opensWith(t, p, "new-password-1") {
		t.Error("the vault no longer opens with the new password")
	}
}

// saveDuringOracle runs save once, the first time an entry is decrypted:
// during a password change, that's while entries are re-encrypted ahead of
// its transaction.
type saveDuringOracle struct {
	CryptoOracle
	save func()
	done bool
}

func (o *saveDuringOracle) UnlockID() (string, error) {
	return o.CryptoOracle.(interface{ UnlockID() (string, error) }).UnlockID()
}

func (o *saveDuringOracle) DecryptEntry(data, salt, aad []byte) ([]byte, error) {
	if !o.done {
		o.done = true
		o.save()
	}
	return o.CryptoOracle.DecryptEntry(data, salt, aad)
}

// An entry saved or changed by another command while the change re-encrypts
// entries ahead of its transaction ends up under the new key too.
func TestStore_RekeyKeepsSavesMadeWhileItWorks(t *testing.T) {
	p, _ := rekeyVault(t)
	other, err := Open(p, NewKeySourceOracle(NewMasterPasswordSource(p, staticPrompt("old-password-1"))))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close() //nolint:errcheck // test cleanup
	src := NewMasterPasswordSource(p, staticPrompt("old-password-1"))
	o := &saveDuringOracle{CryptoOracle: NewKeySourceOracle(src), save: func() {
		for k, v := range map[string]string{"bank": "changed-secret", "late": "late-secret"} {
			if err := other.Put(vault.Key{Kind: vault.KindPassword, Service: k}, []byte(v)); err != nil {
				t.Errorf("save while the change works: %v", err)
			}
		}
	}}
	s, err := Open(p, o)
	if err != nil {
		t.Fatal(err)
	}
	key, rec := newKeyFor(t, "new-password-1")
	if _, err := s.Rekey(key, rec, rewrapTo); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := Open(p, NewKeySourceOracle(NewMasterPasswordSource(p, staticPrompt("new-password-1"))))
	if err != nil {
		t.Fatal(err)
	}
	defer after.Close() //nolint:errcheck // test cleanup
	for k, want := range map[string]string{"bank": "changed-secret", "late": "late-secret"} {
		if got, err := after.Get(vault.Key{Kind: vault.KindPassword, Service: k}); err != nil || string(got) != want {
			t.Errorf("%s under the new password = %q, %v; want %q", k, got, err, want)
		}
	}
}

// A reader in the middle of a read holds off folding the change into the
// vault file, and the result says so; with none, the change is folded in.
func TestStore_RekeyReportsWhenTheFileStillHoldsTheOldVault(t *testing.T) {
	for _, reading := range []bool{false, true} {
		p, s := rekeyVault(t)
		reader, err := sql.Open("sqlite", p)
		if err != nil {
			t.Fatal(err)
		}
		reader.SetMaxOpenConns(1)
		var tx *sql.Tx
		if reading {
			if tx, err = reader.Begin(); err != nil {
				t.Fatal(err)
			}
			var n int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM entries`).Scan(&n); err != nil {
				t.Fatal(err)
			}
		}
		key, rec := newKeyFor(t, "new-password-1")
		res, err := s.Rekey(key, rec, rewrapTo)
		if err != nil {
			t.Fatal(err)
		}
		if res.OldVaultInFile != reading {
			t.Errorf("reading=%v: OldVaultInFile = %v", reading, res.OldVaultInFile)
		}
		if tx != nil {
			_ = tx.Rollback() //nolint:errcheck // test cleanup
		}
		_ = reader.Close() //nolint:errcheck // test cleanup
	}
}
