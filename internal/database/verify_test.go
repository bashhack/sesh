package database

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/vault"
)

func TestVerify_EmptyAndSound(t *testing.T) {
	p, s := rekeyVault(t)
	r, err := s.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Structure) != 0 || len(r.Problems) != 0 || r.Entries != 1 || r.KeyID != vaultID(t, p) || r.Recovery == nil {
		t.Errorf("report = %+v", r)
	}
	// A new vault with no entries is sound too.
	ep := vaultPath(t.TempDir())
	empty, err := Open(ep, NewKeySourceOracle(NewMasterPasswordSource(ep, staticPrompt("empty-password-1", "empty-password-1"))))
	if err != nil {
		t.Fatal(err)
	}
	defer empty.Close() //nolint:errcheck // test cleanup
	if err := empty.CheckKey(); err != nil {
		t.Fatal(err)
	}
	if r, err := empty.Verify(); err != nil || r.Entries != 0 || len(r.Structure) != 0 || r.Recovery != nil {
		t.Errorf("empty vault: %+v, %v", r, err)
	}
}

// Every unreadable entry is reported, ordered by key: a secret that
// doesn't decrypt, settings that don't parse, times that don't read.
func TestVerify_ReportsEachUnreadableEntry(t *testing.T) {
	_, s := rekeyVault(t)
	for _, svc := range []string{"zeta", "alpha", "mid"} {
		if err := s.Put(vault.Key{Kind: vault.KindPassword, Service: svc}, []byte("v")); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []string{
		`UPDATE entries SET encrypted_data = x'00112233445566778899aabbccddeeff00112233445566778899' WHERE service = 'zeta'`,
		`UPDATE entries SET settings = '{' WHERE service = 'alpha'`,
		`UPDATE entries SET updated_at = 'garbage' WHERE service = 'mid'`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	r, err := s.Verify()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range r.Problems {
		got = append(got, p.Key.Service+": "+p.Err.Error())
	}
	want := []string{"alpha: read the settings", "mid: its times don't read", "zeta: its secret doesn't decrypt with the vault's key"}
	if len(got) != 3 || r.Entries != 4 {
		t.Fatalf("problems = %q of %d entries, want 3 of 4", got, r.Entries)
	}
	for i := range want {
		if !strings.HasPrefix(got[i], want[i]) {
			t.Errorf("problem %d = %q, want it to start %q", i, got[i], want[i])
		}
	}
}

// A master password changed by another command after this one opened the
// vault isn't damage: the check says to run again.
func TestVerify_KeyChangedElsewhere(t *testing.T) {
	p, s := rekeyVault(t)
	other, err := Open(p, NewKeySourceOracle(NewMasterPasswordSource(p, staticPrompt("old-password-1"))))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close() //nolint:errcheck // test cleanup
	key, rec := newKeyFor(t, "new-password-1")
	if _, err := other.Rekey(key, rec, rewrapTo); err != nil {
		t.Fatal(err)
	}
	if r, err := s.Verify(); !errors.Is(err, ErrVaultKeyChanged) || len(r.Problems) != 0 {
		t.Errorf("Verify = %+v, %v; want ErrVaultKeyChanged and no problems", r, err)
	}
}

// failingOracle decrypts the first entry, then fails as a locked agent
// would.
type failingOracle struct {
	CryptoOracle
	calls int
}

func (o *failingOracle) UnlockID() (string, error) {
	return o.CryptoOracle.(interface{ UnlockID() (string, error) }).UnlockID()
}

func (o *failingOracle) DecryptEntry(data, salt, aad []byte) ([]byte, error) {
	o.calls++
	if o.calls > 1 {
		return nil, errors.New("not_unlocked: agent is locked")
	}
	return o.CryptoOracle.DecryptEntry(data, salt, aad)
}

// A key source that stops working part way isn't damage either.
func TestVerify_KeySourceFails(t *testing.T) {
	p, s := rekeyVault(t)
	if err := s.Put(vault.Key{Kind: vault.KindPassword, Service: "second"}, []byte("v")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	o := &failingOracle{CryptoOracle: NewKeySourceOracle(NewMasterPasswordSource(p, staticPrompt("old-password-1")))}
	s2, err := Open(p, o)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close() //nolint:errcheck // test cleanup
	r, err := s2.Verify()
	if err == nil || !strings.Contains(err.Error(), "couldn't finish checking") || len(r.Problems) != 0 {
		t.Errorf("Verify = %+v, %v; want it unfinished, with no entry blamed", r, err)
	}
}

// A secret that doesn't decrypt is ErrDecrypt, directly and as the agent
// reports it.
func TestErrDecrypt(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	ct, err := Encrypt(key, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 1
	if _, err := Decrypt(key, ct); !errors.Is(err, ErrDecrypt) || !strings.HasPrefix(err.Error(), "decrypt: ") {
		t.Errorf("damaged ciphertext: err = %v", err)
	}
	if _, err := Decrypt(key, []byte{1}); !errors.Is(err, ErrDecrypt) {
		t.Errorf("short ciphertext: err = %v", err)
	}
	if _, err := Decrypt([]byte{1}, ct); errors.Is(err, ErrDecrypt) {
		t.Errorf("a bad key length isn't a damaged ciphertext: %v", err)
	}
}
