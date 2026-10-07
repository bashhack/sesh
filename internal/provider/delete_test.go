package provider

import (
	"errors"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/vault"
)

func deleteTestStore(t *testing.T, ids ...string) *vault.MemStore {
	t.Helper()
	s := vault.NewMemStore()
	for _, id := range ids {
		k, err := vault.ParseKey(id)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Put(k, []byte("secret")); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func remaining(t *testing.T, s *vault.MemStore) int {
	t.Helper()
	es, err := s.List(&vault.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	return len(es)
}

// Every bad ID is reported at once, and nothing is deleted.
func TestDeleteEntries_RefusesAndDeletesNothing(t *testing.T) {
	s := deleteTestStore(t, "password/a", "api_key/b")
	totpOnly := func(k vault.Key) error {
		if k.Kind != vault.KindTOTP {
			return errors.New(k.String() + " isn't a TOTP entry")
		}
		return nil
	}
	_, err := DeleteEntries(s, []string{"password/a", "password/missing", "bad", "api_key/b"}, nil, nil, true, nil)
	if err == nil || !strings.HasPrefix(err.Error(), "nothing was deleted:\n  ") || !strings.Contains(err.Error(), "password/missing") || !strings.Contains(err.Error(), `"bad"`) {
		t.Fatalf("err = %v", err)
	}
	if !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("err = %v, want it to wrap ErrNotFound", err)
	}
	if _, err := DeleteEntries(s, []string{"password/a"}, totpOnly, nil, true, nil); err == nil || err.Error() != "password/a isn't a TOTP entry" {
		t.Errorf("not the provider's: err = %v", err)
	}
	if n := remaining(t, s); n != 2 {
		t.Errorf("%d entries left, want 2", n)
	}
}

// A missing entry gets the hint.
func TestDeleteEntries_Hint(t *testing.T) {
	s := deleteTestStore(t, "password/GitHub")
	hint := func(vault.Key) string { return "did you mean password/GitHub?" }
	_, err := DeleteEntries(s, []string{"password/github"}, nil, hint, true, nil)
	if !errors.Is(err, vault.ErrNotFound) || !strings.HasSuffix(err.Error(), "; did you mean password/GitHub?") {
		t.Errorf("err = %v", err)
	}
}

// One question for the lot; no deletes nothing; force asks nothing; an ID
// named twice is deleted once.
func TestDeleteEntries_Confirmation(t *testing.T) {
	s := deleteTestStore(t, "password/a", "api_key/b")
	var asked [][]string
	no := func(ids []string) (bool, error) { asked = append(asked, ids); return false, nil }
	if _, err := DeleteEntries(s, []string{"password/a", "api_key/b"}, nil, nil, false, no); !errors.Is(err, ErrDeleteCancelled) {
		t.Fatalf("declined: err = %v", err)
	}
	if len(asked) != 1 || len(asked[0]) != 2 || remaining(t, s) != 2 {
		t.Errorf("asked %v, %d left; want one question about both, and nothing deleted", asked, remaining(t, s))
	}
	n, err := DeleteEntries(s, []string{"password/a", "password/a", "api_key/b"}, nil, nil, true, nil)
	if err != nil || n != 2 || remaining(t, s) != 0 {
		t.Errorf("forced: %d deleted, %v, %d left", n, err, remaining(t, s))
	}
	if _, err := DeleteEntries(s, nil, nil, nil, true, nil); err == nil || !strings.Contains(err.Error(), "at least one") {
		t.Errorf("no IDs: err = %v", err)
	}
}

// failsToDelete finds entries but can't delete them.
type failsToDelete struct{ *vault.MemStore }

func (failsToDelete) DeleteMany([]vault.Key) error { return errors.New("vault busy") }

// A delete that fails in the store reports it and counts nothing deleted.
func TestDeleteEntries_StoreFailure(t *testing.T) {
	s := failsToDelete{deleteTestStore(t, "password/a", "api_key/b")}
	n, err := DeleteEntries(s, []string{"password/a", "api_key/b"}, nil, nil, true, nil)
	if err == nil || err.Error() != "vault busy" || n != 0 {
		t.Errorf("DeleteEntries = %d, %v; want 0 and the store's error", n, err)
	}
}
