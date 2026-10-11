package importer

import (
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/vault"
)

// Place numbers entries of one name in order, gives an item's entries one
// number together, and takes the first name free; many of one name don't
// take long.
func TestPlace(t *testing.T) {
	names := NewNames()
	place := func(keys ...vault.Key) []string {
		var es []*Entry
		for _, k := range keys {
			es = append(es, &Entry{Key: k})
		}
		Place(es, names)
		var got []string
		for _, e := range es {
			got = append(got, e.Key.String())
		}
		return got
	}
	pw := func(s string) vault.Key { return vault.Key{Kind: vault.KindPassword, Service: s} }
	totp := func(s string) vault.Key { return vault.Key{Kind: vault.KindTOTP, Service: s} }
	for i, want := range []string{"password/a", "password/a (2)", "password/a (3)"} {
		if got := place(pw("a")); got[0] != want {
			t.Errorf("a #%d = %s, want %s", i+1, got[0], want)
		}
	}
	place(totp("b"))
	if got := place(pw("b"), totp("b")); got[0] != "password/b (2)" || got[1] != "totp/b (2)" {
		t.Errorf("b's item = %v, want both (2)", got)
	}
	if got := place(pw("b")); got[0] != "password/b" {
		t.Errorf("a later b = %v, want the free password/b", got)
	}
	if got := place(totp("b")); got[0] != "totp/b (3)" {
		t.Errorf("a later totp b = %v, want (3)", got)
	}
	start := time.Now()
	for range 20000 {
		place(pw("same"))
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("20000 of one name took %v", d)
	}
}
