package health

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/vault"
)

// breaches is a made-up breach list.
type breaches map[string]int

func (b breaches) Count(pw []byte) (int, error) {
	if string(pw) == "unreadable" {
		return 0, errors.New("the download is missing a range")
	}
	return b[string(pw)], nil
}

func key(kind vault.Kind, service string) vault.Key { return vault.Key{Kind: kind, Service: service} }

// Each check finds what it should, and only for the kinds it covers.
func TestChecks(t *testing.T) {
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	c := &Checker{Now: now, OldAfter: 365 * 24 * time.Hour, IsWeak: password.IsWeak, Breaches: breaches{"password1": 2_000_000, "hunter2": 0}}
	recent, old := now.Add(-24*time.Hour), now.AddDate(-2, 0, 0)
	for _, x := range []struct {
		secret string
		e      vault.Entry
	}{
		{"password1", vault.Entry{Key: key(vault.KindPassword, "bank"), UpdatedAt: recent}},
		{"password1", vault.Entry{Key: key(vault.KindPassword, "shop"), UpdatedAt: recent}},
		{"wQ7#vPz!2kLm9$Xr", vault.Entry{Key: key(vault.KindPassword, "mail"), UpdatedAt: old}},
		{"password1", vault.Entry{Key: key(vault.KindAPIKey, "ci"), UpdatedAt: old}},
		{"JBSWY3DPEHPK3PXP", vault.Entry{Key: key(vault.KindTOTP, "code"), UpdatedAt: old}},
		{"password1", vault.Entry{Key: key(vault.KindNote, "wifi"), UpdatedAt: old}},
		{"github", vault.Entry{Key: key(vault.KindPassword, "github"), UpdatedAt: recent}},
	} {
		if err := c.Add(&x.e, []byte(x.secret)); err != nil {
			t.Fatal(err)
		}
	}
	r := c.Report()
	names := func(keys []vault.Key) (out []string) {
		for _, k := range keys {
			out = append(out, k.Service)
		}
		return out
	}
	if got := names(r.Weak); !slices.Equal(got, []string{"bank", "github", "shop"}) {
		t.Errorf("weak = %q", got)
	}
	if len(r.Reused) != 1 || !slices.Equal(names(r.Reused[0]), []string{"ci", "bank", "shop"}) {
		t.Errorf("reused = %v", r.Reused)
	}
	var oldNames []string
	for _, a := range r.Old {
		oldNames = append(oldNames, a.Key.Service)
	}
	if !slices.Equal(oldNames, []string{"ci", "mail"}) {
		t.Errorf("old = %q", oldNames)
	}
	if len(r.Breached) != 2 || r.Breached[0].Key.Service != "bank" || r.Breached[0].Count != 2_000_000 {
		t.Errorf("breached = %+v", r.Breached)
	}
	if r.Checked != 5 || r.Problems() != 3+3+2+2 {
		t.Errorf("checked %d, problems %d", r.Checked, r.Problems())
	}
}

// Checks left off find nothing; a breach list that can't be read stops the check.
func TestChecksOff(t *testing.T) {
	c := &Checker{Now: time.Now()}
	e := vault.Entry{Key: key(vault.KindPassword, "a"), UpdatedAt: time.Now().AddDate(-10, 0, 0)}
	if err := c.Add(&e, []byte("password1")); err != nil {
		t.Fatal(err)
	}
	if r := c.Report(); r.Problems() != 0 || r.Checked != 1 {
		t.Errorf("with every check off: %+v", r)
	}
	c = &Checker{Now: time.Now(), Breaches: breaches{}}
	if err := c.Add(&e, []byte("unreadable")); err == nil {
		t.Error("a breach lookup's error was dropped")
	}
}
