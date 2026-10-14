package health

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/vault"
)

func key(kind vault.Kind, service string) vault.Key { return vault.Key{Kind: kind, Service: service} }

// names are keys' services, in order.
func names(keys []vault.Key) (out []string) {
	for _, k := range keys {
		out = append(out, k.Service)
	}
	return out
}

// Each check finds what it should, and only for the kinds it covers.
func TestChecks(t *testing.T) {
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	c := &Checker{Now: now, OldAfter: 365 * 24 * time.Hour, IsWeak: password.IsWeak}
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
		{"", vault.Entry{Key: key(vault.KindPassword, "blank"), UpdatedAt: recent}},
	} {
		if err := c.Add(&x.e, []byte(x.secret), nil); err != nil {
			t.Fatal(err)
		}
	}
	damaged := vault.Entry{Key: key(vault.KindPassword, "damaged")}
	if err := c.Add(&damaged, nil, errors.New("doesn't decrypt")); err != nil {
		t.Fatal(err)
	}
	r := c.Report()
	if got := names(r.Weak); !slices.Equal(got, []string{"bank", "blank", "github", "shop"}) {
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
	if !slices.Equal(names(r.Unreadable), []string{"damaged"}) {
		t.Errorf("unreadable = %v", r.Unreadable)
	}
	if r.Checked != 6 || r.Problems() != 4+3+2+1 {
		t.Errorf("checked %d, problems %d", r.Checked, r.Problems())
	}
}

// Checks left off find nothing.
func TestChecksOff(t *testing.T) {
	c := &Checker{Now: time.Now()}
	e := vault.Entry{Key: key(vault.KindPassword, "a"), UpdatedAt: time.Now().AddDate(-10, 0, 0)}
	if err := c.Add(&e, []byte("password1"), nil); err != nil {
		t.Fatal(err)
	}
	if r := c.Report(); r.Problems() != 0 || r.Checked != 1 {
		t.Errorf("with every check off: %+v", r)
	}
}
