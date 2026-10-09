package secretref

import (
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/vault"
)

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		in, wantID, wantField, wantSub string
	}{
		{in: "sesh://api_key/openai", wantID: "api_key/openai"},
		{in: "sesh://password/github/alice", wantID: "password/github/alice"},
		{in: "sesh://password/db/app#host", wantID: "password/db/app", wantField: "host"},
		{in: "sesh://password/db/app#URL", wantID: "password/db/app", wantField: "URL"},
		{in: "sesh://totp/github/alice", wantID: "totp/github/alice"},
		{in: "api_key/openai", wantSub: `"api_key/openai" isn't a sesh reference: it starts sesh://`},
		{in: "sesh://openai", wantSub: "want kind/service or kind/service/username"},
		{in: "sesh://password/db/app#", wantSub: "names no field after #"},
		{in: "sesh://password/db/app#my pin", wantSub: `the field name "my pin" contains ' '`},
	} {
		r, err := Parse(tc.in)
		if tc.wantSub != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("Parse(%q) = %v, want an error containing %q", tc.in, err, tc.wantSub)
			}
			continue
		}
		if err != nil || r.Key.String() != tc.wantID || r.Field != tc.wantField || r.String() != tc.in {
			t.Errorf("Parse(%q) = %+v (%s), %v", tc.in, r, r, err)
		}
	}
}

// resolveStore holds a password with details, an API key, and a TOTP
// entry.
func resolveStore(t *testing.T) vault.Store {
	t.Helper()
	s := vault.NewMemStore()
	db := vault.Key{Kind: vault.KindPassword, Service: "db", Username: "app"}
	for k, v := range map[vault.Key]string{
		db: "db-pass",
		{Kind: vault.KindAPIKey, Service: "openai"}:                  "sk-1",
		{Kind: vault.KindTOTP, Service: "github", Username: "alice"}: "JBSWY3DPEHPK3PXP",
	} {
		if err := s.Put(k, []byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	d := vault.Details{URL: "https://db.internal", Notes: []byte("notes"), Fields: []vault.Field{
		{Name: "host", Value: []byte("db.internal")},
		{Name: "pin", Value: []byte("4321"), Secret: true},
	}}
	if err := s.SetDetails(db, &d); err != nil {
		t.Fatal(err)
	}
	return s
}

// A reference resolves to the secret, a field, the URL, the notes, or a
// TOTP entry's current code, and says whether the value is secret.
func TestResolve(t *testing.T) {
	s := resolveStore(t)
	for ref, want := range map[string]struct {
		value  string
		secret bool
	}{
		"sesh://password/db/app":       {"db-pass", true},
		"sesh://password/db/app#HOST":  {"db.internal", false},
		"sesh://password/db/app#pin":   {"4321", true},
		"sesh://password/db/app#url":   {"https://db.internal", false},
		"sesh://password/db/app#notes": {"notes", true},
		"sesh://api_key/openai":        {"sk-1", true},
	} {
		r, err := Parse(ref)
		if err != nil {
			t.Fatal(err)
		}
		v, err := Resolve(s, r, "run")
		if err != nil || string(v.Value) != want.value || v.Secret != want.secret {
			t.Errorf("Resolve(%s) = %q (secret %v), %v; want %q (%v)", ref, v.Value, v.Secret, err, want.value, want.secret)
		}
	}
	r, _ := Parse("sesh://totp/github/alice") //nolint:errcheck // a valid reference
	v, err := Resolve(s, r, "run")
	if err != nil || len(v.Value) != 6 || !v.Secret {
		t.Errorf("TOTP code = %q (secret %v), %v", v.Value, v.Secret, err)
	}
	for ref, wantSub := range map[string]string{
		"sesh://password/nope":         "sesh://password/nope: entry not found",
		"sesh://password/db/app#nope":  `sesh://password/db/app#nope: password/db/app has no field "nope"; its fields: host, pin`,
		"sesh://api_key/openai#url":    "sesh://api_key/openai#url: api_key/openai has no URL",
		"sesh://totp/github/alice#pin": `sesh://totp/github/alice#pin: totp/github/alice has no field "pin"; it has no fields`,
	} {
		r, err := Parse(ref)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Resolve(s, r, "run"); err == nil || !strings.Contains(err.Error(), wantSub) {
			t.Errorf("Resolve(%s) = %v, want an error containing %q", ref, err, wantSub)
		}
	}
}
