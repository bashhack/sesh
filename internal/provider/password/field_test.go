package password

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/vault"
)

// fieldStore holds password/github/alice with a URL, notes, and a plain
// and a secret field, and password/bare with none.
func fieldStore(t *testing.T) *vault.MemStore {
	t.Helper()
	store := seeded(t, map[string]string{"password/github/alice": "the-password", "password/bare": "x"})
	d := vault.Details{URL: "https://github.com/login", Notes: []byte("line one\nline two"), Fields: []vault.Field{
		{Name: "recovery-email", Value: []byte("alice@example.com")},
		{Name: "pin", Value: []byte("4321"), Secret: true},
	}}
	if err := store.SetDetails(vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}, &d); err != nil {
		t.Fatal(err)
	}
	return store
}

// get --field shows or copies one value: a field, secret or plain, the
// URL, the notes, or the secret itself.
func TestGet_Field(t *testing.T) {
	for field, want := range map[string]string{
		"pin":            "4321",
		"recovery-email": "alice@example.com",
		"url":            "https://github.com/login",
		"URL":            "https://github.com/login",
		"notes":          "line one\nline two",
		"password":       "the-password",
		"secret":         "the-password",
	} {
		p, stdout := newTestProvider(fieldStore(t))
		p.action, p.service, p.username, p.field, p.show = "get", "github", "alice", field, true
		if _, err := p.GetCredentials(); err != nil || stdout.String() != want+"\n" {
			t.Errorf("--field %s --show: %q, %v; want %q", field, stdout.String(), err, want)
		}
		for _, action := range []string{"get", ""} {
			p, _ = newTestProvider(fieldStore(t))
			p.action, p.service, p.username, p.field = action, "github", "alice", field
			creds, err := p.GetClipboardValue()
			if err != nil || creds.CopyValue != want {
				t.Errorf("--field %s --clip: %q, %v; want %q", field, creds.CopyValue, err, want)
			}
		}
	}
	p, _ := newTestProvider(fieldStore(t))
	p.action, p.service, p.username, p.field = "get", "github", "alice", "pin"
	creds, err := p.GetClipboardValue()
	if err != nil || creds.ClipboardDescription != "field pin of github (alice)" {
		t.Errorf("description = %q, %v", creds.ClipboardDescription, err)
	}
}

func TestGet_FieldJSON(t *testing.T) {
	p, stdout := newTestProvider(fieldStore(t))
	p.action, p.service, p.username, p.field, p.format = "get", "github", "alice", "pin", "json"
	if _, err := p.GetCredentials(); err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("%v: %s", err, stdout)
	}
	if got["field"] != "pin" || got["value"] != "4321" || got["service"] != "github" || got["username"] != "alice" || got["type"] != "password" {
		t.Errorf("JSON = %v", got)
	}
}

func TestGet_FieldRefused(t *testing.T) {
	for _, tc := range []struct {
		service, field, action, wantSub string
	}{
		{"github", "nope", "get", `password/github/alice has no field "nope"; its fields: recovery-email, pin`},
		{"bare", "pin", "get", `password/bare has no field "pin"; it has no fields`},
		{"bare", "url", "get", "password/bare has no URL"},
		{"bare", "notes", "get", "password/bare has no notes"},
		{"github", "my pin", "get", `the field name "my pin" contains ' '`},
		{"github", "pin", "store", "--field works with --action get"},
	} {
		p, _ := newTestProvider(fieldStore(t))
		p.action, p.service, p.field = tc.action, tc.service, tc.field
		if tc.service == "github" {
			p.username = "alice"
		}
		err := p.ValidateRequest()
		if err == nil {
			_, err = p.GetCredentials()
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("%s --field %q: %v, want an error containing %q", tc.action, tc.field, err, tc.wantSub)
		}
	}
}
