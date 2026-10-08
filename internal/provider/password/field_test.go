package password

import (
	"encoding/json"
	"errors"
	"flag"
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
		"PIN":            "4321",
		"Recovery-Email": "alice@example.com",
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
	p.action, p.service, p.username, p.field, p.format = "get", "github", "alice", "PIN", "json"
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
		wantSub string
		args    []string
	}{
		{`password/github/alice has no field "nope"; its fields: recovery-email, pin`, []string{"--service-name", "github", "--username", "alice", "--field", "nope"}},
		{`password/bare has no field "pin"; it has no fields`, []string{"--service-name", "bare", "--field", "pin"}},
		{"password/bare has no URL", []string{"--service-name", "bare", "--field", "url"}},
		{"password/bare has no notes", []string{"--service-name", "bare", "--field", "notes"}},
		{`the field name "my pin" contains ' '`, []string{"--service-name", "github", "--username", "alice", "--field", "my pin"}},
	} {
		p := storeWith(t, fieldStore(t), "", nil, append([]string{"--action", "get"}, tc.args...)...)
		err := p.ValidateRequest()
		if err == nil {
			_, err = p.GetCredentials()
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("%q: %v, want an error containing %q", tc.args, err, tc.wantSub)
		}
	}
	// A missing entry gets the case hint plain get gives; a secure note's
	// notes are its secret.
	store := fieldStore(t)
	if err := store.Put(vault.Key{Kind: vault.KindNote, Service: "wifi"}, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	for args, wantSub := range map[string]string{
		"GitHub alice pin":        "did you mean password/github/alice?",
		"wifi  notes secure_note": "secure_note/wifi is a secure note: its note is its secret, which --field secret reads",
	} {
		a := strings.Split(args, " ")
		flags := []string{"--action", "get", "--service-name", a[0], "--field", a[2]}
		if a[1] != "" {
			flags = append(flags, "--username", a[1])
		}
		if len(a) > 3 {
			flags = append(flags, "--entry-type", a[3])
		}
		p := storeWith(t, store, "", nil, flags...)
		err := p.ValidateRequest()
		if err == nil {
			_, err = p.GetCredentials()
		}
		if err == nil || !strings.Contains(err.Error(), wantSub) {
			t.Errorf("%s: %v, want %q", args, err, wantSub)
		}
	}
	if err := storeWith(t, store, "", nil, "--field", "a=b").CheckListArgs(); err == nil || !strings.Contains(err.Error(), "don't go with --list or --delete") {
		t.Errorf("--list --field: %v", err)
	}
	p := storeWith(t, fieldStore(t), "", nil, "--action", "search", "--query", "git", "--field", "pin")
	if err := p.ValidateRequest(); err == nil || !strings.Contains(err.Error(), "--field also works with --action get") {
		t.Errorf("search --field: %v", err)
	}
}

// storeWith is a provider with args parsed as the CLI would, typed
// answers given in turn, and stdin.
func storeWith(t *testing.T, store vault.Store, stdin string, typed []string, args ...string) *Provider {
	t.Helper()
	p, _ := newTestProvider(store)
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	if err := p.SetupFlags(fs); err != nil {
		t.Fatal(err)
	}
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	p.stdin = strings.NewReader(stdin)
	orig := readPassword
	t.Cleanup(func() { readPassword = orig })
	readPassword = func() ([]byte, error) {
		if len(typed) == 0 {
			return nil, errors.New("nothing more typed")
		}
		v := typed[0]
		typed = typed[1:]
		return []byte(v), nil
	}
	return p
}

// store takes the details flags too: the entry and its details are
// written together, and storing over an entry changes its details as
// asked, keeping the rest.
func TestStore_Details(t *testing.T) {
	stubStdinIsTerminal(t, true)
	store := vault.NewMemStore()
	p := storeWith(t, store, "my notes\n", []string{"Tr0ub4dor&3-horse-staple", "4321"},
		"--action", "store", "--service-name", "github", "--username", "alice",
		"--url", "https://github.com/login", "--field", "email=a@b", "--secret-field", "pin", "--notes")
	if err := p.ValidateRequest(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.GetCredentials(); err != nil {
		t.Fatal(err)
	}
	k := vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}
	d, err := store.Details(k, "all")
	if err != nil {
		t.Fatal(err)
	}
	pin, _ := d.Field("pin")
	if d.URL != "https://github.com/login" || string(d.Notes) != "my notes\n" || len(d.Fields) != 2 || string(pin.Value) != "4321" {
		t.Errorf("details = %+v (notes %q)", d, d.Notes)
	}
	if secret, err := store.Get(k); err != nil || string(secret) != "Tr0ub4dor&3-horse-staple" {
		t.Errorf("secret = %q, %v", secret, err)
	}

	p = storeWith(t, store, "", []string{"An0ther-long-passphrase!"},
		"--action", "store", "--service-name", "github", "--username", "alice", "--force", "--remove-field", "email")
	if _, err := p.GetCredentials(); err != nil {
		t.Fatal(err)
	}
	if d, err = store.Details(k, "all"); err != nil || d.URL != "https://github.com/login" || len(d.Fields) != 1 || string(d.Notes) != "my notes\n" {
		t.Errorf("after storing over it: %+v, %v", d, err)
	}
}

func TestStore_DetailsRefused(t *testing.T) {
	for _, tc := range []struct {
		wantSub  string
		args     []string
		terminal bool
	}{
		{"a secure note can't have notes", []string{"--action", "store", "--service-name", "wifi", "--entry-type", "secure_note", "--notes"}, true},
		{"--url, --notes and the field flags work with --action store, or with sesh edit", []string{"--action", "get", "--service-name", "github", "--url", "x"}, true},
		{"get reads one field", []string{"--action", "get", "--service-name", "github", "--field", "a", "--field", "b"}, true},
		{"without a terminal, only one value can come from stdin", []string{"--action", "store", "--service-name", "wifi", "--entry-type", "secure_note", "--secret-field", "pin"}, false},
		{"--field wants name=value", []string{"--action", "store", "--service-name", "github", "--field", "pin"}, true},
	} {
		stubStdinIsTerminal(t, tc.terminal)
		p := storeWith(t, vault.NewMemStore(), "", nil, tc.args...)
		err := p.ValidateRequest()
		if err == nil {
			_, err = p.GetCredentials()
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("%q: %v, want an error containing %q", tc.args, err, tc.wantSub)
		}
	}
}
