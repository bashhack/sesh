package vault_test

import (
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/vault"
	"github.com/bashhack/sesh/internal/vault/vaulttest"
)

func TestMemStore(t *testing.T) {
	vaulttest.Run(t, func(*testing.T) vault.Store { return vault.NewMemStore() })
}

func TestKey_TextForm(t *testing.T) {
	for s, want := range map[string]vault.Key{
		"password/github/alice": {Kind: vault.KindPassword, Service: "github", Username: "alice"},
		"api_key/openai":        {Kind: vault.KindAPIKey, Service: "openai"},
	} {
		got, err := vault.ParseKey(s)
		if err != nil || got != want {
			t.Errorf("ParseKey(%q) = %+v, %v; want %+v", s, got, err, want)
		}
		if want.String() != s {
			t.Errorf("String() = %q, want %q", want.String(), s)
		}
	}
	for s, wantSub := range map[string]string{
		"github":            "want kind/service",
		"a/b/c/d":           "want kind/service",
		"bogus/github":      `unknown kind "bogus"`,
		"password//alice":   "the service name is empty",
		"sesh-password/x/y": `unknown kind "sesh-password"`,
	} {
		if _, err := vault.ParseKey(s); err == nil || !strings.Contains(err.Error(), wantSub) {
			t.Errorf("ParseKey(%q) = %v, want it to contain %q", s, err, wantSub)
		}
	}
}

func TestKey_Validate(t *testing.T) {
	long := strings.Repeat("é", vault.MaxNameLength)
	for _, k := range []vault.Key{
		{Kind: vault.KindPassword, Service: "My Bank", Username: "alice smith"},
		{Kind: vault.KindPassword, Service: long, Username: long},
	} {
		if err := k.Validate(); err != nil {
			t.Errorf("Validate(%+v) = %v, want nil", k, err)
		}
	}
	for name, tt := range map[string]struct {
		key     vault.Key
		wantSub string
	}{
		"service with a trailing space":  {vault.Key{Kind: vault.KindPassword, Service: "github "}, `the service name "github " starts or ends with a space`},
		"service with a leading space":   {vault.Key{Kind: vault.KindPassword, Service: " github"}, `the service name " github" starts or ends with a space`},
		"service of spaces":              {vault.Key{Kind: vault.KindPassword, Service: "   "}, "starts or ends with a space"},
		"username with a trailing space": {vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice "}, `the username "alice " starts or ends with a space`},
		"a non-breaking space":           {vault.Key{Kind: vault.KindPassword, Service: "github "}, "starts or ends with a space"},
		"service too long":               {vault.Key{Kind: vault.KindPassword, Service: long + "x"}, "the service name is 257 characters long; the most is 256"},
		"username too long":              {vault.Key{Kind: vault.KindPassword, Service: "x", Username: long + "x"}, "the username is 257 characters long; the most is 256"},
	} {
		if err := tt.key.Validate(); err == nil || !strings.Contains(err.Error(), tt.wantSub) {
			t.Errorf("%s: Validate = %v, want it to contain %q", name, err, tt.wantSub)
		}
	}
	if _, err := vault.ParseKey("password/github "); err == nil || !strings.Contains(err.Error(), "starts or ends with a space") {
		t.Errorf("ParseKey with a trailing space = %v, want the space refused", err)
	}
}
