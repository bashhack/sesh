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
