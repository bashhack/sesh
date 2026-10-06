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
		// A zero-width joiner inside a name, as emoji sequences use.
		{Kind: vault.KindPassword, Service: "dev\u200dteam"},
		// An emoji with its presentation selector (a heart).
		{Kind: vault.KindPassword, Service: "I \u2764\ufe0f NY"},
		// A flag emoji, spelled with tag characters (Scotland).
		{Kind: vault.KindPassword, Service: "bank \U0001F3F4\U000E0067\U000E0062\U000E0073\U000E0063\U000E0074\U000E007F"},
	} {
		if err := k.Validate(); err != nil {
			t.Errorf("Validate(%+v) = %v, want nil", k, err)
		}
	}
	for name, tt := range map[string]struct {
		key     vault.Key
		wantSub string
	}{
		"service with a trailing space":    {vault.Key{Kind: vault.KindPassword, Service: "github "}, `the service name "github " starts or ends with a space`},
		"service with a leading space":     {vault.Key{Kind: vault.KindPassword, Service: " github"}, `the service name " github" starts or ends with a space`},
		"service of spaces":                {vault.Key{Kind: vault.KindPassword, Service: "   "}, "starts or ends with a space"},
		"username with a trailing space":   {vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice "}, `the username "alice " starts or ends with a space`},
		"a non-breaking space":             {vault.Key{Kind: vault.KindPassword, Service: "github\u00a0"}, "starts or ends with a space"},
		"a zero-width space":               {vault.Key{Kind: vault.KindPassword, Service: "github\u200b"}, "starts or ends with an invisible character"},
		"a byte-order mark":                {vault.Key{Kind: vault.KindPassword, Service: "\ufeffgithub"}, "starts or ends with an invisible character"},
		"a soft hyphen":                    {vault.Key{Kind: vault.KindPassword, Service: "github\u00ad"}, "starts or ends with an invisible character"},
		"a Hangul filler":                  {vault.Key{Kind: vault.KindPassword, Service: "github\u3164"}, "starts or ends with an invisible character"},
		"a braille blank":                  {vault.Key{Kind: vault.KindPassword, Service: "github\u2800"}, "starts or ends with an invisible character"},
		"a direction override":             {vault.Key{Kind: vault.KindPassword, Service: "git\u202ehub"}, "contains a text-direction control character"},
		"a soft hyphen inside":             {vault.Key{Kind: vault.KindPassword, Service: "git\u00adhub"}, "contains an invisible character"},
		"a zero-width space inside":        {vault.Key{Kind: vault.KindPassword, Service: "x", Username: "alice@exam\u200bple.com"}, "contains an invisible character"},
		"a line separator inside":          {vault.Key{Kind: vault.KindPassword, Service: "git\u2028hub"}, "contains an invisible character"},
		"a stray tag character":            {vault.Key{Kind: vault.KindPassword, Service: "git\U000E0067hub"}, "contains an invisible character"},
		"a stray tag at the end":           {vault.Key{Kind: vault.KindPassword, Service: "github\U000E0067"}, "invisible character"},
		"a variation selector on a letter": {vault.Key{Kind: vault.KindPassword, Service: "git\ufe0fhub"}, "contains an invisible character"},
		"a joiner mark inside":             {vault.Key{Kind: vault.KindPassword, Service: "git\u034fhub"}, "contains an invisible character"},
		"a combining grapheme joiner":      {vault.Key{Kind: vault.KindPassword, Service: "github\u034f"}, "starts or ends with an invisible character"},
		"a Mongolian variation selector":   {vault.Key{Kind: vault.KindPassword, Service: "github\u180b"}, "starts or ends with an invisible character"},
		"invalid UTF-8":                    {vault.Key{Kind: vault.KindPassword, Service: "github\xff"}, "isn't valid text"},
		"service too long":                 {vault.Key{Kind: vault.KindPassword, Service: long + "x"}, "the service name is 257 characters long; the most is 256"},
		"username too long":                {vault.Key{Kind: vault.KindPassword, Service: "x", Username: long + "x"}, "the username is 257 characters long; the most is 256"},
		"the structural rules still":       {vault.Key{Kind: vault.KindPassword, Service: "a/b"}, `contains "/"`},
	} {
		if err := tt.key.Validate(); err == nil || !strings.Contains(err.Error(), tt.wantSub) {
			t.Errorf("%s: Validate = %v, want it to contain %q", name, err, tt.wantSub)
		}
	}
}

func TestParseKey_AppliesTheNameRules(t *testing.T) {
	if _, err := vault.ParseKey("password/github "); err == nil || !strings.Contains(err.Error(), "starts or ends with a space") {
		t.Errorf("ParseKey with a trailing space = %v, want it refused", err)
	}
}
