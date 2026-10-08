package vault_test

import (
	"slices"
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
		// Emoji whose base isn't a symbol (‼️, ℹ️, 〽️).
		{Kind: vault.KindPassword, Service: "alerts \u203c\ufe0f \u2139\ufe0f \u303d\ufe0f"},
		// A Japanese name with an ideographic variation selector (葛󠄀飾).
		{Kind: vault.KindPassword, Service: "\u845b\U000E0100\u98fe"},
		// Standardized variants after Han and Myanmar letters.
		{Kind: vault.KindPassword, Service: "\u4e0d\ufe00 \u1000\ufe00"},
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

func TestCheckTagAndFolder(t *testing.T) {
	for _, tag := range []string{"work", "a-b_c.d", "café", "cafe\u0301", "हिंदी", "2026", "v1.2", strings.Repeat("t", vault.MaxTagLength)} {
		if err := vault.CheckTag(tag); err != nil {
			t.Errorf("CheckTag(%q) = %v, want nil", tag, err)
		}
	}
	for tag, wantSub := range map[string]string{
		"":         "is empty",
		"a b":      `contains ' '`,
		"a,b":      `contains ','`,
		"a/b":      `contains '/'`,
		"a\u200bb": `contains '\u200b'`,
		"\u3164":   `contains '\u3164'`,
		"-x":       `can't start with "-"`,
		"a\ufe0f":  "contains an invisible character",
		"\u0301a":  `contains '\u0301'`,
		strings.Repeat("t", vault.MaxTagLength+1): "the most is 64",
	} {
		if err := vault.CheckTag(tag); err == nil || !strings.Contains(err.Error(), wantSub) {
			t.Errorf("CheckTag(%q) = %v, want it to contain %q", tag, err, wantSub)
		}
	}
	for _, f := range []string{"", "work", "work/aws", "personal/banking.old/2026"} {
		if err := vault.CheckFolder(f); err != nil {
			t.Errorf("CheckFolder(%q) = %v, want nil", f, err)
		}
	}
	for f, wantSub := range map[string]string{
		"/work":     "has an empty part",
		"work/":     "has an empty part",
		"work//aws": "has an empty part",
		"work/a b":  `contains ' '`,
		"work/-x":   `can't start with "-"`,
		"work/../x": `the folder "work/../x" has a part that's only dots`,
		".":         "has a part that's only dots",
		"work/" + strings.Repeat("a", vault.MaxTagLength+1): "a part is 65 characters long; the most is 64",
		strings.Repeat("f/", vault.MaxFolderLength/2) + "f": "the most is 256",
	} {
		if err := vault.CheckFolder(f); err == nil || !strings.Contains(err.Error(), wantSub) {
			t.Errorf("CheckFolder(%q) = %v, want it to contain %q", f, err, wantSub)
		}
	}
}

func TestNormalizeTags(t *testing.T) {
	if got := vault.NormalizeTags([]string{"b", "a", "b"}); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("NormalizeTags = %q, want [a b]", got)
	}
	if got := vault.NormalizeTags(nil); got != nil {
		t.Errorf("NormalizeTags(nil) = %q, want nil", got)
	}
}

// The stored parts of an entry's details put back together give the same
// details; damaged or disagreeing parts are refused, not misread.
func TestDetailsEncoding(t *testing.T) {
	k := vault.Key{Kind: vault.KindPassword, Service: "github"}
	d := vault.Details{URL: "https://github.com", Notes: []byte("n\x00tes"), Fields: []vault.Field{
		{Name: "email", Value: []byte("a@b")},
		{Name: "pin", Value: []byte("1234"), Secret: true},
		{Name: "otp-seed", Value: []byte{0xff, 0x00}, Secret: true},
	}}
	url, plain, sealed, err := vault.EncodeDetails(&d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain, "1234") || strings.Contains(plain, "n\\u0000tes") {
		t.Errorf("the readable part holds a secret: %s", plain)
	}
	e := vault.Entry{Key: k}
	if err := vault.DecodeEntryDetails(&e, url, plain); err != nil {
		t.Fatal(err)
	}
	got, err := vault.DecodeDetails(&e, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != d.URL || string(got.Notes) != string(d.Notes) || len(got.Fields) != 3 || string(got.Fields[2].Value) != "\xff\x00" || string(got.Fields[0].Value) != "a@b" {
		t.Errorf("round trip = %+v, want %+v", got, d)
	}

	// Nothing sealed when there's nothing secret; nothing at all for none.
	if _, p, s, _ := vault.EncodeDetails(&vault.Details{Fields: []vault.Field{{Name: "a", Value: []byte("b")}}}); p == "" || s != nil { //nolint:errcheck // can't fail
		t.Errorf("plain only: plain %q, sealed %v", p, s)
	}
	if u, p, s, _ := vault.EncodeDetails(&vault.Details{}); u != "" || p != "" || s != nil { //nolint:errcheck // can't fail
		t.Errorf("none: %q %q %v", u, p, s)
	}

	for name, damaged := range map[string][]byte{
		"empty":           {},
		"unknown layout":  append([]byte{2}, sealed[1:]...),
		"cut short":       sealed[:len(sealed)-1],
		"extra bytes":     append(slices.Clone(sealed), 0),
		"length too long": append([]byte{1, 0xff, 0xff, 0xff, 0xff}, sealed[5:]...),
	} {
		if _, err := vault.DecodeDetails(&e, damaged); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	// The readable part and the sealed one must agree.
	if _, err := vault.DecodeDetails(&e, nil); err == nil || !strings.Contains(err.Error(), "the notes don't match their record") {
		t.Errorf("no sealed part: %v", err)
	}
	_, _, onlyPin, _ := vault.EncodeDetails(&vault.Details{Notes: []byte("n\x00tes"), Fields: []vault.Field{{Name: "pin", Value: []byte("1"), Secret: true}}}) //nolint:errcheck // can't fail
	if _, err := vault.DecodeDetails(&e, onlyPin); err == nil || !strings.Contains(err.Error(), `the secret field "otp-seed" has no value`) {
		t.Errorf("a missing secret value: %v", err)
	}
	// A name sealed twice is damage, not a value to pick from.
	twice := append(append([]byte{1, 0, 0, 0, 0, 0, 0, 0, 2}, part("pin")...), part("1")...)
	twice = append(append(twice, part("pin")...), part("2")...)
	pinOnly := vault.Entry{Key: k, Fields: []vault.Field{{Name: "pin", Secret: true}}}
	if _, err := vault.DecodeDetails(&pinOnly, twice); err == nil {
		t.Error("a name sealed twice decoded")
	}
	_, _, extra, _ := vault.EncodeDetails(&vault.Details{Notes: []byte("x"), Fields: []vault.Field{{Name: "pin", Value: []byte("1"), Secret: true}, {Name: "otp-seed", Value: []byte("1"), Secret: true}, {Name: "more", Value: []byte("1"), Secret: true}}}) //nolint:errcheck // can't fail
	if _, err := vault.DecodeDetails(&e, extra); err == nil || !strings.Contains(err.Error(), "secret values for fields it doesn't have") {
		t.Errorf("an extra secret value: %v", err)
	}
}

// part is one length-prefixed part of the sealed layout.
func part(s string) []byte {
	return append([]byte{0, 0, 0, byte(len(s))}, s...)
}
