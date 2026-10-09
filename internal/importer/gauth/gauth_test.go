package gauth

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

// A transfer code published in the README of github.com/dim13/otpauth
// (commit 7c39ac5), with its documented decoding: one TOTP account,
// "Example:alice@google.com", issuer "Example", secret JBSWY3DPEHPK3PXP.
// It has no algorithm, digits, or batch fields, so the defaults apply.
const sample = "otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8SGEV4YW1wbGU6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZTAC"

func TestParse_Sample(t *testing.T) {
	p, err := Parse(sample)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Accounts) != 1 || p.BatchSize != 1 || p.BatchIndex != 0 {
		t.Fatalf("payload = %+v", p)
	}
	a := p.Accounts[0]
	if a.Secret != "JBSWY3DPEHPK3PXP" || a.Name != "Example:alice@google.com" || a.Issuer != "Example" ||
		a.Algorithm != "SHA1" || a.Digits != 6 || a.Type != TypeTOTP {
		t.Errorf("account = %+v", a)
	}
}

// encode builds a payload as Google Authenticator does, for tests.
func encode(accounts [][]byte, size, index int) string {
	var b []byte
	for _, a := range accounts {
		b = append(b, 0x0a)
		b = appendVarint(b, uint64(len(a)))
		b = append(b, a...)
	}
	b = append(b, 0x10, 1, 0x18)
	b = appendVarint(b, uint64(size))
	b = append(b, 0x20)
	b = appendVarint(b, uint64(index))
	return "otpauth-migration://offline?data=" + url.QueryEscape(base64.StdEncoding.EncodeToString(b))
}

func account(secret []byte, name, issuer string, algo, digits, typ int) []byte {
	var b []byte
	field := func(n int, v []byte) {
		b = append(b, byte(n<<3|2))
		b = appendVarint(b, uint64(len(v)))
		b = append(b, v...)
	}
	field(1, secret)
	field(2, []byte(name))
	if issuer != "" {
		field(3, []byte(issuer))
	}
	b = append(b, 4<<3, byte(algo), 5<<3, byte(digits), 6<<3, byte(typ))
	return b
}

func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func TestParse_Settings(t *testing.T) {
	uri := encode([][]byte{
		account([]byte("12345678901234567890"), "bob", "", 2, 2, 2),
		account([]byte("abc"), "Corp:carol", "Corp", 3, 1, 1),
		account([]byte("abc"), "md5", "X", 4, 1, 2),
	}, 2, 1)
	p, err := Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	if p.BatchSize != 2 || p.BatchIndex != 1 || len(p.Accounts) != 3 {
		t.Fatalf("payload = %+v", p)
	}
	got := []string{}
	for _, a := range p.Accounts {
		got = append(got, a.Name+"|"+a.Issuer+"|"+a.Algorithm+"|"+string(rune('0'+a.Digits))+"|"+string(a.Type))
	}
	if strings.Join(got, " ") != "bob||SHA256|8|totp Corp:carol|Corp|SHA512|6|hotp md5|X|MD5|6|totp" {
		t.Errorf("accounts = %v", got)
	}
	if p.Accounts[0].Secret != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" {
		t.Errorf("secret = %s", p.Accounts[0].Secret)
	}
}

func TestParse_Refused(t *testing.T) {
	for in, wantSub := range map[string]string{
		"otpauth://totp/x?secret=A":                     "isn't a Google Authenticator transfer code",
		"otpauth-migration://offline":                   "has no data",
		"otpauth-migration://offline?data=%%%":          "has no data",
		"otpauth-migration://offline?data=bm90IHByb3Rv": "damaged",
		"otpauth-migration://offline?data=Cg==":         "damaged",
	} {
		if _, err := Parse(in); err == nil || !strings.Contains(err.Error(), wantSub) {
			t.Errorf("Parse(%q) = %v, want an error containing %q", in, err, wantSub)
		}
	}
}

// Each account becomes a TOTP entry named by its issuer and account, with
// its code settings; one sesh can't use says why.
func TestAccount_Entry(t *testing.T) {
	for _, tc := range []struct {
		wantID   string
		wantAlgo string
		wantSkip string
		a        Account
		digits   int
	}{
		{a: Account{Secret: "JBSWY3DPEHPK3PXP", Name: "Example:alice@google.com", Issuer: "Example", Algorithm: "SHA1", Digits: 6, Type: TypeTOTP}, wantID: "totp/Example/alice@google.com"},
		{a: Account{Secret: "JBSWY3DPEHPK3PXP", Name: "GitHub:alice", Issuer: "GitHub", Algorithm: "SHA256", Digits: 8, Type: TypeTOTP}, wantID: "totp/GitHub/alice", wantAlgo: "SHA256", digits: 8},
		{a: Account{Secret: "JBSWY3DPEHPK3PXP", Name: "Corp:carol", Algorithm: "SHA1", Digits: 6, Type: TypeTOTP}, wantID: "totp/Corp/carol"},
		{a: Account{Secret: "JBSWY3DPEHPK3PXP", Name: "plainname", Algorithm: "SHA1", Digits: 6, Type: TypeTOTP}, wantID: "totp/plainname"},
		{a: Account{Secret: "JBSWY3DPEHPK3PXP", Name: "bob", Issuer: "Acme", Algorithm: "SHA1", Digits: 6, Type: TypeTOTP}, wantID: "totp/Acme/bob"},
		{a: Account{Secret: "JBSWY3DPEHPK3PXP", Name: "x", Issuer: "X", Algorithm: "SHA1", Digits: 6, Type: TypeHOTP}, wantSkip: "a counter-based (HOTP) code, which sesh doesn't make"},
		{a: Account{Secret: "JBSWY3DPEHPK3PXP", Name: "x", Issuer: "X", Algorithm: "MD5", Digits: 6, Type: TypeTOTP}, wantSkip: "uses MD5, which sesh doesn't support"},
		{a: Account{Secret: "JBSWY3DPEHPK3PXP", Name: "a/b", Issuer: "X", Algorithm: "SHA1", Digits: 6, Type: TypeTOTP}, wantSkip: `the username "a/b" contains "/"`},
		{a: Account{Secret: "JBSWY3DPEHPK3PXP", Name: "", Issuer: "", Algorithm: "SHA1", Digits: 6, Type: TypeTOTP}, wantSkip: "has no name"},
	} {
		k, params, skip := tc.a.Entry()
		if tc.wantSkip != "" {
			if !strings.Contains(skip, tc.wantSkip) {
				t.Errorf("%+v: skip %q, want %q", tc.a, skip, tc.wantSkip)
			}
			continue
		}
		if skip != "" || k.String() != tc.wantID || params.Algorithm != tc.wantAlgo || params.Digits != tc.digits || params.Issuer != tc.a.Issuer {
			t.Errorf("%+v: %s %+v %q, want %s", tc.a, k, params, skip, tc.wantID)
		}
	}
}

// A batch size or index out of range is damage: sesh would otherwise count
// up to whatever a crafted code says.
func TestParse_BatchRange(t *testing.T) {
	acc := account([]byte("12345678901234567890"), "a", "A", 1, 1, 2)
	for name, uri := range map[string]string{
		"huge size":     encode([][]byte{acc}, 200, 0),
		"index too big": encode([][]byte{acc}, 2, 2),
	} {
		if _, err := Parse(uri); err == nil || !strings.Contains(err.Error(), "damaged") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The data is read however it was carried: a "+" turned into a space, the
// URL-safe alphabet, no padding, or a #fragment after it.
func TestParse_DataForms(t *testing.T) {
	// A secret whose base64 holds "+" and "/", so each form is tested: the
	// bytes give both at one of the three ways base64 can line up.
	var secret []byte
	var raw string
	for shift := range 3 {
		secret = append(bytes.Repeat([]byte{0}, shift), 0xfb, 0xef, 0xbe, 0xfb, 0xef, 0xbe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
		_, data, _ := strings.Cut(encode([][]byte{account(secret, "a:b", "a", 1, 1, 2)}, 1, 0), "data=")
		var err error
		if raw, err = url.QueryUnescape(data); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(raw, "+") && strings.Contains(raw, "/") {
			break
		}
	}
	if !strings.Contains(raw, "+") || !strings.Contains(raw, "/") {
		t.Fatalf("the test data %q has no + or /", raw)
	}
	want := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	for name, d := range map[string]string{
		"a + as a space": strings.ReplaceAll(raw, "+", " "),
		"URL-safe":       strings.NewReplacer("+", "-", "/", "_").Replace(raw),
		"no padding":     strings.TrimRight(raw, "="),
		"a fragment":     url.QueryEscape(raw) + "#x",
		"literal +":      raw,
	} {
		p, err := Parse(Prefix + "offline?data=" + d)
		if err != nil || len(p.Accounts) != 1 || p.Accounts[0].Secret != want {
			t.Errorf("%s: %+v, %v", name, p, err)
		}
	}
}

// Names are split however the issuer is written in the label, and a
// secret sesh can't use is a reason to skip, found before anything is
// stored.
func TestAccount_EntryForms(t *testing.T) {
	for _, tc := range []struct {
		wantID, wantSkip string
		a                Account
	}{
		{wantID: "totp/GitHub/alice", a: Account{Name: "github:alice", Issuer: "GitHub", Secret: "JBSWY3DPEHPK3PXP", Algorithm: "SHA1", Digits: 6, Type: TypeTOTP}},
		{wantID: "totp/Google/me", a: Account{Name: "Google: me", Issuer: "Google", Secret: "JBSWY3DPEHPK3PXP", Algorithm: "SHA1", Digits: 6, Type: TypeTOTP}},
		{wantID: "totp/AWS/Amazon Web Services:root", a: Account{Name: "Amazon Web Services:root", Issuer: "AWS", Secret: "JBSWY3DPEHPK3PXP", Algorithm: "SHA1", Digits: 6, Type: TypeTOTP}},
		{wantID: "totp/Solo", a: Account{Name: "", Issuer: "Solo", Secret: "JBSWY3DPEHPK3PXP", Algorithm: "SHA1", Digits: 6, Type: TypeTOTP}},
		{wantSkip: "the secret can't be used: secret too short", a: Account{Name: "bob", Issuer: "Short", Secret: "MFRGG", Algorithm: "SHA1", Digits: 6, Type: TypeTOTP}},
	} {
		k, _, skip := tc.a.Entry()
		if tc.wantSkip != "" {
			if !strings.Contains(skip, tc.wantSkip) {
				t.Errorf("%+v: skip %q, want %q", tc.a, skip, tc.wantSkip)
			}
			continue
		}
		if skip != "" || k.String() != tc.wantID {
			t.Errorf("%+v: %s %q, want %s", tc.a, k, skip, tc.wantID)
		}
	}
}
