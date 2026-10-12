package browser

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/totp"
)

// The fixtures in testdata are genuine exports of made-up logins:
//   - chromium.csv and firefox.csv, of the same five, made in a throwaway
//     container by Chromium 154.0.8037.92 (chrome://password-manager/
//     settings, Export passwords) and Firefox ESR 153.4.0 (about:logins,
//     Export Passwords); in Chromium alice's GitHub login has a two-line
//     note, in Firefox its password was changed after it was saved;
//   - safari.csv, one throwaway entry titled "GitHub Test" with a
//     two-line note and a verification code, exported from Apple's
//     Passwords app on macOS (File > Export Selected Password to File).

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParse(t *testing.T) {
	cr, err := Parse(read(t, "chromium.csv"))
	if err != nil || cr.Browser != Chrome || len(cr.Logins) != 5 {
		t.Fatalf("Chromium: %+v, %v", cr, err)
	}
	gh := cr.Logins[1]
	if gh.Name != "github.com" || gh.URL != "https://github.com/" || gh.Username != "alice" || gh.Password != "gh-pass-1" || gh.Note != "main account\nrecovery codes in the safe" {
		t.Errorf("Chromium GitHub = %+v", gh)
	}
	if bob := cr.Logins[2]; bob.Password != `gh,"bob"pw` {
		t.Errorf("Chromium bob's password = %q", bob.Password)
	}
	ff, err := Parse(read(t, "firefox.csv"))
	if err != nil || ff.Browser != Firefox || len(ff.Logins) != 5 {
		t.Fatalf("Firefox: %+v, %v", ff, err)
	}
	a := ff.Logins[0]
	if a.URL != "https://github.com" || a.Password != "gh-pass-2" || !a.Created.Equal(time.UnixMilli(1791686628223)) || !a.Updated.Equal(time.UnixMilli(1791686730455)) {
		t.Errorf("Firefox GitHub = %+v", a)
	}
	if j := ff.Logins[4]; j.Username != "jürgen" || j.Password != "pässwörd" {
		t.Errorf("Firefox jürgen = %+v", j)
	}
	if _, err := Parse([]byte("a,b\n1,2\n")); err == nil || !strings.Contains(err.Error(), "isn't a Chrome, Firefox or Safari password export") {
		t.Errorf("other CSV: %v", err)
	}
	if _, err := Parse([]byte("name,url,username,password,note\ngithub.com,https://github.com/,a\n")); err == nil || !strings.Contains(err.Error(), "login 1 has 3 columns") {
		t.Errorf("short row: %v", err)
	}
}

// Both exports become the same entries, named for the site without
// "www."; a second login for one site and username gets " (2)".
func TestEntries(t *testing.T) {
	for _, name := range []string{"chromium.csv", "firefox.csv"} {
		exp, err := Parse(read(t, name))
		if err != nil {
			t.Fatal(err)
		}
		var keys []string
		for _, e := range Entries(&exp) {
			if e.Skip != "" {
				t.Errorf("%s: %s skipped: %s", name, e.Name, e.Skip)
			}
			keys = append(keys, e.Key.String()+" "+e.Details.URL)
		}
		want := map[string]string{
			"chromium.csv": "password/accounts.google.com/alice@example.com https://accounts.google.com/; password/github.com/alice https://github.com/; password/github.com/bob https://github.com/; password/login.example.org/jürgen https://login.example.org/; password/example.com:8443 https://www.example.com:8443/",
			"firefox.csv":  "password/github.com/alice https://github.com; password/github.com/bob https://github.com; password/example.com:8443 https://www.example.com:8443; password/accounts.google.com/alice@example.com https://accounts.google.com; password/login.example.org/jürgen https://login.example.org",
		}[name]
		if got := strings.Join(keys, "; "); got != want {
			t.Errorf("%s:\n got %s\nwant %s", name, got, want)
		}
	}
	exp := Export{Browser: Chrome, Logins: []Login{
		{URL: "https://github.com/", Username: "a", Password: "1"},
		{URL: "http://www.github.com/", Username: "a", Password: "2"},
		{Name: "Some App", URL: "android://hash@com.example.app/", Username: "a", Password: "3"},
		{URL: "https://example.org/", Username: "b"},
	}}
	got := Entries(&exp)
	if got[1].Key.Service != "github.com (2)" || got[2].Key.Service != "Some App" || got[3].Skip != "it has no password" {
		t.Errorf("entries = %v, %v, %v, skip %q", got[1].Key, got[2].Key, got[3].Key, got[3].Skip)
	}
}

// Chrome's header before it had notes is read too, as is a file starting
// with a byte-order mark.
func TestParse_OldChromeAndBOM(t *testing.T) {
	old, err := Parse([]byte("name,url,username,password\ngithub.com,https://github.com/,alice,pw\n"))
	if err != nil || old.Browser != Chrome || len(old.Logins) != 1 || old.Logins[0].Password != "pw" || old.Logins[0].Note != "" {
		t.Errorf("four columns: %+v, %v", old, err)
	}
	bom, err := Parse(append([]byte("\ufeff"), read(t, "firefox.csv")...))
	if err != nil || bom.Browser != Firefox || len(bom.Logins) != 5 {
		t.Errorf("BOM: %+v, %v", bom, err)
	}
}

// Names for addresses that aren't plain web ones, repeats of one login,
// Firefox's own account, and a realm.
func TestEntries_Naming(t *testing.T) {
	exp := Export{Browser: Firefox, Logins: []Login{
		{URL: "https://example.com", Username: "a", Password: "1"},
		{URL: "http://www.example.com", Username: "a", Password: "1"},
		{URL: "https://example.com", Username: "a", Password: "2"},
		{URL: "https://xn--bcher-kva.example:8443", Username: "a", Password: "1"},
		{URL: "https://example.org", Username: "a", Password: "1"},
		{URL: "https://example.org", Username: "a", Password: "1", Realm: "Admin area"},
		{URL: "https://[::1]:8443", Username: "a", Password: "1"},
		{URL: "moz-proxy://127.0.0.1:8888", Username: "a", Password: "1", Realm: "proxy"},
		{URL: "ftp://ftp.site.com", Username: "a", Password: "1"},
		{URL: "android://hash@com.example.app/", Username: "a", Password: "1"},
		{URL: "chrome://FirefoxAccounts", Username: "uid", Password: `{"scopedKeys":{}}`, Realm: "Firefox Accounts credentials"},
	}}
	var got []string
	for _, e := range Entries(&exp) {
		if e.Skip != "" {
			got = append(got, "skip: "+e.Skip)
			continue
		}
		s := e.Key.String()
		for _, f := range e.Details.Fields {
			s += " " + f.Name + "=" + string(f.Value)
		}
		got = append(got, s)
	}
	want := []string{
		"password/example.com/a",
		"password/example.com (2)/a",
		"password/example.com (3)/a",
		"password/xn--bcher-kva.example:8443/a",
		"password/example.org/a",
		"password/example.org (2)/a http-realm=Admin area",
		"password/[::1]:8443/a",
		"password/127.0.0.1:8888/a http-realm=proxy",
		"password/ftp.site.com/a",
		"password/app.example.com/a",
		"skip: Firefox's own sign-in to your Mozilla account",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// In Chrome's export a repeat of one login is skipped, and an
// internationalised name is in Unicode only where Chrome's own name for it
// is, as Chrome shows Unicode only after its lookalike checks.
func TestEntries_Chrome(t *testing.T) {
	exp := Export{Browser: Chrome, Logins: []Login{
		{Name: "example.com", URL: "https://example.com/", Username: "a", Password: "1"},
		{Name: "example.com", URL: "https://example.com/", Username: "a", Password: "1"},
		{Name: "bücher.example:8443", URL: "https://xn--bcher-kva.example:8443/", Username: "a", Password: "1"},
		{Name: "http://www.bücher.example", URL: "http://www.xn--bcher-kva.example/", Username: "b", Password: "1"},
		// A lookalike of apple.com (Cyrillic а), which Chrome names in xn--.
		{Name: "xn--pple-43d.com", URL: "https://xn--pple-43d.com/", Username: "a", Password: "1"},
		// Arabic, right to left, which Chrome names in xn--.
		{Name: "xn--4gbrim.xn----ymcbaaajlc6dj7bxne2c.xn--wgbh1c", URL: "https://xn--4gbrim.xn----ymcbaaajlc6dj7bxne2c.xn--wgbh1c/", Username: "a", Password: "1"},
	}}
	var got []string
	for _, e := range Entries(&exp) {
		if e.Skip != "" {
			got = append(got, "skip: "+e.Skip)
		} else {
			got = append(got, e.Key.String())
		}
	}
	want := []string{
		"password/example.com/a",
		"skip: the same login as an earlier one, for another address on the site",
		"password/bücher.example:8443/a",
		"password/bücher.example/b",
		"password/xn--pple-43d.com/a",
		"password/xn--4gbrim.xn----ymcbaaajlc6dj7bxne2c.xn--wgbh1c/a",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// Safari's entry is named by its title, its verification code a TOTP
// entry beside the password entry.
func TestEntries_Safari(t *testing.T) {
	exp, err := Parse(read(t, "safari.csv"))
	if err != nil || exp.Browser != Safari || len(exp.Logins) != 1 {
		t.Fatalf("%+v, %v", exp, err)
	}
	got := Entries(&exp)
	if len(got) != 2 {
		t.Fatalf("%d entries", len(got))
	}
	p, o := got[0], got[1]
	if p.Key.String() != "password/GitHub Test/alice" || string(p.Secret) != "gh-pass-1" || p.Details.URL != "https://github.com/" ||
		string(p.Details.Notes) != "main account\nrecovery codes in the safe" {
		t.Errorf("password entry = %v %q %+v", p.Key, p.Secret, p.Details)
	}
	if o.Key.String() != "totp/GitHub Test/alice" || string(o.Secret) != "JBSWY3DPEHPK3PXP" || o.Settings.TOTP != (totp.Params{}) || !o.Details.IsZero() || o.Skip != "" {
		t.Errorf("TOTP entry = %v %q %+v %+v skip %q", o.Key, o.Secret, o.Settings, o.Details, o.Skip)
	}

	exp = Export{Browser: Safari, Logins: []Login{
		{Title: "Code only", URL: "https://x.example/", OTPAuth: "otpauth://totp?secret=GEZDGNBVGY3TQOJQ&digits=8", Note: "n"},
		{Title: "\u200b", URL: "https://www.untitled.example/", Username: "u", Password: "p"},
		{Title: "Counter", Password: "p", OTPAuth: "otpauth://hotp?secret=GEZDGNBVGY3TQOJQSECRET&counter=1"},
	}}
	var keys []string
	for _, e := range Entries(&exp) {
		keys = append(keys, e.Key.String()+"|"+e.Skip+"|"+string(e.Details.Notes)+"|"+e.Details.URL)
	}
	want := "totp/Code only||n|https://x.example/; password/untitled.example/u|||https://www.untitled.example/; password/Counter|||; totp/Counter|its verification code: a counter-based (HOTP) code, which sesh doesn't make||"
	if got := strings.Join(keys, "; "); got != want {
		t.Errorf("got %s", got)
	}
}

func TestTOTPKey(t *testing.T) {
	for in, want := range map[string]string{
		"otpauth://totp?secret=GEZDGNBVGY3TQOJQSECRET&algorithm=MD5":                                             "it uses MD5",
		"otpauth://totp?secret=GEZDGNBVGY3TQOJQSECRET&digits=10":                                                 "10-digit codes",
		"otpauth://totp?secret=GEZDGNBVGY3TQOJQSECRET&period=0":                                                  "isn't a positive number",
		"otpauth://totp?issuer=GEZDGNBVGY3TQOJQSECRET":                                                           "it has no key",
		"otpauth://totp?secret=GEZD!!GNBVGY3TQOJQSECRET":                                                         "isn't a valid base32 key",
		"otpauth://totp?secret=GEZDGNBVGY3TQOJQSECRET&encoder=steam":                                             "a Steam code",
		"otpauth://totp/Steam:gamer?secret=GEZDGNBVGY3TQOJQSECRET&period=30&digits=5&issuer=Steam&encoder=Steam": "a Steam code",
		"otpauth://totp?secret=GEZDGNBVGY3TQOJQSECRET&period=100000":                                             "longer than sesh allows",
		"otpauth://totp?secret=GEZDGNBVGY3TQOJQSECRET&digits=x":                                                  "isn't a number",
		"otpauth://totp/a%zz?secret=GEZDGNBVGY3TQOJQSECRET":                                                      "doesn't read as an otpauth:// address",
	} {
		if _, _, why := totpKey(in); !strings.Contains(why, want) || strings.Contains(why, "GEZD") {
			t.Errorf("totpKey(%q) = %q, want %q and no key", in, why, want)
		}
	}
	if k, p, why := totpKey("OTPAUTH://TOTP/Corp:me?secret=GEZDGNBVGY3TQOJQ&algorithm=SHA256&digits=8&period=60"); k != "GEZDGNBVGY3TQOJQ" || why != "" ||
		p != (totp.Params{Algorithm: "SHA256", Digits: 8, Period: 60, Issuer: "Corp"}) {
		t.Errorf("totpKey = %q %+v %q", k, p, why)
	}
}
