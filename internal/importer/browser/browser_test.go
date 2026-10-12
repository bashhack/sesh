package browser

import (
	"os"
	"strings"
	"testing"
	"time"
)

// The fixtures in testdata are genuine exports of the same five made-up
// logins, made in a throwaway container: chromium.csv by Chromium
// 154.0.8037.92 (chrome://password-manager/settings, Export passwords),
// firefox.csv by Firefox ESR 153.4.0 (about:logins, Export Passwords). In
// Chromium alice's GitHub login has a two-line note; in Firefox its
// password was changed after it was saved.

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
	if _, err := Parse([]byte("a,b\n1,2\n")); err == nil || !strings.Contains(err.Error(), "isn't a Chrome or Firefox password export") {
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
