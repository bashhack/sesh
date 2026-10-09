package bitwarden

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/importer"
)

// The genuine export's items become these entries.
func TestEntries_GenuineExport(t *testing.T) {
	exp, err := Parse(read(t, "plain.json"), noPassword)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*importer.Entry{}
	var lines []string
	for _, e := range Entries(&exp) {
		id := e.Key.String()
		if e.Skip != "" {
			id = "skip " + e.Name
		}
		got[id] = e
		lines = append(lines, id)
	}
	t.Logf("entries:\n%s", strings.Join(lines, "\n"))
	gh, ok := got["password/GitHub/alice"]
	if !ok {
		t.Fatalf("no password/GitHub/alice in %v", lines)
	}
	if string(gh.Secret) != "gh-new-password-2" || gh.Details.URL != "https://github.com/login" || gh.Folder != "Work-Accounts" ||
		string(gh.Details.Notes) != "main account\nrecovery codes in the safe" {
		t.Errorf("GitHub = %+v", gh)
	}
	var fields []string
	for _, f := range gh.Details.Fields {
		s := f.Name + "=" + string(f.Value)
		if f.Secret {
			s += "*"
		}
		fields = append(fields, s)
	}
	if want := "recovery-email=alice@example.com pin=4321* 2fa-enabled=true url-2=github.com"; strings.Join(fields, " ") != want {
		t.Errorf("fields %q, want %q", strings.Join(fields, " "), want)
	}
	changes := strings.Join(gh.Changes, "; ")
	if gh.Lost[lostHistory] != 1 {
		t.Errorf("GitHub lost = %v, want 1 old password", gh.Lost)
	}
	for _, want := range []string{`folder "Work Accounts" is "Work-Accounts"`, `field "linked user" not kept`, `field "2fa enabled" is "2fa-enabled"`} {
		if !strings.Contains(changes, want) {
			t.Errorf("changes %q missing %q", changes, want)
		}
	}
	code, ok := got["totp/GitHub/alice"]
	if !ok || string(code.Secret) != "JBSWY3DPEHPK3PXP" || code.Settings.TOTP.Algorithm != "SHA256" || code.Settings.TOTP.Digits != 8 {
		t.Errorf("GitHub TOTP = %+v", code)
	}
	if e, ok := got["password/GitHub (2)/alice"]; !ok || e.Folder != "Personal" {
		t.Errorf("the second GitHub = %+v (%v)", e, ok)
	}
	if e, ok := got["totp/AWS console/root"]; !ok || string(e.Secret) != "GEZDGNBVGY3TQOJQ" || e.Folder != "Work-Accounts/Banking" {
		t.Errorf("AWS TOTP = %+v", e)
	}
	if e, ok := got["skip Steam"]; !ok || !strings.Contains(e.Skip, "a Steam code") {
		t.Errorf("Steam = %+v", e)
	}
	if e, ok := got["password/Steam/gamer"]; !ok || string(e.Secret) != "steam-pw" {
		t.Errorf("Steam password = %+v", e)
	}
	if e, ok := got["password/Router"]; !ok || len(e.Tags) != 1 || e.Tags[0] != "favorite" || e.Details.URL != "192.168.1.1" {
		t.Errorf("Router = %+v", e)
	}
	if e, ok := got["password/a-b site/u"]; !ok || e.Folder != "Bank-Co" {
		t.Errorf("a/b site = %+v", e)
	}
	if e, ok := got["secure_note/Wifi"]; !ok || string(e.Secret) != "SSID: home\nPassword: correct horse" {
		t.Errorf("Wifi = %+v", e)
	}
	if e, ok := got["secure_note/Visa"]; !ok || string(e.Secret) != "Visa card ending 4242" || len(e.Details.Fields) != 5 || !e.Details.Fields[0].Secret {
		t.Errorf("Visa = %+v", e)
	}
	if e, ok := got["secure_note/Me"]; !ok || string(e.Secret) != "Identity: Ms Alice Doe" {
		t.Errorf("Me = %+v", e)
	}
	if e, ok := got["secure_note/deploy key"]; !ok || !strings.HasPrefix(string(e.Secret), "SSH key SHA256:") || !e.Details.Fields[0].Secret {
		t.Errorf("deploy key = %+v", e)
	}
	for _, e := range got {
		if e.Skip == "" && e.Created.IsZero() {
			t.Errorf("%s has no creation time", e.Key)
		}
	}
}

// A login's TOTP entry doesn't repeat what changed about the details,
// which are on its password entry.
func TestEntries_TOTPEntryChanges(t *testing.T) {
	exp, err := Parse(read(t, "plain.json"), noPassword)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range Entries(&exp) {
		if e.Key.String() == "totp/GitHub/alice" && len(e.Changes) != 1 {
			t.Errorf("TOTP entry changes = %q, want only its folder's", e.Changes)
		}
	}
}

// A login with only a passkey is kept as a secure note, its passkey
// counted as not kept.
func TestEntries_PasskeyOnly(t *testing.T) {
	exp := Export{Items: []Item{{Type: TypeLogin, Name: "webauthn.io", Login: &Login{Username: "u", URIs: []URI{{URI: "https://webauthn.io"}}, Fido2Credentials: []json.RawMessage{json.RawMessage(`{}`)}}}}}
	es := Entries(&exp)
	if len(es) != 1 || es[0].Skip != "" || es[0].Key.String() != "secure_note/webauthn.io" || es[0].Lost[lostPasskey] != 1 ||
		es[0].Details.URL != "https://webauthn.io" || string(es[0].Details.Fields[0].Value) != "u" {
		t.Errorf("entries = %+v", es[0])
	}
}

// Two items with one name: the second's entries all get " (2)", whichever
// comes first, so a TOTP key is never filed beside the other's password.
func TestEntries_SameNameItems(t *testing.T) {
	login := func(pw, code string) Item {
		return Item{Type: TypeLogin, Name: "GitHub", Login: &Login{Username: "alice", Password: pw, TOTP: code}}
	}
	exp := Export{Items: []Item{login("first", ""), login("second", "JBSWY3DPEHPK3PXP")}}
	got := map[string]string{}
	for _, e := range Entries(&exp) {
		got[e.Key.String()] = string(e.Secret)
	}
	if got["password/GitHub/alice"] != "first" || got["password/GitHub (2)/alice"] != "second" ||
		got["totp/GitHub (2)/alice"] != "JBSWY3DPEHPK3PXP" || len(got) != 3 {
		t.Errorf("entries = %v", got)
	}
	// A name already as long as sesh holds still fits with " (2)".
	long := strings.Repeat("x", 256)
	exp = Export{Items: []Item{{Type: TypeLogin, Name: long, Login: &Login{Password: "a"}}, {Type: TypeLogin, Name: long, Login: &Login{Password: "b"}}}}
	for _, e := range Entries(&exp) {
		if e.Skip != "" {
			t.Errorf("long name: %s skipped: %s", e.Key, e.Skip)
		}
	}
}

// A TOTP key is read in any case and with spaces or dashes; one sesh
// can't use is skipped with a reason that never holds the key.
func TestTOTPKey(t *testing.T) {
	for in, want := range map[string]string{
		"OTPAUTH://TOTP/Upper:me?secret=GEZDGNBVGY3TQOJQ": "GEZDGNBVGY3TQOJQ",
		"jbsw y3dp-ehpk 3pxp":                             "JBSWY3DPEHPK3PXP",
	} {
		if got, _, why := totpKey(in); got != want || why != "" {
			t.Errorf("totpKey(%q) = %q, %q", in, got, why)
		}
	}
	for in, want := range map[string]string{
		"otpauth://totp/a%zz?secret=GEZDGNBVGY3TQOJQSECRET":            "it doesn't read as an otpauth:// address",
		"otpauth://hotp/a?secret=GEZDGNBVGY3TQOJQSECRET&counter=1":     "a counter-based (HOTP) code",
		"otpauth://totp/a?secret=GEZDGNBVGY3TQOJQSECRET&algorithm=MD5": "it uses MD5",
		"GEZD!!GNBVGY3TQOJQSECRET":                                     "the key isn't a valid base32 key",
		"GEZDG":                                                        "the key is too short",
		"steam://GEZDGNBVGY3TQOJQSECRET":                               "a Steam code",
	} {
		_, _, why := totpKey(in)
		if !strings.Contains(why, want) || strings.Contains(why, "GEZD") || strings.Contains(why, "SECRET") {
			t.Errorf("totpKey(%q) why = %q, want %q and no key", in, why, want)
		}
	}
}

// A custom field named like a URL field, and more fields than sesh holds,
// still import: names made unique, the extra fields counted.
func TestEntries_Fields(t *testing.T) {
	it := Item{Type: TypeLogin, Name: "site", Fields: []Field{{Name: "url 2", Value: "mine", Type: FieldText}},
		Login: &Login{Password: "p", URIs: []URI{{URI: "a.example"}, {URI: "b.example"}}}}
	exp := Export{Items: []Item{it}}
	e := Entries(&exp)[0]
	if e.Skip != "" || len(e.Details.Fields) != 2 || e.Details.Fields[0].Name != "url-2" || e.Details.Fields[1].Name != "url-2-2" {
		t.Errorf("fields = %+v, skip %q", e.Details.Fields, e.Skip)
	}
	card := Item{Type: TypeCard, Name: "card", Card: &Card{Number: "4242424242424242", Code: "1"}}
	for i := range 52 {
		card.Fields = append(card.Fields, Field{Name: fmt.Sprintf("f%d", i), Value: "v", Type: FieldText})
	}
	exp = Export{Items: []Item{card}}
	e = Entries(&exp)[0]
	if e.Skip != "" || len(e.Details.Fields) != 50 || !strings.Contains(strings.Join(e.Changes, ";"), "4 fields not kept: sesh holds 50") {
		t.Errorf("card: %d fields, skip %q, changes %q", len(e.Details.Fields), e.Skip, e.Changes)
	}
}

// An archived item is said to be one.
func TestEntries_Archived(t *testing.T) {
	now := time.Now()
	exp := Export{Items: []Item{{Type: TypeSecureNote, Name: "old", Notes: "n", ArchivedDate: &now}}}
	if e := Entries(&exp)[0]; !strings.Contains(strings.Join(e.Changes, ";"), "archived in Bitwarden") {
		t.Errorf("changes = %q", e.Changes)
	}
}
