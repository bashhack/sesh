package bitwarden

import (
	"encoding/json"
	"strings"
	"testing"

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
	for _, want := range []string{`folder "Work Accounts" is "Work-Accounts"`, `field "linked user" not kept`, "1 old password not kept", `field "2fa enabled" is "2fa-enabled"`} {
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

// A login with only a passkey says so when it's skipped.
func TestEntries_PasskeyOnly(t *testing.T) {
	exp := Export{Items: []Item{{Type: TypeLogin, Name: "webauthn.io", Login: &Login{Username: "u", Fido2Credentials: []json.RawMessage{json.RawMessage(`{}`)}}}}}
	es := Entries(&exp)
	if len(es) != 1 || es[0].Skip != "a login with only a passkey, which sesh doesn't hold" {
		t.Errorf("entries = %+v", es)
	}
}
