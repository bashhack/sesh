package keepass

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// The genuine export's entries become these.
func TestEntries_GenuineExport(t *testing.T) {
	exp, err := Parse(read(t, "app-kdbx4.xml"))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	byKey := map[string]int{}
	entries := Entries(&exp)
	for i, e := range entries {
		k := e.Key.String()
		if e.Skip != "" {
			k = "skip " + e.Name
			got[k] = e.Skip
		} else {
			got[k] = e.Folder + " | " + string(e.Secret)
		}
		byKey[k] = i
	}
	for k, want := range map[string]string{
		"password/Router":           " | router-pw",
		"password/Steam/gamer":      " | steam-pw",
		"skip Steam":                "its TOTP key: a Steam code, which sesh doesn't make",
		"secure_note/Wifi":          " | ssid home",
		"password/a-b site/u":       " | ab-pw",
		"password/GitHub/alice":     "Work-Accounts | gh-pass-2",
		"totp/GitHub/alice":         "Work-Accounts | JBSWY3DPEHPK3PXP",
		"password/Bank/bob":         "Work-Accounts/Banking | bank-pw",
		"totp/Bank/bob":             "Work-Accounts/Banking | GEZDGNBVGY3TQOJQ",
		"password/GitHub (2)/alice": "Personal | gh-personal",
		"skip Old account":          "in KeePass's recycle bin",
	} {
		if got[k] != want {
			t.Errorf("%s = %q, want %q", k, got[k], want)
		}
	}
	if len(entries) != 11 {
		t.Errorf("%d entries: %v", len(entries), got)
	}

	gh := entries[byKey["password/GitHub/alice"]]
	if gh.Details.URL != "https://github.com/login" || string(gh.Details.Notes) != "main account\nrecovery codes in the safe" {
		t.Errorf("GitHub details = %q, %q", gh.Details.URL, gh.Details.Notes)
	}
	var fields []string
	for _, f := range gh.Details.Fields {
		fields = append(fields, fmt.Sprintf("%s=%s secret=%v", f.Name, f.Value, f.Secret))
	}
	if strings.Join(fields, "; ") != "pin=4321 secret=true; recovery-email=alice@example.com secret=false" {
		t.Errorf("GitHub fields = %q", fields)
	}
	if strings.Join(gh.Tags, ",") != "code,work" || gh.Lost[lostHistory] != 4 || gh.Lost[lostAttachment] != 1 ||
		gh.Created.IsZero() || gh.Updated.Before(gh.Created) {
		t.Errorf("GitHub tags %q, lost %v, times %v %v", gh.Tags, gh.Lost, gh.Created, gh.Updated)
	}
	if !strings.Contains(strings.Join(gh.Changes, "\n"), `folder "Work Accounts" is "Work-Accounts" in sesh`) {
		t.Errorf("GitHub changes = %q", gh.Changes)
	}
	ghTOTP := entries[byKey["totp/GitHub/alice"]]
	if ghTOTP.Settings.TOTP != (totp.Params{Algorithm: "SHA256", Digits: 8, Issuer: "GitHub"}) || ghTOTP.Lost != nil || !ghTOTP.Details.IsZero() {
		t.Errorf("GitHub TOTP = %+v, lost %v, details %+v", ghTOTP.Settings, ghTOTP.Lost, ghTOTP.Details)
	}
	if b := entries[byKey["totp/Bank/bob"]]; b.Settings.TOTP != (totp.Params{Issuer: "Bank"}) {
		t.Errorf("Bank TOTP = %+v", b.Settings)
	}
	router := entries[byKey["password/Router"]]
	if !strings.Contains(strings.Join(router.Changes, "\n"), "expired in KeePass on 2026-10-11") {
		t.Errorf("Router changes = %q", router.Changes)
	}
	if ab := entries[byKey["password/a-b site/u"]]; !strings.Contains(strings.Join(ab.Changes, "\n"), `named "a-b site" in sesh`) {
		t.Errorf("a/b site changes = %q", ab.Changes)
	}
	if w := entries[byKey["secure_note/Wifi"]]; !strings.Contains(strings.Join(w.Changes, "\n"), "a secure note in sesh") {
		t.Errorf("Wifi changes = %q", w.Changes)
	}
}

// TOTP in a layout other than KeePassXC's otp field isn't read, and said;
// the password still comes across, as do the fields that aren't TOTP.
func TestEntries_OldTOTPLayouts(t *testing.T) {
	str := func(k, v string) String {
		var s String
		s.Key, s.Value.Text = k, v
		return s
	}
	for name, extra := range map[string][]String{
		"legacy": {str("TOTP Seed", "JBSWY3DPEHPK3PXP"), str("TOTP Settings", "30;6")},
		"keeotp": {str("otp", "key=JBSWY3DPEHPK3PXP&size=6&step=30")},
		"kp2":    {str("TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP")},
	} {
		e := Entry{Strings: append([]String{str("Title", "site"), str("Password", "pw"), str("color", "blue")}, extra...)}
		exp := Export{}
		exp.Root.Group.Entries = []Entry{e}
		got := Entries(&exp)
		if len(got) != 1 || got[0].Skip != "" || got[0].Key.Kind != vault.KindPassword ||
			!strings.Contains(strings.Join(got[0].Changes, "\n"), "older layout sesh doesn't read: add it with sesh --service totp --setup") {
			t.Errorf("%s: %+v", name, got)
			continue
		}
		if f := got[0].Details.Fields; len(f) != 1 || f[0].Name != "color" {
			t.Errorf("%s: fields %+v", name, f)
		}
	}
}

func TestTOTPKey(t *testing.T) {
	for in, want := range map[string]totp.Params{
		"otpauth://totp/Bank:bob?secret=GEZDGNBVGY3TQOJQ&period=30&digits=6&issuer=Bank": {Issuer: "Bank"},
		"otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&algorithm=HMAC-SHA-512&period=0":       {Algorithm: "SHA512", Period: 1},
		"otpauth://totp/Corp:me?secret=GEZDGNBVGY3TQOJQ&secret=AAAA&period=999999":       {Issuer: "Corp", Period: totp.MaxTOTPPeriodSeconds},
	} {
		if key, p, why := totpKey(in); key != "GEZDGNBVGY3TQOJQ" || p != want || why != "" {
			t.Errorf("totpKey(%q) = %q, %+v, %q", in, key, p, why)
		}
	}
	for in, want := range map[string]string{
		"otpauth://totp/x?secret=GEZDGNBVGY3TQOJQSECRET&encoder=steam": "a Steam code",
		"otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQSECRET&counter=1":     "counter-based (HOTP)",
		"otpauth://totp/x?secret=GEZDGNBVGY3TQOJQSECRET&algorithm=MD5": "it uses MD5",
		"otpauth://totp/x?secret=GEZDGNBVGY3TQOJQSECRET&digits=10":     "10-digit codes",
		"otpauth://totp/x?secret=GEZDGNBVGY3TQOJQSECRET&digits=x":      "isn't a number",
		"otpauth://totp/x?issuer=GEZDGNBVGY3TQOJQSECRET":               "it has no key",
		"otpauth://totp/x?secret=GEZD!!GNBVGY3TQOJQSECRET":             "isn't a valid base32 key",
		"otpauth://other/x?secret=GEZDGNBVGY3TQOJQSECRET":              "doesn't read as an otpauth:// address",
	} {
		_, _, why := totpKey(in)
		if !strings.Contains(why, want) || strings.Contains(why, "GEZD") || strings.Contains(why, "SECRET") {
			t.Errorf("totpKey(%q) why = %q, want %q and no key", in, why, want)
		}
	}
}

// An entry that expires later says so; tags are fitted to sesh's rules.
func TestEntries_ExpiryAndTags(t *testing.T) {
	var title, pw String
	title.Key, title.Value.Text = "site", "site"
	title.Key = "Title"
	pw.Key, pw.Value.Text = "Password", "p"
	e := Entry{Strings: []String{title, pw}, Tags: "a b;  work ,,;\tc/d;!!!"}
	e.Times.Expires = "True"
	e.Times.ExpiryTime.Time = time.Now().Add(48 * time.Hour)
	exp := Export{}
	exp.Root.Group.Entries = []Entry{e}
	got := Entries(&exp)[0]
	changes := strings.Join(got.Changes, "\n")
	if strings.Join(got.Tags, ",") != "a-b,work,c-d" || !strings.Contains(changes, "expires in KeePass on ") ||
		!strings.Contains(changes, `tag "a b" is "a-b" in sesh`) || !strings.Contains(changes, `tag "!!!" not kept`) {
		t.Errorf("tags %q, changes:\n%s", got.Tags, changes)
	}
}
