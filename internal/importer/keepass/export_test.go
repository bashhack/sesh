package keepass

import (
	"os"
	"strings"
	"testing"
	"time"
)

// The fixtures in testdata are genuine KeePassXC 2.7.10 files of one
// throwaway database (password kp-test-pass), its values made up:
//   - app.kdbx: made with the app's new-database wizard (KDBX 4); groups and
//     plain entries added with keepassxc-cli, then TOTP, tags, custom and
//     protected fields, an expiry date, and the "a/b site" title set in
//     the app, then a clone of GitHub made with "Replace username and
//     password with references", and a group named "Home/Lab" with an
//     entry;
//   - app-kdbx4.xml: the app's Database > Export > XML File of it;
//   - app.csv: the app's Database > Export > CSV File of it, made before the
//     clone and "Home/Lab";
//   - cli-kdbx3.xml: `keepassxc-cli export -f xml` of a KDBX 3 database made
//     with `keepassxc-cli db-create`.

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParse(t *testing.T) {
	exp, err := Parse(read(t, "app-kdbx4.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if exp.Meta.Generator != "KeePassXC" || exp.Root.Group.Name != "Root" || len(exp.Root.Group.Groups) != 4 {
		t.Fatalf("meta %+v, root %q with %d groups", exp.Meta, exp.Root.Group.Name, len(exp.Root.Group.Groups))
	}
	if n, g := Count(&exp); n != 9 || g != 4 {
		t.Errorf("Count = %d entries, %d groups", n, g)
	}
	// KDBX 4 writes times as base64 seconds since year 1: Router's expiry
	// is what the app showed, running in UTC: 11 Oct 2026 01:41:11.
	router := exp.Root.Group.Entries[0]
	if title, _ := router.Field("Title"); title != "Router" || !router.Times.ExpiryTime.Equal(time.Date(2026, 10, 11, 1, 41, 11, 0, time.UTC)) {
		t.Errorf("Router %q expires %v", title, router.Times.ExpiryTime)
	}
	// KDBX 3 writes them as ISO 8601.
	old, err := Parse(read(t, "cli-kdbx3.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if c := old.Root.Group.Entries[0].Times.CreationTime; !c.Equal(time.Date(2026, 10, 11, 0, 31, 30, 0, time.UTC)) {
		t.Errorf("KDBX 3 creation time = %v", c)
	}
}

// The database itself and the CSV export are refused, saying what to
// export instead; so is XML with encrypted values, which only a .kdbx holds.
func TestParse_Refused(t *testing.T) {
	for name, want := range map[string]string{
		"app.kdbx": "Database > Export > XML File",
		"app.csv":  "KeePassXC's CSV export",
	} {
		b := read(t, name)
		if !IsExport(b) {
			t.Errorf("%s isn't recognised", name)
		}
		if _, err := Parse(b); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	enc := strings.Replace(string(read(t, "app-kdbx4.xml")), `ProtectInMemory="True">gh-pass-2`, `Protected="True">c2VjcmV0`, 1)
	if _, err := Parse([]byte(enc)); err == nil || !strings.Contains(err.Error(), "encrypted values") {
		t.Errorf("encrypted values: %v", err)
	}
	if IsExport([]byte(`{"items":[]}`)) {
		t.Error("JSON taken for a KeePass export")
	}
	if _, err := Parse([]byte(`<?xml version="1.0"?><Other/>`)); err == nil {
		t.Error("other XML read")
	}
}
