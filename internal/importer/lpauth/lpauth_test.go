package lpauth

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// export is shaped as a real export is (its fields, top and per account,
// as LastPass Authenticator 2026 writes them), with made-up keys.
const export = `{
  "localDeviceId": null,
  "deviceName": "Test phone",
  "version": 1,
  "folders": [
    {"id": 1, "name": "Favorites", "isOpened": true},
    {"id": 0, "name": "Other Accounts", "isOpened": true},
    {"id": 2, "name": "Work / AWS", "isOpened": false}
  ],
  "accounts": [
    {"accountID": "", "lmiUserId": "", "issuerName": "GitHub", "originalIssuerName": "GitHub", "userName": "alice", "originalUserName": "alice",
     "secret": "JBSWY3DPEHPK3PXP", "algorithm": "SHA1", "digits": 6, "timeStep": 30, "creationTimestamp": 1715971083,
     "isFavorite": false, "folderData": {"folderId": 0, "position": 0}},
    {"accountID": "", "lmiUserId": "", "issuerName": "My Bank", "originalIssuerName": "bank.example", "userName": " alice@example.com", "originalUserName": "alice@example.com",
     "secret": "jbsw y3dp ehpk 3pxq", "algorithm": "SHA512", "digits": 8, "timeStep": 60, "creationTimestamp": 0,
     "isFavorite": true, "folderData": {"folderId": 2, "position": 1}},
    {"accountID": "", "lmiUserId": "", "issuerName": "", "originalIssuerName": "", "userName": "ClassLink", "originalUserName": "ClassLink",
     "secret": "JBSWY3DPEHPK3PXR", "algorithm": "SHA1", "digits": 6, "timeStep": 30, "creationTimestamp": 1715971100,
     "isFavorite": false, "folderData": {"folderId": 1, "position": 2}},
    {"accountID": "", "lmiUserId": "", "issuerName": "Acme/Corp", "originalIssuerName": "Acme/Corp", "userName": "", "originalUserName": "",
     "secret": "JBSWY3DPEHPK3PXS", "algorithm": "SHA1", "digits": 6, "timeStep": 30, "creationTimestamp": 1715971100,
     "isFavorite": false, "folderData": null},
    {"accountID": "", "lmiUserId": "", "issuerName": "GitHub", "originalIssuerName": "GitHub", "userName": "alice", "originalUserName": "alice",
     "secret": "JBSWY3DPEHPK3PXP", "algorithm": "SHA1", "digits": 6, "timeStep": 30, "creationTimestamp": 1715971083,
     "isFavorite": false, "folderData": {"folderId": 0, "position": 4}},
    {"accountID": "", "lmiUserId": "", "issuerName": "GitHub", "originalIssuerName": "GitHub", "userName": "alice", "originalUserName": "alice",
     "secret": "JBSWY3DPEHPK3PXT", "algorithm": "SHA1", "digits": 6, "timeStep": 30, "creationTimestamp": 1715971083,
     "isFavorite": false, "folderData": {"folderId": 0, "position": 5}},
    {"accountID": "", "lmiUserId": "", "issuerName": "Old", "userName": "x", "secret": "JBSWY3DPEHPK3PXP", "algorithm": "MD5", "digits": 6, "timeStep": 30},
    {"accountID": "", "lmiUserId": "", "issuerName": "Long", "userName": "x", "secret": "JBSWY3DPEHPK3PXP", "algorithm": "SHA1", "digits": 10, "timeStep": 30},
    {"accountID": "", "lmiUserId": "", "issuerName": "Broken", "userName": "x", "secret": "not base32!", "algorithm": "SHA1", "digits": 6, "timeStep": 30},
    {"accountID": "", "lmiUserId": "", "issuerName": " ", "userName": "", "secret": "JBSWY3DPEHPK3PXP", "algorithm": "SHA1", "digits": 6, "timeStep": 30},
    {"issuerName": "", "originalIssuerName": "Okta", "userName": "", "originalUserName": "bob", "secret": "JBSWY3DPEHPK3PXU",
     "algorithm": "SHA1", "digits": 6, "timeStep": 30, "folderData": {"folderId": "2", "position": 9}},
    {"issuerName": "GitHub", "userName": "alice", "secret": "jbsw y3dp ehpk 3pxp", "algorithm": "SHA1", "digits": 6, "timeStep": 30},
    {"issuerName": "Weird", "userName": "x", "secret": "JBSWY3DPEHPK3PXV", "algorithm": "SHA1", "digits": 6, "timeStep": 30, "folderData": {"folderId": "two"}}
  ]
}`

func TestEntries(t *testing.T) {
	exp, err := Parse([]byte(export))
	if err != nil {
		t.Fatal(err)
	}
	got := Entries(&exp)
	if len(got) != len(exp.Accounts) {
		t.Fatalf("%d entries for %d accounts", len(got), len(exp.Accounts))
	}
	type want struct {
		key     string
		skip    string // a part of the reason; "" for none
		secret  string
		folder  string
		tags    []string
		changes []string // each in the entry's changes
		params  totp.Params
		created int64
	}
	for i, w := range []want{
		{key: "totp/GitHub/alice", secret: "JBSWY3DPEHPK3PXP", params: totp.Params{Issuer: "GitHub"}, created: 1715971083},
		// Named as the app shows it, renamed; the username trimmed; the
		// key normalized; a folder of the user's own; a favorite.
		{key: "totp/My Bank/alice@example.com", secret: "JBSWY3DPEHPK3PXQ", folder: "Work-AWS", tags: []string{"favorite"},
			params:  totp.Params{Issuer: "My Bank", Algorithm: "SHA512", Digits: 8, Period: 60},
			changes: []string{`folder "Work / AWS" is "Work-AWS" in sesh`}},
		// No issuer: named by the account; the app's Favorites folder isn't one.
		{key: "totp/ClassLink", secret: "JBSWY3DPEHPK3PXR", params: totp.Params{}, created: 1715971100},
		// A / in a name becomes -.
		{key: "totp/Acme-Corp", secret: "JBSWY3DPEHPK3PXS", params: totp.Params{Issuer: "Acme/Corp"}, created: 1715971100,
			changes: []string{`named "Acme-Corp" in sesh`}},
		{skip: "the same account twice"},
		// One name, another key: numbered.
		{key: "totp/GitHub (2)/alice", secret: "JBSWY3DPEHPK3PXT", params: totp.Params{Issuer: "GitHub"}, created: 1715971083},
		{skip: "uses MD5"},
		{skip: "makes 10-digit codes"},
		{skip: "the key isn't a valid base32 key"},
		{skip: "has no name"},
		// Empty names fall back to those the account was added with; a
		// folder id in a string, as Bitwarden's Android model has it.
		{key: "totp/Okta/bob", secret: "JBSWY3DPEHPK3PXU", folder: "Work-AWS", params: totp.Params{Issuer: "Okta"}},
		// The same key written another way is the same account.
		{skip: "the same account twice"},
		// A folder id that isn't one costs the folder, not the import.
		{key: "totp/Weird/x", secret: "JBSWY3DPEHPK3PXV", params: totp.Params{Issuer: "Weird"}},
	} {
		e := got[i]
		if w.skip != "" {
			if !strings.Contains(e.Skip, w.skip) {
				t.Errorf("account %d: skip %q, want %q", i, e.Skip, w.skip)
			}
			continue
		}
		if e.Skip != "" || e.Key.String() != w.key || string(e.Secret) != w.secret || e.Folder != w.folder || !slices.Equal(e.Tags, w.tags) {
			t.Errorf("account %d: %s %q folder %q tags %q skip %q; want %s %q folder %q tags %q", i, e.Key, e.Secret, e.Folder, e.Tags, e.Skip, w.key, w.secret, w.folder, w.tags)
		}
		for _, c := range w.changes {
			if !slices.Contains(e.Changes, c) {
				t.Errorf("account %d: changes %q lack %q", i, e.Changes, c)
			}
		}
		if e.Settings.TOTP != w.params {
			t.Errorf("account %d: params %+v, want %+v", i, e.Settings.TOTP, w.params)
		}
		if wantCreated := time.Unix(w.created, 0); w.created != 0 && !e.Created.Equal(wantCreated) || w.created == 0 && !e.Created.IsZero() {
			t.Errorf("account %d: created %v", i, e.Created)
		}
		if e.Key.Kind != vault.KindTOTP {
			t.Errorf("account %d: kind %s", i, e.Key.Kind)
		}
	}
}

// IsExport knows the export, and not another app's JSON.
func TestIsExport(t *testing.T) {
	if !IsExport([]byte(export)) {
		t.Error("the export wasn't recognized")
	}
	for _, other := range []string{
		// Bitwarden's JSON, with the words in a note.
		`{"encrypted": false, "items": [{"type": 2, "notes": "\"accounts\": [{\"timeStep\": 30}]", "login": {"totp": "x"}}]}`,
		`{"accounts": "not a list", "timeStep": 30}`,
		`{"accounts": [], "settings": {"timeStep": 30}}`,
		`{"accounts": [{"name": "a"}], "settings": {"timeStep": 30}}`,
		`otpauth-migration://offline?data=abc`,
		``,
	} {
		if IsExport([]byte(other)) {
			t.Errorf("IsExport(%q) = true", other)
		}
	}
	if _, err := Parse([]byte(`{"version": 1}`)); err == nil || !strings.Contains(err.Error(), "no accounts list") {
		t.Errorf("Parse with no accounts: %v", err)
	}
}
