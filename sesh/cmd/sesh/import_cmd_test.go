package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/makiuchi-d/gozxing"
	zqr "github.com/makiuchi-d/gozxing/qrcode"

	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/kdf"
	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// transferCode builds a Google Authenticator transfer code holding
// accounts (secret, name, issuer, algorithm, digits, type, as the app
// numbers them), part index of size of export id.
func transferCode(size, index, id int, accounts ...[]any) string {
	varint := func(b []byte, v uint64) []byte {
		for v >= 0x80 {
			b = append(b, byte(v)|0x80)
			v >>= 7
		}
		return append(b, byte(v))
	}
	bytesField := func(b []byte, n int, v []byte) []byte {
		b = varint(b, uint64(n<<3|2))
		b = varint(b, uint64(len(v)))
		return append(b, v...)
	}
	var payload []byte
	for _, a := range accounts {
		var acc []byte
		acc = bytesField(acc, 1, []byte(a[0].(string)))
		acc = bytesField(acc, 2, []byte(a[1].(string)))
		acc = bytesField(acc, 3, []byte(a[2].(string)))
		acc = append(acc, 4<<3, byte(a[3].(int)), 5<<3, byte(a[4].(int)), 6<<3, byte(a[5].(int)))
		payload = bytesField(payload, 1, acc)
	}
	payload = append(payload, 3<<3, byte(size), 4<<3, byte(index), 5<<3, byte(id))
	return "otpauth-migration://offline?data=" + url.QueryEscape(base64.StdEncoding.EncodeToString(payload))
}

func runImportOut(t *testing.T, stdin string, terminal bool, args ...string) (string, string, error) {
	t.Helper()
	app := agentTestApp()
	app.Stdin = strings.NewReader(stdin)
	app.StdinIsTerminal = func() bool { return terminal }
	err := runImport(app, args)
	return app.Stdout.(*bytes.Buffer).String(), app.Stderr.(*bytes.Buffer).String(), err
}

// importVault is a vault holding totp/GitHub/alice already.
func importVault(t *testing.T) *rekeyTestEnv {
	t.Helper()
	env := setupRekeyEnv(t)
	useConfigFile(t, "")
	t.Setenv("SESH_MASTER_PASSWORD", "import-password-1234")
	populatePasswordStore(t, env, map[string]string{"totp/GitHub/alice": "JBSWY3DPEHPK3PXP"})
	return env
}

// A transfer code's accounts are shown, asked about, and stored as TOTP
// entries with their settings; ones sesh can't take are listed as
// skipped, and ones already in the vault follow --on-conflict.
func TestImport_GoogleAuthenticator(t *testing.T) {
	env := importVault(t)
	code := transferCode(1, 0, 7,
		[]any{"12345678901234567890", "GitHub:alice", "GitHub", 1, 1, 2},
		[]any{"abcdefghij", "Corp:carol", "Corp", 2, 2, 2},
		[]any{"abcdefghij", "counter", "Old", 1, 1, 1},
		[]any{"klmnopqrst", "bob", "", 1, 1, 2},
	)
	_, stderr, err := runImportOut(t, "", true, "--from", "google-authenticator", code)
	if err == nil || !strings.Contains(err.Error(), "add --on-conflict skip") {
		t.Fatalf("a clash without --on-conflict: %v", err)
	}
	for _, want := range []string{
		"Found 4 accounts in 1 transfer code from Google Authenticator.",
		"To import (2):\n  totp/Corp/carol  (SHA256, 8 digits)\n  totp/bob\n",
		"Already in the vault (1):\n  totp/GitHub/alice\n",
		"Skipped (1):\n  \"Old: counter\": a counter-based (HOTP) code, which sesh doesn't make\n",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("summary missing %q:\n%s", want, stderr)
		}
	}
	out, stderr, err := runImportOut(t, "y\n", true, "--from", "google-authenticator", "--on-conflict", "skip", code)
	if err != nil || !strings.Contains(out, "✅ Imported 2 TOTP entries from Google Authenticator.") || !strings.Contains(stderr, "Import 2 entries? [y/N]: ") ||
		!strings.Contains(out, "Before removing an account from your phone, check that its code matches, as with: sesh code totp/") {
		t.Fatalf("import: %q, %q, %v", out, stderr, err)
	}
	store := openDoctorVault(t, env)
	e, err := store.Lookup(vault.Key{Kind: vault.KindTOTP, Service: "Corp", Username: "carol"})
	if err != nil || e.Settings.TOTP.Algorithm != "SHA256" || e.Settings.TOTP.Digits != 8 || e.Settings.TOTP.Issuer != "Corp" {
		t.Errorf("Corp/carol = %+v, %v", e.Settings, err)
	}
	if secret, err := store.Get(vault.Key{Kind: vault.KindTOTP, Service: "bob"}); err != nil || string(secret) != "NNWG23TPOBYXE43U" {
		t.Errorf("bob's secret = %q, %v", secret, err)
	}
	if secret, err := store.Get(vault.Key{Kind: vault.KindTOTP, Service: "GitHub", Username: "alice"}); err != nil || string(secret) != "JBSWY3DPEHPK3PXP" {
		t.Errorf("the skipped clash changed: %q, %v", secret, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	// Overwriting replaces it.
	if _, _, err := runImportOut(t, "", false, "--yes", "--on-conflict", "overwrite", code); err != nil {
		t.Fatal(err)
	}
	store = openDoctorVault(t, env)
	defer store.Close() //nolint:errcheck // test cleanup
	if secret, err := store.Get(vault.Key{Kind: vault.KindTOTP, Service: "GitHub", Username: "alice"}); err != nil || string(secret) != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" {
		t.Errorf("overwritten secret = %q, %v", secret, err)
	}
}

// --dry-run shows and imports nothing; without a terminal it needs --yes;
// "n" imports nothing.
func TestImport_Asks(t *testing.T) {
	env := importVault(t)
	code := transferCode(1, 0, 1, []any{"abcdefghij", "x:y", "x", 1, 1, 2})
	if _, stderr, err := runImportOut(t, "", false, "--dry-run", code); err != nil || !strings.Contains(stderr, "Nothing imported (--dry-run).") {
		t.Errorf("--dry-run: %q, %v", stderr, err)
	}
	if _, _, err := runImportOut(t, "", false, code); err == nil || !strings.Contains(err.Error(), "add --yes") {
		t.Errorf("no terminal: %v", err)
	}
	if _, stderr, err := runImportOut(t, "n\n", true, code); err != nil || !strings.HasSuffix(stderr, "Nothing imported.\n") {
		t.Errorf("no: %q, %v", stderr, err)
	}
	store := openDoctorVault(t, env)
	defer store.Close() //nolint:errcheck // test cleanup
	if err := store.Exists(vault.Key{Kind: vault.KindTOTP, Service: "x", Username: "y"}); err == nil {
		t.Error("an entry was imported")
	}
}

// A code of a split export is read from a screenshot, and a missing one
// is pointed out.
func TestImport_FromImagesAndSplitExports(t *testing.T) {
	importVault(t)
	dir := t.TempDir()
	shot := filepath.Join(dir, "IMG_1.png")
	writeQR(t, shot, transferCode(3, 0, 9, []any{"abcdefghij", "a:one", "a", 1, 1, 2}))
	text := filepath.Join(dir, "codes.txt")
	if err := os.WriteFile(text, []byte("# exported\n"+transferCode(3, 2, 9, []any{"klmnopqrst", "b:two", "b", 1, 1, 2})+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, stderr, err := runImportOut(t, "", false, "--yes", shot, text)
	if err != nil || !strings.Contains(out, "Imported 2 TOTP entries") {
		t.Fatalf("%q, %v", out, err)
	}
	if !strings.Contains(stderr, "The export has 3 codes, and code 2 wasn't given") {
		t.Errorf("summary:\n%s", stderr)
	}
	for args, wantSub := range map[string]string{
		"--from 1password x.1pux": `sesh can't import from "1password"`,
		"nothing.txt":             "no such file",
		text + ".none":            "no such file",
	} {
		if _, _, err := runImportOut(t, "", false, strings.Fields(args)...); err == nil || !strings.Contains(err.Error(), wantSub) {
			t.Errorf("%s: %v, want %q", args, err, wantSub)
		}
	}
	plain := filepath.Join(dir, "other.png")
	writeQR(t, plain, "https://example.com")
	if _, _, err := runImportOut(t, "", false, plain); err == nil || !strings.Contains(err.Error(), "isn't a Google Authenticator transfer code") {
		t.Errorf("another QR code: %v", err)
	}
}

// writeQR writes text as a QR code in a PNG at path.
func writeQR(t *testing.T, path, text string) {
	t.Helper()
	m, err := zqr.NewQRCodeWriter().Encode(text, gozxing.BarcodeFormat_QR_CODE, 500, 500, nil)
	if err != nil {
		t.Fatal(err)
	}
	img := image.NewGray(image.Rect(0, 0, 500, 500))
	for y := range 500 {
		for x := range 500 {
			if !m.Get(x, y) {
				img.SetGray(x, y, color.Gray{Y: 255})
			}
		}
	}
	f, err := os.Create(path) //nolint:gosec // a test file
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // written
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
}

// A secret sesh refuses is skipped before anything is stored, accounts
// sharing a name are told apart, a name differing only in case is pointed
// out, errors never repeat a code's text, and the import is logged.
func TestImport_Edges(t *testing.T) {
	env := importVault(t)
	code := transferCode(1, 0, 2,
		[]any{"12345678901234567890", "first:a", "first", 1, 1, 2},
		[]any{"short", "Short:bob", "Short", 1, 1, 2},
		[]any{"abcdefghijklmnopqrst", "dup:x", "dup", 1, 1, 2},
		[]any{"zyxwvutsrqponmlkjihg", "dup:x", "dup", 1, 1, 2},
		[]any{"abcdefghijklmnopqrst", "github:alice", "github", 1, 1, 2},
		[]any{"later-later-later!!", "later:z", "later", 1, 1, 2},
	)
	out, stderr, err := runImportOut(t, code+"\n", false, "--yes", "-")
	if err != nil || !strings.Contains(out, "Imported 4 TOTP entries") {
		t.Fatalf("%q, %q, %v", out, stderr, err)
	}
	for _, want := range []string{
		"totp/github/alice\n      you have totp/GitHub/alice",
		`"Short:bob": the secret can't be used: secret too short`,
		`"dup:x": another account here has this name`,
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("summary missing %q:\n%s", want, stderr)
		}
	}
	app := agentTestApp()
	if err := runAudit(app, []string{"--limit", "1"}); err != nil {
		t.Fatal(err)
	}
	if got := app.Stdout.(*bytes.Buffer).String(); !strings.Contains(got, "import  4 TOTP entries from Google Authenticator") {
		t.Errorf("audit:\n%s", got)
	}

	damaged := "otpauth-migration://offline?data=//8JBSW"
	for wantSub, args := range map[string][]string{
		"code 1: the transfer code is damaged":                  {damaged + " "},
		"argument 1 isn't a Google Authenticator transfer code": {"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"},
		"argument 1 looks like a transfer code":                 {"offline?data=JBSW"},
	} {
		_, _, err := runImportOut(t, "", false, args...)
		if err == nil || !strings.Contains(err.Error(), wantSub) || strings.Contains(err.Error(), "JBSW") || strings.Contains(err.Error(), "data=") {
			t.Errorf("%q: %v", wantSub, err)
		}
	}
	_ = env
}

// A dry run before there's a vault shows what it found, and makes none.
func TestImport_DryRunWithoutAVault(t *testing.T) {
	env := setupRekeyEnv(t)
	useConfigFile(t, "")
	t.Setenv("SESH_MASTER_PASSWORD", "")
	code := transferCode(1, 0, 3, []any{"12345678901234567890", "x:y", "x", 1, 1, 2})
	_, stderr, err := runImportOut(t, "", true, "--dry-run", code)
	if err != nil || !strings.Contains(stderr, "To import (1):") || !strings.Contains(stderr, "Nothing imported (--dry-run).") {
		t.Fatalf("%q, %v", stderr, err)
	}
	if _, err := os.Stat(env.dbPath); !os.IsNotExist(err) {
		t.Errorf("a vault was made: %v", err)
	}
}

// Codes typed or pasted at a terminal are refused: a terminal cuts a line
// shorter than a code.
func TestImport_StdinAtATerminal(t *testing.T) {
	importVault(t)
	if _, _, err := runImportOut(t, "", true, "-"); err == nil || !strings.Contains(err.Error(), "pbpaste | sesh import -") {
		t.Errorf("err = %v", err)
	}
}

// bitwardenFixture is a genuine Bitwarden export from the importer's
// testdata (see internal/importer/bitwarden/export_test.go).
func bitwardenFixture(name string) string {
	return filepath.Join("..", "..", "..", "internal", "importer", "bitwarden", "testdata", name)
}

// A Bitwarden export is found without --from, shown with its renamed
// folders and what changed, and stored with folders, tags, details and
// times; the password-protected one asks for its password. The vault
// already has totp/GitHub/alice.
func TestImport_Bitwarden(t *testing.T) {
	env := importVault(t)
	_, stderr, err := runImportOut(t, "", false, "--dry-run", bitwardenFixture("plain.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Found 10 items and 5 folders in the Bitwarden export.",
		"Folders, renamed to fit sesh's rules:\n",
		`"Work Accounts" is "Work-Accounts"`,
		"  Passwords, in Work-Accounts (1):\n    password/GitHub/alice\n",
		`        field "linked user" not kept`,
		"  Secure notes, in no folder (1):\n    secure_note/Me\n",
		"Old passwords, for the entries' history: up to 1 (any an entry has already aren't added again)\n",
		"Not kept:\n  items set to ask for the master password again (sesh doesn't ask): 1\n",
		"Already in the vault (1):\n  totp/GitHub/alice\n",
		`named "GitHub (2)" in sesh: an entry before it has the name`,
		`"Steam": its TOTP key: a Steam code, which sesh doesn't make`,
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("summary missing %q:\n%s", want, stderr)
		}
	}
	old := readSecret
	t.Cleanup(func() { readSecret = old })
	readSecret = func() ([]byte, error) { return []byte("export-pass-1"), nil }
	out, stderr, err := runImportOut(t, "y\n", true, "--on-conflict", "skip", bitwardenFixture("password.json"))
	if err != nil || !strings.Contains(out, "✅ Imported 11 entries from Bitwarden.\nKept 1 old password in their history") || !strings.Contains(stderr, "Password for the Bitwarden export: ") {
		t.Fatalf("%q\n%s\n%v", out, stderr, err)
	}
	if strings.Contains(out, "delete") {
		t.Errorf("a protected export got the delete warning: %q", out)
	}
	store := openDoctorVault(t, env)
	defer store.Close() //nolint:errcheck // test cleanup
	gh := vault.Key{Kind: vault.KindPassword, Service: "GitHub", Username: "alice"}
	e, err := store.Lookup(gh)
	if err != nil || e.Folder != "Work-Accounts" || e.URL != "https://github.com/login" || e.CreatedAt.Year() != 2026 {
		t.Errorf("GitHub = %+v, %v", e, err)
	}
	if old, err := store.ReadVersion(gh, 2, "test"); err != nil || string(old) != "gh-old-password-1" {
		t.Errorf("GitHub's version 2 = %q, %v", old, err)
	}
	d, err := store.Details(gh, "all")
	if err != nil || string(d.Notes) != "main account\nrecovery codes in the safe" || len(d.Fields) != 4 {
		t.Errorf("GitHub details = %+v, %v", d, err)
	}
	if secret, err := store.Get(gh); err != nil || string(secret) != "gh-new-password-2" {
		t.Errorf("GitHub password = %q, %v", secret, err)
	}
	if r, err := store.Lookup(vault.Key{Kind: vault.KindPassword, Service: "Router"}); err != nil || len(r.Tags) != 1 || r.Tags[0] != "favorite" {
		t.Errorf("Router = %+v, %v", r, err)
	}
	// Plain exports say to delete the file; account-restricted ones are refused.
	if out, _, err := runImportOut(t, "", false, "--yes", "--on-conflict", "skip", bitwardenFixture("plain.json")); err != nil || !strings.Contains(out, "holds your passwords unencrypted") {
		t.Errorf("plain: %q, %v", out, err)
	}
	if _, _, err := runImportOut(t, "", false, bitwardenFixture("account.json")); err == nil || !strings.Contains(err.Error(), "account restricted") {
		t.Errorf("account restricted: %v", err)
	}
	// The CSV export is found without --from, and read.
	if out, said, err := runImportOut(t, "", false, "--yes", "--on-conflict", "skip", bitwardenFixture("vault.csv")); err != nil || !strings.Contains(out+said, "Found 7 items and 5 folders in the Bitwarden export") {
		t.Errorf("CSV without --from: %q, %q, %v", out, said, err)
	}
	// An organization's CSV is found as Bitwarden's, and refused.
	org := filepath.Join(t.TempDir(), "org.csv")
	if err := os.WriteFile(org, []byte("collections,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runImportOut(t, "", false, org); err == nil || !strings.Contains(err.Error(), "organization's Bitwarden export") {
		t.Errorf("an organization's CSV without --from: %v", err)
	}
	if _, _, err := runImportOut(t, "", false, "--from", "bitwarden", bitwardenFixture("password.json")); err == nil || !strings.Contains(err.Error(), "run sesh import at a terminal") {
		t.Errorf("protected, no terminal: %v", err)
	}
}

// Overwriting with an import takes the secret and code settings from it,
// adds its tags to yours, and keeps your other settings, folder (when the
// import has none) and creation time.
func TestImport_BitwardenOverwrite(t *testing.T) {
	env := importVault(t)
	gh := vault.Key{Kind: vault.KindTOTP, Service: "GitHub", Username: "alice"}
	store := openDoctorVault(t, env)
	cur, err := store.Lookup(gh)
	if err != nil {
		t.Fatal(err)
	}
	cur.Settings.AWSMFADevice = "arn:aws:iam::123456789012:mfa/alice"
	cur.Tags = []string{"mine"}
	cur.CreatedAt = time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := store.Save(&cur, []byte("GEZDGNBVGY3TQOJQ")); err != nil {
		t.Fatal(err)
	}
	// The import's Router has a URL but no notes or fields: yours stay.
	router := vault.Key{Kind: vault.KindPassword, Service: "Router"}
	mine := vault.Details{URL: "http://old.example", Notes: []byte("recovery codes: 1111"), Fields: []vault.Field{{Name: "pin", Value: []byte("4321"), Secret: true}}}
	if err := store.SaveWithDetails(&vault.Entry{Key: router}, []byte("old-pw"), &mine); err != nil {
		t.Fatal(err)
	}
	// The import's GitHub login has fields: they're merged into yours by
	// name, ignoring case, the import's winning.
	ghPass := vault.Key{Kind: vault.KindPassword, Service: "GitHub", Username: "alice"}
	ghMine := vault.Details{Notes: []byte("old notes"), Fields: []vault.Field{
		{Name: "pin", Value: []byte("0000"), Secret: true},
		{Name: "2FA-Enabled", Value: []byte("no"), Secret: true},
		{Name: "team", Value: []byte("blue")},
	}}
	if err := store.SaveWithDetails(&vault.Entry{Key: ghPass}, []byte("old-pw"), &ghMine); err != nil {
		t.Fatal(err)
	}
	// One whose merged fields would be more than sesh holds is skipped.
	deploy := vault.Key{Kind: vault.KindNote, Service: "deploy key"}
	var many vault.Details
	for i := range vault.MaxFields {
		many.Fields = append(many.Fields, vault.Field{Name: fmt.Sprintf("f%d", i), Value: []byte("v")})
	}
	if err := store.SaveWithDetails(&vault.Entry{Key: deploy}, []byte("old-pw"), &many); err != nil {
		t.Fatal(err)
	}
	store.Close() //nolint:errcheck,gosec // reopened below
	_, stderr, err := runImportOut(t, "", false, "--yes", "--on-conflict", "overwrite", bitwardenFixture("plain.json"))
	if err != nil || !strings.Contains(stderr, "Already in the vault, to be replaced (3):\n") ||
		!strings.Contains(stderr, `field "2fa-enabled" replaces yours (2FA-Enabled), kept secret`) ||
		!strings.Contains(stderr, `"deploy key": merged with your entry's, its details would break sesh's rules: an entry can have at most 50 fields`) {
		t.Fatalf("%s\n%v", stderr, err)
	}
	store = openDoctorVault(t, env)
	defer store.Close() //nolint:errcheck // test cleanup
	e, err := store.Lookup(gh)
	if err != nil {
		t.Fatal(err)
	}
	if e.Settings.AWSMFADevice != "arn:aws:iam::123456789012:mfa/alice" || !e.CreatedAt.Equal(cur.CreatedAt) ||
		!slices.Contains(e.Tags, "mine") || e.Folder != "Work-Accounts" || time.Since(e.UpdatedAt) > time.Minute {
		t.Errorf("GitHub TOTP = %+v", e)
	}
	if secret, err := store.Get(gh); err != nil || string(secret) != "JBSWY3DPEHPK3PXP" || e.Settings.TOTP.Digits != 8 {
		t.Errorf("secret = %q, %v, code settings %+v: not replaced", secret, err, e.Settings.TOTP)
	}
	d, err := store.Details(ghPass, "all")
	var fields []string
	for _, f := range d.Fields {
		fields = append(fields, f.Name+"="+string(f.Value))
		if f.Name == "2fa-enabled" && !f.Secret {
			t.Error("2fa-enabled, secret in the vault, was made plain by a plain field from the import")
		}
	}
	if err != nil || string(d.Notes) != "main account\nrecovery codes in the safe" ||
		strings.Join(fields, " ") != "pin=4321 2fa-enabled=true team=blue recovery-email=alice@example.com url-2=github.com" {
		t.Errorf("GitHub fields = %q, notes %q, %v", fields, d.Notes, err)
	}
	if secret, err := store.Get(deploy); err != nil || string(secret) != "old-pw" {
		t.Errorf("deploy key = %q, %v: should be left as it was", secret, err)
	}
	d, err = store.Details(router, "all")
	if err != nil || d.URL != "192.168.1.1" || string(d.Notes) != "recovery codes: 1111" || len(d.Fields) != 1 || string(d.Fields[0].Value) != "4321" {
		t.Errorf("Router details = %+v, %v", d, err)
	}
}

// Google Authenticator's import says to delete the files the codes came from.
func TestImport_GoogleAuthenticatorDeleteReminder(t *testing.T) {
	importVault(t)
	file := filepath.Join(t.TempDir(), "codes.txt")
	code := transferCode(1, 0, 7, []any{"klmnopqrst", "bob", "", 1, 1, 2})
	if err := os.WriteFile(file, []byte(code+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, err := runImportOut(t, "", false, "--yes", file)
	if err != nil || !strings.Contains(out, "The transfer codes in "+file+" hold every secret they carry: delete them now") {
		t.Errorf("%q, %v", out, err)
	}
	if out, _, err := runImportOut(t, "", false, "--yes", "--on-conflict", "skip", code); err != nil || strings.Contains(out, "delete them") {
		t.Errorf("a code given as text: %q, %v", out, err)
	}
}

func TestDescribeParams(t *testing.T) {
	for p, want := range map[totp.Params]string{
		{}:                               "",
		{Algorithm: "SHA256", Digits: 8}: "  (SHA256, 8 digits)",
		{Period: 60}:                     "  (60 seconds)",
		{Algorithm: "SHA512", Period: 1}: "  (SHA512, 1 second)",
	} {
		if got := describeParams(p); got != want {
			t.Errorf("describeParams(%+v) = %q, want %q", p, got, want)
		}
	}
}

// keepassFixture is a genuine KeePassXC file from the importer's testdata
// (see internal/importer/keepass/export_test.go).
func keepassFixture(name string) string {
	return filepath.Join("..", "..", "..", "internal", "importer", "keepass", "testdata", name)
}

// A KeePass XML export is found without --from, shown, and stored with
// folders, tags, fields and TOTP settings; the database itself and the CSV
// export are refused.
func TestImport_KeePass(t *testing.T) {
	env := importVault(t)
	_, stderr, err := runImportOut(t, "", false, "--dry-run", keepassFixture("app-kdbx4.xml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Found 9 entries and 4 groups in the KeePass export.",
		`"Work Accounts" is "Work-Accounts" in sesh`,
		"  Passwords, in Work-Accounts (2):\n    password/GitHub/alice\n",
		"expired in KeePass on " + time.Date(2026, 10, 11, 1, 41, 11, 0, time.UTC).Local().Format("2006-01-02"),
		"password and username taken from the entry they refer to",
		`"Home/Lab" is "Home-Lab" in sesh`,
		`"Old account": in KeePass's recycle bin`,
		`"Steam": its TOTP key: a Steam code, which sesh doesn't make`,
		"Old passwords, for the entries' history: up to 1 (any an entry has already aren't added again)\n",
		"earlier versions with no other password to keep (sesh's history keeps old passwords only): 11\n",
		"attachments (add each with sesh add file): 2\n",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("summary missing %q:\n%s", want, stderr)
		}
	}
	out, _, err := runImportOut(t, "", false, "--yes", "--on-conflict", "skip", keepassFixture("app-kdbx4.xml"))
	if err != nil || !strings.Contains(out, "✅ Imported 11 entries from KeePass.\nKept 1 old password in their history") || !strings.Contains(out, "holds your passwords unencrypted") {
		t.Fatalf("%q, %v", out, err)
	}
	store := openDoctorVault(t, env)
	defer store.Close() //nolint:errcheck // test cleanup
	gh := vault.Key{Kind: vault.KindPassword, Service: "GitHub", Username: "alice"}
	e, err := store.Lookup(gh)
	if err != nil || e.Folder != "Work-Accounts" || strings.Join(e.Tags, ",") != "code,work" || e.URL != "https://github.com/login" {
		t.Errorf("GitHub = %+v, %v", e, err)
	}
	if old, err := store.ReadVersion(gh, 2, "test"); err != nil || string(old) != "gh-pass-1" {
		t.Errorf("GitHub's version 2 = %q, %v", old, err)
	}
	d, err := store.Details(gh, "all")
	if err != nil || len(d.Fields) != 2 || d.Fields[0].Name != "pin" || !d.Fields[0].Secret || string(d.Fields[0].Value) != "4321" {
		t.Errorf("GitHub details = %+v, %v", d, err)
	}
	if secret, err := store.Get(vault.Key{Kind: vault.KindPassword, Service: "GitHub - Clone", Username: "alice"}); err != nil || string(secret) != "gh-pass-2" {
		t.Errorf("clone's password = %q, %v", secret, err)
	}
	bank, err := store.Lookup(vault.Key{Kind: vault.KindTOTP, Service: "Bank", Username: "bob"})
	if err != nil || bank.Folder != "Work-Accounts/Banking" {
		t.Errorf("Bank TOTP = %+v, %v", bank, err)
	}
	for name, want := range map[string]string{
		"app.kdbx": "Database > Export > XML File",
		"app.csv":  "KeePassXC's CSV export",
	} {
		if _, _, err := runImportOut(t, "", false, keepassFixture(name)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// browserFixture is a genuine browser export from the importer's testdata
// (see internal/importer/browser/browser_test.go).
func browserFixture(name string) string {
	return filepath.Join("..", "..", "..", "internal", "importer", "browser", "testdata", name)
}

// Chrome's and Firefox's exports are found without --from and stored with
// their URLs and notes; giving the wrong browser says which it is.
func TestImport_Browsers(t *testing.T) {
	env := importVault(t)
	out, stderr, err := runImportOut(t, "", false, "--yes", browserFixture("chromium.csv"))
	if err != nil || !strings.Contains(stderr, "Found 5 entries in the Chrome export.") || !strings.Contains(out, "✅ Imported 5 entries from Chrome.") ||
		!strings.Contains(out, "holds your passwords unencrypted") {
		t.Fatalf("Chrome: %q\n%s\n%v", out, stderr, err)
	}
	_, stderr, err = runImportOut(t, "", false, "--dry-run", browserFixture("firefox.csv"))
	if err != nil || !strings.Contains(stderr, "Found 5 entries in the Firefox export.") || !strings.Contains(stderr, "Already in the vault (5):") {
		t.Errorf("Firefox: %s\n%v", stderr, err)
	}
	if _, _, err := runImportOut(t, "", false, "--from", "chrome", browserFixture("firefox.csv")); err == nil || !strings.Contains(err.Error(), "this export is from Firefox: use --from firefox") {
		t.Errorf("wrong --from: %v", err)
	}
	store := openDoctorVault(t, env)
	defer store.Close() //nolint:errcheck // test cleanup
	gh := vault.Key{Kind: vault.KindPassword, Service: "github.com", Username: "alice"}
	d, err := store.Details(gh, "all")
	if err != nil || d.URL != "https://github.com/" || string(d.Notes) != "main account\nrecovery codes in the safe" {
		t.Errorf("github.com/alice details = %+v, %v", d, err)
	}
	if secret, err := store.Get(vault.Key{Kind: vault.KindPassword, Service: "github.com", Username: "bob"}); err != nil || string(secret) != `gh,"bob"pw` {
		t.Errorf("bob = %q, %v", secret, err)
	}
}

// Firefox's times come across: made, and the password last changed.
func TestImport_FirefoxTimes(t *testing.T) {
	env := importVault(t)
	if _, _, err := runImportOut(t, "", false, "--yes", "--from", "firefox", browserFixture("firefox.csv")); err != nil {
		t.Fatal(err)
	}
	store := openDoctorVault(t, env)
	defer store.Close() //nolint:errcheck // test cleanup
	e, err := store.Lookup(vault.Key{Kind: vault.KindPassword, Service: "github.com", Username: "alice"})
	if err != nil || !e.CreatedAt.Equal(time.UnixMilli(1791686628223)) || !e.UpdatedAt.Equal(time.UnixMilli(1791686730455)) {
		t.Errorf("github.com/alice = %+v, %v", e, err)
	}
}

// The Passwords app's export is found without --from; its entry is stored
// by title, with its verification code as a TOTP entry beside it.
func TestImport_ApplePasswords(t *testing.T) {
	env := importVault(t)
	out, stderr, err := runImportOut(t, "", false, "--yes", browserFixture("apple-passwords.csv"))
	if err != nil || !strings.Contains(stderr, "Found 1 entry in the Apple Passwords export.") || !strings.Contains(out, "✅ Imported 2 entries from Apple Passwords.") {
		t.Fatalf("%q\n%s\n%v", out, stderr, err)
	}
	store := openDoctorVault(t, env)
	defer store.Close() //nolint:errcheck // test cleanup
	d, err := store.Details(vault.Key{Kind: vault.KindPassword, Service: "GitHub Test", Username: "alice"}, "all")
	if err != nil || d.URL != "https://github.com/" || string(d.Notes) != "main account\nrecovery codes in the safe" {
		t.Errorf("password entry details = %+v, %v", d, err)
	}
	if secret, err := store.Get(vault.Key{Kind: vault.KindTOTP, Service: "GitHub Test", Username: "alice"}); err != nil || string(secret) != "JBSWY3DPEHPK3PXP" {
		t.Errorf("TOTP entry = %q, %v", secret, err)
	}
}

// A Passwords app entry whose verification code sesh can't make still
// imports its password, the code listed as skipped; --from chrome on its
// export says which it is.
func TestImport_ApplePasswordsRefusedCode(t *testing.T) {
	importVault(t)
	file := filepath.Join(t.TempDir(), "Passwords.csv")
	csv := "Title,URL,Username,Password,Notes,OTPAuth\nCounter,https://c.example/,u,pw,,otpauth://hotp?secret=GEZDGNBVGY3TQOJQ&counter=1\n"
	if err := os.WriteFile(file, []byte(csv), 0o600); err != nil {
		t.Fatal(err)
	}
	out, stderr, err := runImportOut(t, "", false, "--yes", file)
	if err != nil || !strings.Contains(out, "✅ Imported 1 entry from Apple Passwords.") ||
		!strings.Contains(stderr, `"Counter": its verification code: a counter-based (HOTP) code, which sesh doesn't make`) {
		t.Errorf("%q\n%s\n%v", out, stderr, err)
	}
	if _, _, err := runImportOut(t, "", false, "--from", "chrome", file); err == nil || !strings.Contains(err.Error(), "this export is from Apple Passwords: use --from apple-passwords") {
		t.Errorf("wrong --from: %v", err)
	}
}

// Importing again over the same entries adds no old password twice, and
// says what was kept; one with no room under history.keep is said; with
// history.keep 0 none are kept, and the summary says so.
func TestImport_HistoryAgainAndKeepNone(t *testing.T) {
	env := importVault(t)
	gh := vault.Key{Kind: vault.KindPassword, Service: "GitHub", Username: "alice"}
	for i, want := range []string{"Kept 1 old password in their history", ""} {
		out, _, err := runImportOut(t, "", false, "--yes", "--on-conflict", "overwrite", bitwardenFixture("plain.json"))
		if err != nil || (want != "" && !strings.Contains(out, want)) || (want == "" && strings.Contains(out, "old password")) {
			t.Fatalf("import %d: %v\n%s", i+1, err, out)
		}
	}
	store := openDoctorVault(t, env)
	if vs, err := store.History(gh); err != nil || len(vs) != 1 {
		t.Errorf("after importing twice, history = %v, %v; want 1 version", vs, err)
	}
	store.Close() //nolint:errcheck // test cleanup

	// Its password changed in sesh: the one replaced fills history.keep 1.
	putSecrets(t, gh, "mine")
	t.Setenv(config.EnvHistoryKeep, "1")
	if _, err := runFiling(t, runHistory, "password/GitHub/alice", "--forget", "2"); err != nil {
		t.Fatal(err)
	}
	putSecrets(t, gh, "mine-2")
	out, _, err := runImportOut(t, "", false, "--yes", "--on-conflict", "overwrite", bitwardenFixture("plain.json"))
	if err != nil || !strings.Contains(out, "Not kept: 1 old password past history.keep (1), the oldest of those imported.") || strings.Contains(out, "Kept ") {
		t.Errorf("no room: %v\n%s", err, out)
	}

	t.Setenv(config.EnvHistoryKeep, "0")
	_, stderr, err := runImportOut(t, "", false, "--dry-run", "--on-conflict", "overwrite", bitwardenFixture("plain.json"))
	if err != nil || !strings.Contains(stderr, "old passwords (history.keep is 0): 1\n") || strings.Contains(stderr, "for the entries' history") {
		t.Errorf("history.keep 0: %v\n%s", err, stderr)
	}
}

// sesh's own encrypted export is told from other files, previewed with its clashes, imported after its password and
// a yes, its details kept; a wrong password, a plain export, and nobody to type the password are refused.
func TestImport_Sesh(t *testing.T) {
	env := importVault(t)
	src := vault.NewMemStore()
	m := password.NewManager(src)
	for _, k := range []vault.Key{{Kind: vault.KindPassword, Service: "github", Username: "alice"}, {Kind: vault.KindTOTP, Service: "GitHub", Username: "alice"}} {
		secret := "s3cret"
		if k.Kind == vault.KindTOTP {
			secret = "JBSWY3DPEHPK3PXP"
		}
		if err := m.StorePassword(k.Service, k.Username, []byte(secret), k.Kind, vault.Filing{Folder: "Work", FolderSet: true}); err != nil {
			t.Fatal(err)
		}
	}
	gh := vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}
	if err := src.SetDetails(gh, &vault.Details{URL: "https://github.com", Notes: []byte("n")}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := m.ExportEncrypted(&buf, &password.ExportOptions{KDF: kdf.Minimum()}, []byte("export-pass-1234")); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "backup.enc")
	if err := os.WriteFile(file, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	old := readSecret
	t.Cleanup(func() { readSecret = old })
	typed := "export-pass-1234"
	readSecret = func() ([]byte, error) { return []byte(typed), nil }

	_, stderr, err := runImportOut(t, "", true, "--dry-run", file)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Password for the sesh export: ", "Found 2 entries in the sesh export.", "password/github/alice", "Already in the vault (1):\n  totp/GitHub/alice\n"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("missing %q:\n%s", want, stderr)
		}
	}
	out, stderr, err := runImportOut(t, "y\n", true, "--from", "sesh", "--on-conflict", "skip", file)
	if err != nil || !strings.Contains(out, "✅ Imported 1 entry from a sesh export.") {
		t.Fatalf("%q\n%s\n%v", out, stderr, err)
	}
	store := openDoctorVault(t, env)
	e, err := store.Lookup(gh)
	store.Close() //nolint:errcheck,gosec // test cleanup
	if err != nil || e.Folder != "Work" || e.URL != "https://github.com" {
		t.Errorf("imported: folder %q url %q, %v", e.Folder, e.URL, err)
	}

	typed = "wrong-pass-1234"
	if _, _, err := runImportOut(t, "", true, "--from", "sesh", file); err == nil || !strings.Contains(err.Error(), "wrong password") {
		t.Errorf("a wrong password: %v", err)
	}
	plain := filepath.Join(t.TempDir(), "plain.json")
	if err := os.WriteFile(plain, []byte(`[{"service":"x","type":"password","secret":"y"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	// A plain export is previewed too, and its file said to be deleted.
	if out, errOut, err := runImportOut(t, "", true, "--from", "sesh", plain); err != nil || !strings.Contains(out+errOut, "Found 1 entry in the sesh export.") {
		t.Errorf("a plain export: %v\n%s%s", err, out, errOut)
	}
	if _, _, err := runImportOut(t, "", false, "--from", "sesh", file); err == nil || err.Error() != "this sesh export is protected by a password: run sesh import at a terminal to type it" {
		t.Errorf("no terminal: %v", err)
	}
	if _, _, err := runImportOut(t, "", true, "--from", "sesh", file, file); err == nil || !strings.Contains(err.Error(), "give one sesh export") {
		t.Errorf("two files: %v", err)
	}
}

// Replacing an AWS entry from sesh's export takes the export's device with its key; a new entry keeps its code
// settings, tags, notes, fields and times. A file whose settings sesh refuses isn't asked a password for, and a plain
// export is sent to --action import, with or without --from.
func TestImport_SeshOverwriteAndRefusals(t *testing.T) {
	env := importVault(t)
	aws, aws2 := vault.AWSKey("prof"), vault.AWSKey("prof2")
	store := openDoctorVault(t, env)
	for _, k := range []vault.Key{aws, aws2} {
		if err := store.SaveWithDetails(&vault.Entry{Key: k, Settings: vault.Settings{AWSMFADevice: "arn:aws:iam::1:mfa/OLD"}}, []byte("JBSWY3DPEHPK3PXP"), &vault.Details{}); err != nil {
			t.Fatal(err)
		}
	}
	store.Close() //nolint:errcheck,gosec // test cleanup

	src := vault.NewMemStore()
	made := time.Date(2025, 3, 4, 5, 6, 7, 0, time.UTC)
	fresh := vault.Key{Kind: vault.KindTOTP, Service: "new", Username: "x"}
	for _, e := range []struct {
		k      vault.Key
		secret string
		s      vault.Settings
	}{
		{aws, "GEZDGNBVGY3TQOJQ", vault.Settings{AWSMFADevice: "arn:aws:iam::1:mfa/NEW"}},
		{aws2, "GEZDGNBVGY3TQOJQ", vault.Settings{}}, // no device: sesh asks AWS for it
		{fresh, "JBSWY3DPEHPK3PXP", vault.Settings{TOTP: totp.Params{Algorithm: "SHA256", Digits: 8, Period: 60}}},
	} {
		if err := src.Save(&vault.Entry{Key: e.k, Settings: e.s, Tags: []string{"phone"}, CreatedAt: made, UpdatedAt: made}, []byte(e.secret)); err != nil {
			t.Fatal(err)
		}
	}
	if err := src.SetDetails(fresh, &vault.Details{Notes: []byte("backup codes in the safe"), Fields: []vault.Field{{Name: "pin", Value: []byte("1234"), Secret: true}}}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := password.NewManager(src).ExportEncrypted(&buf, &password.ExportOptions{KDF: kdf.Minimum()}, []byte("export-pass-1234")); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "backup.enc")
	if err := os.WriteFile(file, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	old := readSecret
	t.Cleanup(func() { readSecret = old })
	asked := 0
	readSecret = func() ([]byte, error) { asked++; return []byte("export-pass-1234"), nil }
	// The preview says each device that changes.
	if _, stderr, err := runImportOut(t, "", true, "--dry-run", "--on-conflict", "overwrite", file); err != nil ||
		!strings.Contains(stderr, "its MFA device becomes arn:aws:iam::1:mfa/NEW") || !strings.Contains(stderr, "its MFA device (arn:aws:iam::1:mfa/OLD) is taken out") {
		t.Errorf("the preview: %v\n%s", err, stderr)
	}
	// Its TOTP entries aren't from a phone: no word of checking one before removing it there.
	if out, stderr, err := runImportOut(t, "", true, "--yes", "--on-conflict", "overwrite", file); err != nil || strings.Contains(out, "your phone") {
		t.Fatalf("%q\n%s\n%v", out, stderr, err)
	}
	store = openDoctorVault(t, env)
	defer store.Close() //nolint:errcheck // test cleanup
	a, err := store.Lookup(aws)
	secret, gerr := store.Get(aws)
	if err != nil || gerr != nil || a.Settings.AWSMFADevice != "arn:aws:iam::1:mfa/NEW" || string(secret) != "GEZDGNBVGY3TQOJQ" {
		t.Errorf("the AWS entry: device %q, secret %q, %v %v", a.Settings.AWSMFADevice, secret, err, gerr)
	}
	if a2, err := store.Lookup(aws2); err != nil || a2.Settings.AWSMFADevice != "" {
		t.Errorf("the AWS entry exported without a device: %q, %v", a2.Settings.AWSMFADevice, err)
	}
	n, err := store.Lookup(fresh)
	if err != nil || n.Settings.TOTP != (totp.Params{Algorithm: "SHA256", Digits: 8, Period: 60}) || !slices.Equal(n.Tags, []string{"phone"}) ||
		!n.CreatedAt.Equal(made) || !n.UpdatedAt.Equal(made) {
		t.Errorf("the new entry: %+v, %v", n, err)
	}
	if d, err := store.Details(fresh, "test"); err != nil || len(d.Fields) != 1 || !d.Fields[0].Secret || string(d.Notes) != "backup codes in the safe" {
		t.Errorf("its details: %+v, %v", d, err)
	}

	bad := filepath.Join(t.TempDir(), "bad.enc")
	if err := os.WriteFile(bad, []byte(`{"version":1,"algorithm":"argon2id","salt":"AAAAAAAAAAAAAAAAAAAAAA==","ciphertext":"AA==","params":{"time":3,"memory":4294967295,"threads":4,"key_len":32}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	asked = 0
	if _, _, err := runImportOut(t, "", true, bad); err == nil || !strings.Contains(err.Error(), "memory setting out of range") || asked != 0 {
		t.Errorf("settings refused: %v, asked %d", err, asked)
	}
	plain := filepath.Join(t.TempDir(), "plain.json")
	if err := os.WriteFile(plain, []byte(`[{"service":"x","type":"password","secret":"y"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, errOut, err := runImportOut(t, "", true, plain); err != nil || !strings.Contains(out+errOut, "Found 1 entry in the sesh export.") {
		t.Errorf("a plain export without --from: %v\n%s%s", err, out, errOut)
	}
}

// Without a terminal, a protected Bitwarden export says how to type its password.
func TestImport_BitwardenNoTerminal(t *testing.T) {
	importVault(t)
	if _, _, err := runImportOut(t, "", false, "--from", "bitwarden", bitwardenFixture("password.json")); err == nil ||
		err.Error() != "this Bitwarden export is protected by a password: run sesh import at a terminal to type it" {
		t.Errorf("%v", err)
	}
}

// LastPass Authenticator's export is found without --from, and its
// accounts imported as TOTP entries; one sesh has already is a clash.
func TestImport_LastPassAuthenticator(t *testing.T) {
	env := importVault(t)
	file := filepath.Join(t.TempDir(), "accounts.json")
	if err := os.WriteFile(file, []byte(`{"localDeviceId": null, "deviceName": "phone", "version": 1,
  "folders": [{"id": 0, "name": "Other Accounts", "isOpened": true}],
  "accounts": [
    {"issuerName": "GitHub", "originalIssuerName": "GitHub", "userName": "alice", "originalUserName": "alice", "secret": "JBSWY3DPEHPK3PXP",
     "algorithm": "SHA1", "digits": 6, "timeStep": 30, "creationTimestamp": 1715971083, "isFavorite": false, "folderData": {"folderId": 0, "position": 0}},
    {"issuerName": "Amazon Web Services", "originalIssuerName": "Amazon Web Services", "userName": "alice@123456789012", "originalUserName": "alice@123456789012",
     "secret": "JBSWY3DPEHPK3PXQ", "algorithm": "SHA1", "digits": 6, "timeStep": 30, "creationTimestamp": 1715971100, "isFavorite": true, "folderData": {"folderId": 0, "position": 1}}
  ]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, stderr, err := runImportOut(t, "", false, "--dry-run", file)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Found 2 accounts in the LastPass Authenticator export.", "totp/Amazon Web Services/alice@123456789012", "totp/GitHub/alice"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("summary missing %q:\n%s", want, stderr)
		}
	}
	out, _, err := runImportOut(t, "", false, "--from", "lastpass-authenticator", "--yes", "--on-conflict", "skip", file)
	if err != nil || !strings.Contains(out, "✅ Imported 1 TOTP entry from LastPass Authenticator.") || !strings.Contains(out, "delete "+file+" now") || !strings.Contains(out, "Before removing an account from your phone, check that its code matches") {
		t.Fatalf("%q, %v", out, err)
	}
	store := openDoctorVault(t, env)
	defer store.Close() //nolint:errcheck // test cleanup
	k := vault.Key{Kind: vault.KindTOTP, Service: "Amazon Web Services", Username: "alice@123456789012"}
	if e, err := store.Lookup(k); err != nil || !slices.Equal(e.Tags, []string{"favorite"}) || e.CreatedAt.Unix() != 1715971100 {
		t.Errorf("imported: %+v, %v", e, err)
	}
	if secret, err := store.Get(k); err != nil || string(secret) != "JBSWY3DPEHPK3PXQ" {
		t.Errorf("secret %q, %v", secret, err)
	}
}

// Each source's file is told apart from the others', LastPass
// Authenticator's from JSON that only mentions its words.
func TestDetectSource_LastPassAuthenticator(t *testing.T) {
	dir := t.TempDir()
	for name, tc := range map[string]struct{ body, want string }{
		"lastpass":   {`{"version": 1, "accounts": [{"issuerName": "a", "secret": "JBSWY3DPEHPK3PXP", "timeStep": 30}]}`, "lastpass-authenticator"},
		"bitwarden":  {`{"encrypted": false, "folders": [], "items": [{"id": "1", "type": 1, "name": "x", "notes": "accounts timeStep", "login": {"username": "u", "password": "p", "totp": null}}]}`, "bitwarden"},
		"sesh plain": {`[{"id": "totp/a", "kind": "totp", "service": "a", "secret": "x", "notes": "\"accounts\" \"timeStep\""}]`, ""},
	} {
		file := filepath.Join(dir, name+".json")
		if err := os.WriteFile(file, []byte(tc.body), 0o600); err != nil {
			t.Fatal(err)
		}
		got := detectSource([]string{file})
		if tc.want != "" && got != tc.want || tc.want == "" && got == "lastpass-authenticator" {
			t.Errorf("%s: detectSource() = %q, want %q", name, got, tc.want)
		}
	}
}
