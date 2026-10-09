package main

import (
	"bytes"
	"encoding/base64"
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
	if err != nil || !strings.Contains(out, "✅ Imported 2 TOTP entries from Google Authenticator.") || !strings.Contains(stderr, "Import 2 entries? [y/N]: ") {
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
		"put --dry-run before the files":                        {"a.png", "--dry-run"},
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
		"Not kept:\n  items set to ask for the master password again (sesh doesn't ask): 1\n  old passwords (sesh keeps no history yet): 1\n",
		"Already in the vault (1):\n  totp/GitHub/alice\n",
		`named "GitHub (2)" in sesh: another item has its name`,
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
	if err != nil || !strings.Contains(out, "✅ Imported 11 entries from Bitwarden.") || !strings.Contains(stderr, "Password for the Bitwarden export: ") {
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
	store.Close() //nolint:errcheck,gosec // reopened below
	_, stderr, err := runImportOut(t, "", false, "--yes", "--on-conflict", "overwrite", bitwardenFixture("plain.json"))
	if err != nil || !strings.Contains(stderr, "Already in the vault, to be replaced (1):\n  totp/GitHub/alice\n") {
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
