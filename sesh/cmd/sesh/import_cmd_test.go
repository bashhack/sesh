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
	"strings"
	"testing"

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
	if !strings.Contains(stderr, "The export has 3 codes, and code 2 of them wasn't given") {
		t.Errorf("summary:\n%s", stderr)
	}
	for args, wantSub := range map[string]string{
		"--from bitwarden x.json": `sesh can't import from "bitwarden" yet`,
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
