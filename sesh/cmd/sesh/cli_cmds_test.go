package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/clipboard"
	"github.com/bashhack/sesh/internal/qrcode"
)

// cliApp is an app reading stdin, at a terminal when terminal, whose
// copies are recorded.
func cliApp(stdin string, terminal bool) (*App, *[]string) {
	app := agentTestApp()
	app.Stdin = strings.NewReader(stdin)
	app.StdinIsTerminal = func() bool { return terminal }
	var copied []string
	app.ClipboardCopy = func(s string) error { copied = append(copied, s); return nil }
	return app, &copied
}

// runCLI runs a command on app, returning what it printed to stdout and
// stderr.
func runCLI(app *App, run func(*App, []string) error, args ...string) (string, string, error) {
	err := run(app, args)
	return app.Stdout.(*bytes.Buffer).String(), app.Stderr.(*bytes.Buffer).String(), err
}

// typedSecrets makes readSecret return secrets in turn, as typed at a terminal.
func typedSecrets(t *testing.T, secrets ...string) {
	t.Helper()
	old := readSecret
	t.Cleanup(func() { readSecret = old })
	readSecret = func() ([]byte, error) {
		if len(secrets) == 0 {
			return nil, errors.New("nothing more typed")
		}
		s := secrets[0]
		secrets = secrets[1:]
		return []byte(s), nil
	}
}

// Words name one entry as the search finds it; several matches are listed by ID without a terminal, and asked about
// at one, where Enter cancels and a number out of range is asked again. An ID, spaces and all, matches only itself.
func TestResolveEntry(t *testing.T) {
	filingVault(t)
	mustRun(t, runFolder, "move", "work", "password/github/alice")
	app, _ := cliApp("", false)
	if out, _, err := runCLI(app, runGet, "gitl"); err != nil || out != "b\n" {
		t.Errorf("one match: %q, %v", out, err)
	}
	app, _ = cliApp("", false)
	if _, _, err := runCLI(app, runGet, "git"); err == nil || !strings.Contains(err.Error(), "\"git\" matches 2 entries; name one by its ID:\n  password/") {
		t.Errorf("several, no terminal: %v", err)
	}
	app, _ = cliApp("9\n2\n", true)
	out, errOut, err := runCLI(app, runGet, "git")
	if err != nil || !strings.Contains(errOut, "github (alice)  password  work") || !strings.Contains(errOut, "Type a number from 1 to 2.") || (out != "a\n" && out != "b\n") {
		t.Errorf("several, chosen: %q, %q, %v", out, errOut, err)
	}
	app, _ = cliApp("\n", true)
	if _, _, err := runCLI(app, runGet, "git"); !errors.Is(err, errNoChoice) {
		t.Errorf("cancelled: %v", err)
	}
	for _, args := range [][]string{{"password/My Bank"}, {"password/My", "Bank"}, {"my", "bank"}} {
		app, _ = cliApp("", false)
		if out, _, err := runCLI(app, runGet, args...); err != nil || out != "d\n" {
			t.Errorf("%q: %q, %v", args, out, err)
		}
	}
	app, _ = cliApp("", false)
	if _, _, err := runCLI(app, runGet, "password/GitHub/alice"); err == nil || !strings.Contains(err.Error(), "did you mean password/github/alice?") {
		t.Errorf("an ID in another case: %v", err)
	}
	app, _ = cliApp("", false)
	if _, _, err := runCLI(app, runGet, "nothing", "like", "it"); err == nil || !strings.Contains(err.Error(), `no entry matches "nothing like it"`) {
		t.Errorf("no match: %v", err)
	}
}

// sesh list lists every entry or the kinds named, narrowed by folder and tag, as a table or JSON.
func TestList(t *testing.T) {
	filingVault(t)
	mustRun(t, runFolder, "move", "work", "password/github/alice")
	out := mustRun(t, runList)
	for _, want := range []string{"NAME", "KIND", "FOLDER", "api_key/openai", "password/My Bank", "password/github/alice"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if out := mustRun(t, runList, "keys"); !strings.Contains(out, "api_key/openai") || strings.Contains(out, "password/") {
		t.Errorf("keys:\n%s", out)
	}
	if out := mustRun(t, runList, "--folder", "work"); !strings.Contains(out, "password/github/alice") || strings.Contains(out, "gitlab") {
		t.Errorf("--folder work:\n%s", out)
	}
	var listed []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(mustRun(t, runList, "passwords", "--json")), &listed); err != nil || len(listed) != 3 {
		t.Errorf("--json: %+v, %v", listed, err)
	}
	app, _ := cliApp("", false)
	if _, errOut, err := runCLI(app, runList, "totp"); err != nil || !strings.Contains(errOut, "No TOTP entries") {
		t.Errorf("none of a kind: %q, %v", errOut, err)
	}
	for args, wantSub := range map[string]string{
		"frobs":         `sesh list takes kinds (passwords, keys, notes, totp), not "frobs"`,
		"--sort colour": `--sort is name, created, updated, or folder, not "colour"`,
	} {
		if _, err := runFiling(t, runList, strings.Fields(args)...); err == nil || !strings.Contains(err.Error(), wantSub) {
			t.Errorf("%s: %v", args, err)
		}
	}
}

// sesh search ranks matches, says the command for a single one, and suggests names for none.
func TestSearch(t *testing.T) {
	filingVault(t)
	app, _ := cliApp("", false)
	out, errOut, err := runCLI(app, runSearch, "openai")
	if err != nil || !strings.Contains(out, `Found 1 entry matching "openai"`) || !strings.Contains(errOut, "Copy it: sesh copy api_key/openai") {
		t.Errorf("one: %q, %q, %v", out, errOut, err)
	}
	app, _ = cliApp("", false)
	if out, _, err := runCLI(app, runSearch, "key"); err != nil || !strings.Contains(out, "api_key/openai") || strings.Contains(out, "password/") {
		t.Errorf("a kind word: %q, %v", out, err)
	}
	app, _ = cliApp("", false)
	if _, errOut, err := runCLI(app, runSearch, "githbu"); err != nil || !strings.Contains(errOut, `No entries matching "githbu". Did you mean: github?`) {
		t.Errorf("none: %q, %v", errOut, err)
	}
}

// sesh copy copies the secret, or a TOTP entry's code, or the part asked for; sesh get prints it.
func TestCopyAndGet(t *testing.T) {
	filingVault(t)
	app, copied := cliApp("", false)
	if _, errOut, err := runCLI(app, runCopy, "openai"); err != nil || !slices.Equal(*copied, []string{"c"}) || !strings.Contains(errOut, "Copied openai's api key") {
		t.Errorf("secret: %q, %q, %v", *copied, errOut, err)
	}
	app, copied = cliApp("", false)
	if _, _, err := runCLI(app, runCopy, "github", "--username"); err != nil || !slices.Equal(*copied, []string{"alice"}) {
		t.Errorf("--username: %q, %v", *copied, err)
	}
	app, _ = cliApp("", false)
	if _, _, err := runCLI(app, runCopy, "github", "--url"); err == nil || !strings.Contains(err.Error(), "github (alice) has no URL") {
		t.Errorf("no URL: %v", err)
	}
	app, _ = cliApp("", false)
	if _, _, err := runCLI(app, runCopy, "github", "--url", "--username"); err == nil || !strings.Contains(err.Error(), "one of --username, --url and --field") {
		t.Errorf("two parts: %v", err)
	}
	app, _ = cliApp("", false)
	app.ClipboardCheck = func() error { return clipboard.ErrNoDisplay }
	if _, _, err := runCLI(app, runCopy, "openai"); err == nil || !strings.Contains(err.Error(), "sesh get prints it instead") {
		t.Errorf("no clipboard: %v", err)
	}
	app, _ = cliApp("", false)
	out, _, err := runCLI(app, runGet, "github", "--json")
	var got struct{ ID, Part, Value string }
	if err != nil || json.Unmarshal([]byte(out), &got) != nil || got.ID != "password/github/alice" || got.Part != "secret" || got.Value != "a" {
		t.Errorf("--json: %q, %v", out, err)
	}
}

// sesh code prints a TOTP entry's code and its time; copy and get give the code too. Other kinds aren't matched.
func TestCode(t *testing.T) {
	filingVault(t)
	app, _ := cliApp("JBSWY3DPEHPK3PXP\n", false)
	if _, _, err := runCLI(app, runAdd, "totp", "github", "--username", "alice"); err != nil {
		t.Fatal(err)
	}
	app, _ = cliApp("", false)
	out, errOut, err := runCLI(app, runCode, "github")
	if err != nil || len(strings.TrimSpace(out)) != 6 || !strings.Contains(errOut, "github (alice)'s code, for ") {
		t.Errorf("code: %q, %q, %v", out, errOut, err)
	}
	app, copied := cliApp("", false)
	if _, _, err := runCLI(app, runCopy, "github", "totp"); err != nil || len(*copied) != 1 || len((*copied)[0]) != 6 {
		t.Errorf("copy a code: %q, %v", *copied, err)
	}
	app, _ = cliApp("", false)
	if _, _, err := runCLI(app, runCode, "openai"); err == nil || !strings.Contains(err.Error(), `no TOTP entry matches "openai"`) {
		t.Errorf("not TOTP: %v", err)
	}
}

// sesh open opens the URL, through the browser; an entry without one says how to add one.
func TestOpen(t *testing.T) {
	filingVault(t)
	var opened []string
	old := startBrowser
	t.Cleanup(func() { startBrowser = old })
	startBrowser = func(a string) error { opened = append(opened, a); return nil }
	mustRun(t, runEdit, "openai", "--url", "platform.openai.com")
	if _, err := runFiling(t, runOpen, "openai"); err != nil || !slices.Equal(opened, []string{"https://platform.openai.com"}) {
		t.Errorf("opened %q, %v", opened, err)
	}
	if _, err := runFiling(t, runOpen, "gitlab"); err == nil || !strings.Contains(err.Error(), "gitlab has no URL; add one with: sesh edit password/gitlab --url <url>") {
		t.Errorf("no URL: %v", err)
	}
}

// sesh add adds each kind: a secret piped in, a generated password (copied), a note's lines, a TOTP key or link
// (which names it), or a QR code; an entry there already isn't replaced without --force.
func TestAdd(t *testing.T) {
	filingVault(t)
	app, _ := cliApp("piped-Strong-pass-81\n", false)
	if _, errOut, err := runCLI(app, runAdd, "password", "bank", "--username", "me", "--url", "bank.example", "--tag", "money"); err != nil || !strings.Contains(errOut, "✅ Added bank (me)") {
		t.Fatalf("piped: %q, %v", errOut, err)
	}
	app, _ = cliApp("", false)
	if out, _, err := runCLI(app, runGet, "bank", "me"); err != nil || out != "piped-Strong-pass-81\n" {
		t.Errorf("stored: %q, %v", out, err)
	}
	app, copied := cliApp("", false)
	if _, errOut, err := runCLI(app, runAdd, "password", "shop", "--generate", "--length", "30"); err != nil || len(*copied) != 1 || len((*copied)[0]) != 30 || !strings.Contains(errOut, "and copied its password") {
		t.Errorf("generated: %q, %q, %v", *copied, errOut, err)
	}
	app, _ = cliApp("line one\nline two\n", false)
	if _, _, err := runCLI(app, runAdd, "note", "house"); err != nil {
		t.Fatal(err)
	}
	app, _ = cliApp("", false)
	if out, _, err := runCLI(app, runGet, "house"); err != nil || out != "line one\nline two\n" {
		t.Errorf("note: %q, %v", out, err)
	}
	app, _ = cliApp("otpauth://totp/Acme:jo@acme.io?secret=JBSWY3DPEHPK3PXP&issuer=Acme&digits=8\n", false)
	if _, errOut, err := runCLI(app, runAdd, "totp"); err != nil || !strings.Contains(errOut, "✅ Added Acme (jo@acme.io) (codes: SHA1, 8 digits, every 30s)") {
		t.Errorf("a link: %q, %v", errOut, err)
	}
	old := scanQR
	t.Cleanup(func() { scanQR = old })
	scanQR = func() (qrcode.TOTPInfo, error) {
		return qrcode.TOTPInfo{Secret: "JBSWY3DPEHPK3PXP", Issuer: "Corp", Account: "carol"}, nil
	}
	app, _ = cliApp("", false)
	if _, errOut, err := runCLI(app, runAdd, "totp", "--qr", "--folder", "work"); err != nil || !strings.Contains(errOut, "✅ Added Corp (carol)") {
		t.Errorf("--qr: %q, %v", errOut, err)
	}
	if out := mustRun(t, runList, "totp", "--folder", "work"); !strings.Contains(out, "totp/Corp/carol") {
		t.Errorf("--qr's folder:\n%s", out)
	}
	for args, wantSub := range map[string]string{
		"password github --username alice": "github (alice) already exists; add --force to replace it",
		"password GitHub --username alice": "github (alice) already exists, and names are case-sensitive",
		"widget x":                         `takes a kind first (password, key, note, or totp), not "widget"`,
		"key x --generate":                 "--generate makes a password; a API key comes from elsewhere",
		"password x --length 8":            "add --generate",
		"note x --qr":                      "--qr reads a TOTP entry's key",
		"password":                         "name the entry: sesh add password <name>",
		"totp":                             "name the entry: sesh add totp <name>",
	} {
		a, _ := cliApp("JBSWY3DPEHPK3PXP\n", false)
		if _, _, err := runCLI(a, runAdd, strings.Fields(args)...); err == nil || !strings.Contains(err.Error(), wantSub) {
			t.Errorf("%s: %v, want %q", args, err, wantSub)
		}
	}
	app, _ = cliApp("replaced-Strong-pass-81\n", false)
	if _, _, err := runCLI(app, runAdd, "password", "github", "--username", "alice", "--force"); err != nil {
		t.Errorf("--force: %v", err)
	}
	typedSecrets(t, "typed-Strong-pass-81")
	app, _ = cliApp("", true)
	if _, errOut, err := runCLI(app, runAdd, "key", "stripe"); err != nil || !strings.Contains(errOut, "API key for stripe: ") {
		t.Errorf("typed: %q, %v", errOut, err)
	}
}

// sesh generate prints a password stored nowhere, or copies it.
func TestGenerate(t *testing.T) {
	app, _ := cliApp("", false)
	out, _, err := runCLI(app, runGenerate, "--length", "12", "--no-symbols")
	if pw := strings.TrimSpace(out); err != nil || len(pw) != 12 || strings.ContainsAny(pw, "!#$%&*+-.:;<=>?@^_~") {
		t.Errorf("printed %q, %v", out, err)
	}
	app, copied := cliApp("", false)
	if out, _, err := runCLI(app, runGenerate, "--copy"); err != nil || out != "" || len(*copied) != 1 || len((*copied)[0]) != 24 {
		t.Errorf("--copy: %q, %q, %v", out, *copied, err)
	}
	app, _ = cliApp("", false)
	if _, _, err := runCLI(app, runGenerate, "github"); err == nil || !strings.Contains(err.Error(), "sesh add password <name> --generate") {
		t.Errorf("a name: %v", err)
	}
}

// sesh trash's words name one entry; several IDs name several; without a terminal it needs --force.
func TestTrashEntries(t *testing.T) {
	filingVault(t)
	app, _ := cliApp("", false)
	if _, _, err := runCLI(app, runTrash, "openai"); err == nil || !strings.Contains(err.Error(), "add --force") {
		t.Errorf("no terminal: %v", err)
	}
	// Words are one search, not an entry each.
	if _, err := runFiling(t, runTrash, "--force", "openai", "bank"); err == nil || !strings.Contains(err.Error(), `no entry matches "openai bank"`) {
		t.Errorf("two words: %v", err)
	}
	app, _ = cliApp("y\n", true)
	if out, errOut, err := runCLI(app, runTrash, "my", "bank"); err != nil || !strings.Contains(errOut, `Delete "password/My Bank"? [y/N]`) || !strings.Contains(out, "Moved 1 entry to the trash") {
		t.Errorf("words: %q, %q, %v", out, errOut, err)
	}
	if out, err := runFiling(t, runTrash, "--force", "password/gitlab", "api_key/openai"); err != nil || !strings.Contains(out, "Moved 2 entries to the trash") {
		t.Errorf("IDs: %q, %v", out, err)
	}
	if out, err := runFiling(t, runTrash, "github", "--purge", "--force"); err != nil || !strings.Contains(out, "Deleted 1 entry for good") {
		t.Errorf("--purge: %q, %v", out, err)
	}
	if out := mustRun(t, runTrash, "list"); !strings.Contains(out, "password/My Bank") || strings.Contains(out, "github") {
		t.Errorf("the trash:\n%s", out)
	}
}

// sesh export writes JSON or CSV without a terminal, and encrypted only at one; a kind with no entries, or the
// vault's own file, is refused before anything is written.
func TestExportCommand(t *testing.T) {
	filingVault(t)
	file := filepath.Join(t.TempDir(), "all.json")
	app, _ := cliApp("", false)
	if _, errOut, err := runCLI(app, runExport, "--format", "json", "--file", file); err != nil || !strings.Contains(errOut, "Exported 4 entries") || !strings.Contains(errOut, "unencrypted") {
		t.Fatalf("json: %q, %v", errOut, err)
	}
	if b, err := os.ReadFile(file); err != nil || !strings.Contains(string(b), `"service": "openai"`) {
		t.Errorf("the file: %s, %v", b, err)
	}
	app, _ = cliApp("", false)
	if out, _, err := runCLI(app, runExport, "keys", "--format", "csv"); err != nil || !strings.HasPrefix(out, "service,username,type,secret") || strings.Count(out, "\n") != 2 {
		t.Errorf("csv: %q, %v", out, err)
	}
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	for args, wantSub := range map[string]string{
		"--file x.enc":        "an encrypted export asks for its password at a terminal",
		"notes --format json": "no note entries, so nothing was exported",
		"--format yaml":       `--format is encrypted, json, or csv, not "yaml"`,
	} {
		a, _ := cliApp("", false)
		if _, _, err := runCLI(a, runExport, strings.Fields(args)...); err == nil || !strings.Contains(err.Error(), wantSub) {
			t.Errorf("%s: %v, want %q", args, err, wantSub)
		}
	}
	app, _ = cliApp("", false)
	if _, _, err := runCLI(app, runExport, "--format", "json", "--force", "--file", cfg.DBPath.Value); err == nil || !strings.Contains(err.Error(), "is the vault itself") {
		t.Errorf("the vault's file: %v", err)
	}
	typedSecrets(t, "export-pass-Strong-77", "export-pass-Strong-77")
	enc := filepath.Join(t.TempDir(), "all.enc")
	app, _ = cliApp("", true)
	if _, errOut, err := runCLI(app, runExport, "--file", enc); err != nil || !strings.Contains(errOut, "Exported 4 entries to ") {
		t.Errorf("encrypted: %q, %v", errOut, err)
	}
}

// sesh aws refuses, before unlocking, what its words and flags get wrong.
func TestAWSCommand(t *testing.T) {
	for args, wantSub := range map[string]string{
		"setup --clip":  "--clip copies a code; sesh aws setup stores the key",
		"--folder work": "--folder and --tag file the entry sesh aws setup stores",
		"login":         `sesh aws takes setup, or flags, not "login"`,
	} {
		app, _ := cliApp("", false)
		if _, _, err := runCLI(app, runAWS, strings.Fields(args)...); err == nil || !strings.Contains(err.Error(), wantSub) {
			t.Errorf("%s: %v, want %q", args, err, wantSub)
		}
	}
}
