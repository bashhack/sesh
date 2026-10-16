package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/vault"
)

// editVault is a vault with a few entries, unlocked with SESH_MASTER_PASSWORD.
func editVault(t *testing.T) *rekeyTestEnv {
	t.Helper()
	env := setupRekeyEnv(t)
	useConfigFile(t, "")
	t.Setenv("SESH_MASTER_PASSWORD", "edit-password-1234")
	populatePasswordStore(t, env, map[string]string{
		"password/github/alice": "old-pw", "api_key/openai": "sk-1", "secure_note/recovery": "codes", "password/gitlab": "x",
	})
	return env
}

func runEditOut(t *testing.T, stdin string, terminal bool, args ...string) (string, string, error) {
	t.Helper()
	app := agentTestApp()
	app.Stdin = strings.NewReader(stdin)
	app.StdinIsTerminal = func() bool { return terminal }
	err := runEdit(app, args)
	return app.Stdout.(*bytes.Buffer).String(), app.Stderr.(*bytes.Buffer).String(), err
}

func TestEdit_RenameKeepsFiling(t *testing.T) {
	env := editVault(t)
	mustRun(t, runFolder, "move", "work", "password/github/alice")
	mustRun(t, runTag, "add", "code", "password/github/alice")
	out, _, err := runEditOut(t, "", false, "password/github/alice", "--rename", "github-work", "--username", "")
	if err != nil || out != "✅ password/github-work: renamed from password/github/alice\n" {
		t.Fatalf("rename: %q, %v", out, err)
	}
	store := openDoctorVault(t, env)
	defer store.Close() //nolint:errcheck // test cleanup
	e, err := store.Lookup(vault.Key{Kind: vault.KindPassword, Service: "github-work"})
	if err != nil || e.Folder != "work" || len(e.Tags) != 1 {
		t.Errorf("renamed entry = %+v, %v; want its folder and tag kept", e, err)
	}
	if got, err := store.Get(vault.Key{Kind: vault.KindPassword, Service: "github-work"}); err != nil || string(got) != "old-pw" {
		t.Errorf("secret = %q, %v", got, err)
	}
}

func TestEdit_SecretKindAndGenerate(t *testing.T) {
	env := editVault(t)
	// Without a terminal, --secret reads a line from stdin.
	if out, _, err := runEditOut(t, "new-pw-Strong-91x\n", false, "password/gitlab", "--secret"); err != nil || out != "✅ password/gitlab: secret changed\n" {
		t.Errorf("--secret: %q, %v", out, err)
	}
	if out, _, err := runEditOut(t, "", false, "api_key/openai", "--type", "password"); err != nil || out != "✅ password/openai: renamed from api_key/openai\n" {
		t.Errorf("--type: %q, %v", out, err)
	}
	if out, _, err := runEditOut(t, "", false, "password/openai", "--generate", "--length", "32"); err != nil || !strings.Contains(out, "secret changed") {
		t.Errorf("--generate: %q, %v", out, err)
	}
	if out, _, err := runEditOut(t, "", false, "password/gitlab", "--generate", "--words", "4", "--separator", "."); err != nil || !strings.Contains(out, "secret changed") {
		t.Errorf("--generate --words: %q, %v", out, err)
	}
	if _, _, err := runEditOut(t, "", false, "password/gitlab", "--words", "4"); err == nil || !strings.Contains(err.Error(), "add --generate") {
		t.Errorf("--words without --generate: %v", err)
	}
	store := openDoctorVault(t, env)
	defer store.Close() //nolint:errcheck // test cleanup
	if got, err := store.Get(vault.Key{Kind: vault.KindPassword, Service: "gitlab"}); err != nil || strings.Count(string(got), ".") != 3 {
		t.Errorf("gitlab = %q, %v", got, err)
	}
	if got, err := store.Get(vault.Key{Kind: vault.KindPassword, Service: "openai"}); err != nil || len(got) != 32 {
		t.Errorf("openai = %d bytes, %v; want a generated 32", len(got), err)
	}
}

// At a terminal with no flags, it asks, with the current values as defaults.
func TestEdit_Asks(t *testing.T) {
	editVault(t)
	// Service: github-work; username: Enter keeps alice; type: Enter keeps;
	// the secret: no.
	out, errOut, err := runEditOut(t, "github-work\n\n\nn\n", true, "password/github/alice")
	if err != nil || out != "✅ password/github-work/alice: renamed from password/github/alice\n" {
		t.Fatalf("asked: %q, %v\n%s", out, err, errOut)
	}
	for _, want := range []string{"Name [github]: ", "Username [alice] (- removes it): ", "Type [password] (password, api_key, secure_note): ", "Change the secret? [y/N]: "} {
		if !strings.Contains(errOut, want) {
			t.Errorf("didn't ask %q:\n%s", want, errOut)
		}
	}
	if _, errOut, err := runEditOut(t, "\n\n\nn\n", true, "password/github-work/alice"); err != nil || !strings.Contains(errOut, "Nothing changed.") {
		t.Errorf("all kept: %v\n%s", err, errOut)
	}
}

func TestEdit_Refusals(t *testing.T) {
	env := editVault(t)
	for name, tt := range map[string]struct {
		wantSub string
		args    []string
	}{
		"a name taken":          {`another entry has that name: password/gitlab`, []string{"password/github/alice", "--rename", "gitlab", "--username", ""}},
		"a missing entry":       {"did you mean password/github/alice?", []string{"password/GitHub/alice", "--username", "bob"}},
		"nothing changes":       {"nothing to change: the entry already has that name and kind", []string{"password/gitlab", "--rename", "gitlab"}},
		"no flags, no terminal": {"nothing to change: give --rename", []string{"password/gitlab"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := runEditOut(t, "", false, tt.args...); err == nil || !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("err = %v, want %q", err, tt.wantSub)
			}
		})
	}
	if got := readEntriesViaPassword(t, env, []string{"password/github/alice"})["password/github/alice"]; got != "old-pw" {
		t.Errorf("after refusals the entry is %q", got)
	}
}

// What's wrong with the flags for an entry named by its ID is said before looking for a vault; words need one.
func TestEdit_RefusedBeforeUnlocking(t *testing.T) {
	setupRekeyEnv(t)
	useConfigFile(t, "")
	for args, wantSub := range map[string]string{
		"password/a --type totp":           "a TOTP entry's kind can't change",
		"totp/a --type password":           "a TOTP entry's kind can't change",
		"password/a --type card":           `unknown type "card"`,
		"password/a --length 8":            "add --generate",
		"password/a --secret --no-symbols": "add --generate",
		"totp/a --secret":                  "add it again with sesh add totp --force",
		"secure_note/a --generate":         "a note isn't generated",
		"password/a --secret --generate":   "choose one",
		"password/a --rename a/b":          `contains "/"`,
		"password/a --generate --length 0": "--length: password length must be at least 1",
		"password/a --generate --length 3": "--length: password length 3 is too short for 4 required character sets",
		"nope":                             "nothing to change",
	} {
		if _, _, err := runEditOut(t, "", false, strings.Fields(args)...); err == nil || !strings.Contains(err.Error(), wantSub) {
			t.Errorf("%s: %v, want %q", args, err, wantSub)
		}
	}
}

// Renaming an AWS profile's MFA entry out of service aws asks first.
func TestEdit_AWSEntry(t *testing.T) {
	env := editVault(t)
	populatePasswordStore(t, env, map[string]string{"totp/aws/work": "JBSWY3DPEHPK3PXP"})
	if _, _, err := runEditOut(t, "", false, "totp/aws/work", "--rename", "aws-old"); err == nil || !strings.Contains(err.Error(), "add --force to do it anyway") {
		t.Errorf("no terminal: %v", err)
	}
	// Renaming the profile keeps it an AWS entry: no question.
	if out, _, err := runEditOut(t, "", false, "totp/aws/work", "--username", "prod"); err != nil || !strings.Contains(out, "renamed from totp/aws/work") {
		t.Errorf("profile rename: %q, %v", out, err)
	}
	if out, _, err := runEditOut(t, "", false, "totp/aws/prod", "--rename", "aws-old", "--force"); err != nil || !strings.Contains(out, "✅ totp/aws-old/prod") {
		t.Errorf("--force: %q, %v", out, err)
	}
}

func TestComplete_EditTypes(t *testing.T) {
	cands, _ := complete([]string{"edit", "password/x", "--type", ""})
	var got []string
	for _, c := range cands {
		got = append(got, c.value)
	}
	if strings.Join(got, " ") != "password api_key secure_note" {
		t.Errorf("--type completes %q", got)
	}
}

// Removing an AWS entry's username takes it out of the AWS provider too,
// so it asks; renaming its profile doesn't.
func TestEdit_AWSUsernameRemoval(t *testing.T) {
	env := editVault(t)
	populatePasswordStore(t, env, map[string]string{"totp/aws/work": "JBSWY3DPEHPK3PXP"})
	if _, _, err := runEditOut(t, "", false, "totp/aws/work", "--username", ""); err == nil || !strings.Contains(err.Error(), "add --force") {
		t.Errorf("removing the username: %v", err)
	}
}

// A taken name is refused before the new secret is read: stdin is left
// unread, and nothing is said about a stored password.
func TestEdit_NameTakenBeforeTheSecret(t *testing.T) {
	editVault(t)
	_, errOut, err := runEditOut(t, "password\n", false, "password/github/alice", "--rename", "gitlab", "--username", "", "--secret")
	if err == nil || !strings.Contains(err.Error(), "another entry has that name: password/gitlab") || strings.Contains(errOut, "stored") {
		t.Errorf("err = %v, stderr %q", err, errOut)
	}
}

func TestEdit_AskingEdges(t *testing.T) {
	env := editVault(t)
	// The end of input at the first question, or at the last, changes nothing.
	for name, stdin := range map[string]string{"at the first": "", "at the last": "renamed-by-eof\n\n\n"} {
		if _, errOut, err := runEditOut(t, stdin, true, "password/gitlab"); err != nil || !strings.Contains(errOut, "Nothing changed.") {
			t.Errorf("%s: %v\n%s", name, err, errOut)
		}
	}
	// A bad answer is asked again; "-" removes the username.
	out, errOut, err := runEditOut(t, "a/b\ngithub2\n-\ncard\npassword\nn\n", true, "password/github/alice")
	if err != nil || out != "✅ password/github2: renamed from password/github/alice\n" || strings.Count(errOut, "Name [github]: ") != 2 || strings.Count(errOut, "Type [password]") != 2 {
		t.Errorf("asked again: %q, %v\n%s", out, err, errOut)
	}
	if got := readEntriesViaPassword(t, env, []string{"password/gitlab"})["password/gitlab"]; got != "x" {
		t.Errorf("gitlab = %q after cancelled edits", got)
	}
}

// A piped secret: one trailing newline (\r\n too) is dropped; several lines
// are refused for a password; a note keeps them all.
func TestEdit_PipedSecrets(t *testing.T) {
	env := editVault(t)
	if _, _, err := runEditOut(t, "crlf-pw-Strong-81\r\n", false, "password/gitlab", "--secret"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runEditOut(t, "line1-Strong-81\nline2\n", false, "password/gitlab", "--secret"); err == nil || !strings.Contains(err.Error(), "is one line, and this has several") {
		t.Errorf("several lines: %v", err)
	}
	if _, _, err := runEditOut(t, "line one\nline two\n", false, "secure_note/recovery", "--secret"); err != nil {
		t.Fatal(err)
	}
	got := readEntriesViaPassword(t, env, []string{"password/gitlab", "secure_note/recovery"})
	if got["password/gitlab"] != "crlf-pw-Strong-81" || got["secure_note/recovery"] != "line one\nline two\n" {
		t.Errorf("stored %q", got)
	}
}

func TestEdit_HelpAndAudit(t *testing.T) {
	editVault(t)
	if _, errOut, err := runEditOut(t, "", false, "password/gitlab", "-h"); err != nil || !strings.Contains(errOut, "Usage: sesh edit <entry> [flags]") {
		t.Errorf("-h: %v\n%s", err, errOut)
	}
	if _, _, err := runEditOut(t, "", false, "password/gitlab", "--rename", "gitlab-2"); err != nil {
		t.Fatal(err)
	}
	app := agentTestApp()
	if err := runAudit(app, []string{"--limit", "1"}); err != nil {
		t.Fatal(err)
	}
	if out := app.Stdout.(*bytes.Buffer).String(); !strings.Contains(out, "gitlab-2 (renamed from password/gitlab)") {
		t.Errorf("audit: %s", out)
	}
	if cands, _ := complete([]string{"edit", ""}); !slices.ContainsFunc(cands, func(c candidate) bool { return c.value == "--rename" }) {
		t.Errorf("completion offers %v, not edit's flags", cands)
	}
}

// --secret given the secret the entry has changes nothing, and says so, as storing it again would.
func TestEdit_SameSecret(t *testing.T) {
	editVault(t)
	out, errOut, err := runEditOut(t, "sk-1\n", false, "api_key/openai", "--secret")
	if err != nil || out != "" || errOut != "Nothing changed: the entry already has that secret.\n" {
		t.Errorf("the same secret: out %q, err out %q, %v", out, errOut, err)
	}
}

// --rename-field keeps a field's value and secrecy; --plain-field makes a secret field plain with its value. Names
// that clash, or fields not there, are refused before anything changes.
func TestEdit_RenameAndPlainField(t *testing.T) {
	env := editVault(t)
	gh := "password/github/alice"
	if _, _, err := runEditOut(t, "", false, gh, "--field", "email=a@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runEditOut(t, "4321\n", false, gh, "--secret-field", "pin"); err != nil {
		t.Fatal(err)
	}
	for args, wantSub := range map[string]string{
		gh + " --rename-field nope=x":                   `no field "nope" to rename; its fields: email, pin`,
		gh + " --rename-field email=PIN":                "has a field pin already; remove it first",
		gh + " --rename-field email=email":              "named that already",
		gh + " --rename-field email":                    "wants old=new",
		gh + " --plain-field email":                     "plain already",
		gh + " --plain-field nope":                      `no field "nope" to make plain`,
		gh + " --rename-field pin=x --remove-field pin": "both removed and renamed",
	} {
		if _, _, err := runEditOut(t, "", false, strings.Fields(args)...); err == nil || !strings.Contains(err.Error(), wantSub) {
			t.Errorf("%s: %v, want %q", args, err, wantSub)
		}
	}
	app, _ := cliApp("", false)
	if _, _, err := runCLI(app, runAdd, "password", "x", "--rename-field", "a=b"); err == nil || !strings.Contains(err.Error(), "sesh edit <entry> --rename-field") {
		t.Errorf("add: %v", err)
	}
	if _, _, err := runEditOut(t, "", false, gh, "--rename-field", "pin=card-pin", "--rename-field", "email=Email"); err != nil {
		t.Fatal(err)
	}
	fields := func() []vault.Field {
		store := openDoctorVault(t, env)
		defer store.Close() //nolint:errcheck // test cleanup
		d, err := store.Details(vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		return d.Fields
	}
	got := fields()
	if len(got) != 2 || !slices.ContainsFunc(got, func(f vault.Field) bool { return f.Name == "card-pin" && f.Secret && string(f.Value) == "4321" }) ||
		!slices.ContainsFunc(got, func(f vault.Field) bool { return f.Name == "Email" && !f.Secret && string(f.Value) == "a@example.com" }) {
		t.Errorf("renamed = %+v", got)
	}
	if _, _, err := runEditOut(t, "", false, gh, "--plain-field", "card-pin"); err != nil {
		t.Fatal(err)
	}
	if got := fields(); !slices.ContainsFunc(got, func(f vault.Field) bool { return f.Name == "card-pin" && !f.Secret && string(f.Value) == "4321" }) {
		t.Errorf("made plain = %+v", got)
	}
	if log := mustRun(t, runAudit); !strings.Contains(log, "field pin renamed to card-pin") || !strings.Contains(log, "field card-pin made plain") {
		t.Errorf("the changes aren't in the audit log:\n%s", log)
	}
}
