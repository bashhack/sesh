package main

import (
	"bytes"
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
	out, _, err := runEditOut(t, "", false, "password/github/alice", "--service", "github-work", "--username", "")
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
	store := openDoctorVault(t, env)
	defer store.Close() //nolint:errcheck // test cleanup
	if got, err := store.Get(vault.Key{Kind: vault.KindPassword, Service: "gitlab"}); err != nil || string(got) != "new-pw-Strong-91x" {
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
	for _, want := range []string{"Service name [github]: ", "Username [alice] (- removes it): ", "Type [password] (password, api_key, secure_note): ", "Change the secret? [y/N]: "} {
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
		"a name taken":            {`another entry has that name: password/gitlab`, []string{"password/github/alice", "--service", "gitlab", "--username", ""}},
		"a missing entry":         {"did you mean password/github/alice?", []string{"password/GitHub/alice", "--username", "bob"}},
		"nothing changes":         {"nothing to change: the entry already has that name and kind", []string{"password/gitlab", "--service", "gitlab"}},
		"no flags, no terminal":   {"nothing to change: give --service", []string{"password/gitlab"}},
		"flags after the ID only": {"name the entry first", []string{"--service", "x", "password/gitlab"}},
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

// What's wrong without a vault is said before looking for one.
func TestEdit_RefusedBeforeUnlocking(t *testing.T) {
	setupRekeyEnv(t)
	useConfigFile(t, "")
	for args, wantSub := range map[string]string{
		"password/a --type totp":           "a TOTP entry's kind can't change",
		"totp/a --type password":           "a TOTP entry's kind can't change",
		"password/a --type card":           `unknown type "card"`,
		"password/a --length 8":            "add --generate",
		"password/a --secret --no-symbols": "add --generate",
		"totp/a --secret":                  "store it again with --action totp-store",
		"secure_note/a --generate":         "a note isn't generated",
		"password/a --secret --generate":   "choose one",
		"password/a --service a/b":         `contains "/"`,
		"password/a --generate --length 0": "--length wants 1 or more",
		"nope":                             `entry ID "nope"`,
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
	if _, _, err := runEditOut(t, "", false, "totp/aws/work", "--service", "aws-old"); err == nil || !strings.Contains(err.Error(), "add --force to do it anyway") {
		t.Errorf("no terminal: %v", err)
	}
	// Renaming the profile keeps it an AWS entry: no question.
	if out, _, err := runEditOut(t, "", false, "totp/aws/work", "--username", "prod"); err != nil || !strings.Contains(out, "renamed from totp/aws/work") {
		t.Errorf("profile rename: %q, %v", out, err)
	}
	if out, _, err := runEditOut(t, "", false, "totp/aws/prod", "--service", "aws-old", "--force"); err != nil || !strings.Contains(out, "✅ totp/aws-old/prod") {
		t.Errorf("--force: %q, %v", out, err)
	}
}

func TestComplete_EditTypes(t *testing.T) {
	cands, _ := complete(nil, []string{"edit", "password/x", "--type", ""})
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
	_, errOut, err := runEditOut(t, "password\n", false, "password/github/alice", "--service", "gitlab", "--username", "", "--secret")
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
	if err != nil || out != "✅ password/github2: renamed from password/github/alice\n" || strings.Count(errOut, "Service name [github]: ") != 2 || strings.Count(errOut, "Type [password]") != 2 {
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
	if _, errOut, err := runEditOut(t, "", false, "password/gitlab", "-h"); err != nil || !strings.Contains(errOut, "Usage: sesh edit <id> [flags]") {
		t.Errorf("-h: %v\n%s", err, errOut)
	}
	if _, _, err := runEditOut(t, "", false, "password/gitlab", "--service", "gitlab-2"); err != nil {
		t.Fatal(err)
	}
	app := agentTestApp()
	if err := runAudit(app, []string{"--limit", "1"}); err != nil {
		t.Fatal(err)
	}
	if out := app.Stdout.(*bytes.Buffer).String(); !strings.Contains(out, "gitlab-2 (renamed from password/gitlab)") {
		t.Errorf("audit: %s", out)
	}
	if cands, _ := complete(nil, []string{"edit", ""}); len(cands) != 0 {
		t.Errorf("completion offers %v where the ID goes", cands)
	}
}
