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
		"password/a --type card":           `unknown --type "card"`,
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
