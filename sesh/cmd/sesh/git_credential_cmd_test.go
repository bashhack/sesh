package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/vault"
)

func TestReadCredentialAsk(t *testing.T) {
	for in, want := range map[string]credentialAsk{
		"protocol=https\nhost=github.com\n\n":                            {protocol: "https", host: "github.com"},
		"protocol=https\nhost=git.corp:8443\nusername=bob\npath=x.git\n": {protocol: "https", host: "git.corp:8443", username: "bob"},
		"url=https://alice@github.com/o/r.git\n":                         {protocol: "https", host: "github.com", username: "alice"},
		"protocol=https\n\nhost=after-the-blank-line\n":                  {protocol: "https"},
		"capability[]=authtype\nwwwauth[]=Basic realm=x\nnot a pair\n":   {},
	} {
		if got, err := readCredentialAsk(strings.NewReader(in)); err != nil || got != want {
			t.Errorf("%q = %+v, %v; want %+v", in, got, err, want)
		}
	}
}

func TestCredentialMatches(t *testing.T) {
	gh := credentialAsk{protocol: "https", host: "github.com"}
	for _, tt := range []struct {
		ask  credentialAsk
		e    vault.Entry
		want bool
	}{
		{gh, vault.Entry{Kind: vault.KindPassword, Service: "github", URL: "https://github.com/login"}, true},
		{gh, vault.Entry{Kind: vault.KindAPIKey, Service: "gh token", URL: "github.com"}, true},
		{gh, vault.Entry{Kind: vault.KindPassword, Service: "github", URL: "https://GitHub.com:443/"}, true},
		{gh, vault.Entry{Kind: vault.KindPassword, Service: "github", URL: "http://github.com"}, false},
		{gh, vault.Entry{Kind: vault.KindPassword, Service: "github", URL: "https://gist.github.com"}, false},
		{gh, vault.Entry{Kind: vault.KindPassword, Service: "github"}, false},
		{gh, vault.Entry{Kind: vault.KindTOTP, Service: "github", URL: "https://github.com"}, false},
		{gh, vault.Entry{Kind: vault.KindNote, Service: "github", URL: "https://github.com"}, false},
		{credentialAsk{protocol: "https", host: "git.corp:8443", username: "bob"}, vault.Entry{Kind: vault.KindPassword, Service: "corp", Username: "bob", URL: "https://git.corp:8443"}, true},
		{credentialAsk{protocol: "https", host: "git.corp:8443"}, vault.Entry{Kind: vault.KindPassword, Service: "corp", Username: "bob", URL: "https://git.corp"}, false},
		{credentialAsk{protocol: "https", host: "github.com", username: "bob"}, vault.Entry{Kind: vault.KindPassword, Service: "github", Username: "alice", URL: "https://github.com"}, false},
		{credentialAsk{protocol: "https", host: "github.com", username: "bob"}, vault.Entry{Kind: vault.KindAPIKey, Service: "token", URL: "https://github.com"}, true},
	} {
		if got := credentialMatches(&tt.e, tt.ask); got != tt.want {
			t.Errorf("%s at %q for %+v = %v", tt.e.Key, tt.e.URL, tt.ask, got)
		}
	}
}

func runGitCredentialOut(t *testing.T, stdin string, args ...string) (out, said string, err error) {
	t.Helper()
	app := agentTestApp()
	app.Stdin = strings.NewReader(stdin)
	err = runGitCredential(app, args)
	return app.Stdout.(*bytes.Buffer).String(), app.Stderr.(*bytes.Buffer).String(), err
}

// git asks for a site's password: the one entry for it is given, with its username, and the read is audited; several give none and say which; store and erase change nothing.
func TestGitCredential(t *testing.T) {
	env := editVault(t)
	store := openDoctorVault(t, env)
	for k, u := range map[vault.Key]string{
		{Kind: vault.KindPassword, Service: "github", Username: "alice"}: "https://github.com/login",
		{Kind: vault.KindPassword, Service: "gitlab"}:                    "https://gitlab.com",
		{Kind: vault.KindAPIKey, Service: "openai"}:                      "https://gitlab.com/openai",
	} {
		if err := store.SetDetails(k, &vault.Details{URL: u}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	before := auditEvents(t, env.dbPath)
	out, said, err := runGitCredentialOut(t, "protocol=https\nhost=github.com\n\n", "get")
	if err != nil || out != "username=alice\npassword=old-pw\n" || said != "" {
		t.Errorf("get: %q, %q, %v", out, said, err)
	}
	if after := auditEvents(t, env.dbPath); after["access"] != before["access"]+1 {
		t.Errorf("access events before %d, after %d", before["access"], after["access"])
	}
	// A username git names isn't said back.
	if named, _, err := runGitCredentialOut(t, "protocol=https\nhost=github.com\nusername=alice\n", "get"); err != nil || named != "password=old-pw\n" {
		t.Errorf("with the username: %q, %v", named, err)
	}
	out, said, err = runGitCredentialOut(t, "protocol=https\nhost=gitlab.com\n", "get")
	if err != nil || out != "" || !strings.Contains(said, "2 entries are for https://gitlab.com (") || !strings.Contains(said, "credential.https://gitlab.com.username") {
		t.Errorf("two entries: %q, %q, %v", out, said, err)
	}
	if none, said, err := runGitCredentialOut(t, "protocol=https\nhost=example.com\n", "get"); err != nil || none != "" || said != "" {
		t.Errorf("none: %q, %q, %v", none, said, err)
	}
	for _, action := range []string{"store", "erase"} {
		if out, said, err := runGitCredentialOut(t, "protocol=https\nhost=github.com\nusername=alice\npassword=typed\n", action); err != nil || out != "" || said != "" {
			t.Errorf("%s: %q, %q, %v", action, out, said, err)
		}
	}
	if out, _, err := runGitCredentialOut(t, "protocol=https\nhost=github.com\n", "get"); err != nil || out != "username=alice\npassword=old-pw\n" {
		t.Errorf("after store and erase: %q, %v", out, err)
	}
	// A password git can't take, with a line break, isn't given.
	populatePasswordStore(t, env, map[string]string{"password/multi": "line one\nline two"})
	store = openDoctorVault(t, env)
	if err := store.SetDetails(vault.Key{Kind: vault.KindPassword, Service: "multi"}, &vault.Details{URL: "https://multi.example"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if out, said, err := runGitCredentialOut(t, "protocol=https\nhost=multi.example\n", "get"); err != nil || out != "" || !strings.Contains(said, "has a line break in it") {
		t.Errorf("a line break: %q, %q, %v", out, said, err)
	}
	for args, wantSub := range map[string]string{"fill": "takes get, store or erase", "get extra": "takes one word"} {
		if _, _, err := runGitCredentialOut(t, "", strings.Fields(args)...); err == nil || !strings.Contains(err.Error(), wantSub) {
			t.Errorf("%s: %v, want %q", args, err, wantSub)
		}
	}
}

// The master password is asked at the terminal, not on stdin, which is git's: the terminal is there before the vault unlocks.
func TestGitCredential_AsksAtTheTerminal(t *testing.T) {
	env := editVault(t)
	store := openDoctorVault(t, env)
	if err := store.SetDetails(vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}, &vault.Details{URL: "https://github.com"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SESH_MASTER_PASSWORD", "")
	tty, err := os.CreateTemp(t.TempDir(), "tty")
	if err != nil {
		t.Fatal(err)
	}
	oldOpen, oldPrompt := openTerminal, terminalPasswordPrompt
	t.Cleanup(func() { openTerminal, terminalPasswordPrompt = oldOpen, oldPrompt })
	openTerminal = func() (*os.File, error) { return tty, nil }
	var askedAt *os.File
	terminalPasswordPrompt = func() passwordPromptConfig {
		askedAt = terminalIn
		return interactivePrompt(t, "edit-password-1234")
	}
	out, said, err := runGitCredentialOut(t, "protocol=https\nhost=github.com\n", "get")
	if err != nil || out != "username=alice\npassword=old-pw\n" {
		t.Fatalf("get: %q, %q, %v", out, said, err)
	}
	if askedAt != tty || terminalIn != os.Stdin {
		t.Errorf("asked at %v (the terminal is %v); after, terminalIn is %v", askedAt, tty, terminalIn)
	}
}

// The username git names picks its entry; one with no username, a token's, does when none has it.
func TestGitCredential_Usernames(t *testing.T) {
	env := editVault(t)
	populatePasswordStore(t, env, map[string]string{"api_key/gh-token": "ghp_x", "password/github/bob": "bob-pw"})
	store := openDoctorVault(t, env)
	for _, k := range []vault.Key{{Kind: vault.KindPassword, Service: "github", Username: "alice"}, {Kind: vault.KindAPIKey, Service: "gh-token"}, {Kind: vault.KindPassword, Service: "github", Username: "bob"}} {
		if err := store.SetDetails(k, &vault.Details{URL: "https://github.com"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	for user, want := range map[string]string{"alice": "password=old-pw\n", "bob": "password=bob-pw\n", "carol": "password=ghp_x\n"} {
		if out, said, err := runGitCredentialOut(t, "protocol=https\nhost=github.com\nusername="+user+"\n", "get"); err != nil || out != want {
			t.Errorf("%s: %q, %q, %v", user, out, said, err)
		}
	}
	if out, said, err := runGitCredentialOut(t, "protocol=https\nhost=github.com\n", "get"); err != nil || out != "" || !strings.Contains(said, "3 entries are for https://github.com") {
		t.Errorf("no username: %q, %q, %v", out, said, err)
	}
}
