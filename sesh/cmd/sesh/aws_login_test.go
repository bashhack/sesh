package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/aws"
	"github.com/bashhack/sesh/internal/clipboard"
	"github.com/bashhack/sesh/internal/subshell"
	"github.com/bashhack/sesh/internal/totp"
)

// fakeLogin is the AWS CLI as sesh aws's sign-in sees it: the profile's
// kind, whether its session works (each identity call takes the next
// answer; the last repeats), and the sign-ins run.
type fakeLogin struct {
	loginErr error
	during   func() // run while the sign-in is under way
	kind     string
	sessions []error
	logins   [][]string
}

func stubLogin(t *testing.T, f *fakeLogin) {
	t.Helper()
	k, id, run := awsProfileKind, awsCallerIdentity, awsRunLogin
	t.Cleanup(func() { awsProfileKind, awsCallerIdentity, awsRunLogin = k, id, run })
	awsProfileKind = func(string) string { return f.kind }
	awsCallerIdentity = func(string) (string, error) {
		err := f.sessions[0]
		if len(f.sessions) > 1 {
			f.sessions = f.sessions[1:]
		}
		if err != nil {
			return "", err
		}
		return "arn:aws:iam::123456789012:user/alice", nil
	}
	awsRunLogin = func(_ string, args ...string) error {
		f.logins = append(f.logins, args)
		if f.during != nil {
			f.during()
		}
		return f.loginErr
	}
}

// loginVault is a vault holding the MFA key for profile work.
func loginVault(t *testing.T) {
	t.Helper()
	env := setupRekeyEnv(t)
	useConfigFile(t, "")
	t.Setenv("SESH_MASTER_PASSWORD", "login-password-1234")
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("SSH_CLIENT", "")
	populatePasswordStore(t, env, map[string]string{"totp/aws/work": "JBSWY3DPEHPK3PXP"})
}

var errSessionEnded = errors.New("unable to load a existing login session, Please reauthenticate with 'aws login'")

// A profile whose session works opens with no sign-in and no vault: with
// no master password to be had (none set, no terminal), nothing asks for
// one. Its exports clear credentials and AWS_DEFAULT_PROFILE.
func TestAWSLogin_SessionWorks(t *testing.T) {
	loginVault(t)
	t.Setenv("SESH_MASTER_PASSWORD", "")
	f := &fakeLogin{kind: "aws login", sessions: []error{nil}}
	stubLogin(t, f)
	app, copied := cliApp("", false)
	out, errOut, err := runCLI(app, runAWS, "--profile", "work", "--no-subshell")
	if err != nil {
		t.Fatalf("sesh aws: %v\n%s", err, errOut)
	}
	if len(f.logins) != 0 || len(*copied) != 0 {
		t.Errorf("signed in %q, copied %q", f.logins, *copied)
	}
	if want := "unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_SECURITY_TOKEN AWS_DEFAULT_PROFILE\nexport AWS_PROFILE=work\n"; out != want {
		t.Errorf("exports:\n%s\nwant\n%s", out, want)
	}
	if !strings.Contains(errOut, "signs in as arn:aws:iam::123456789012:user/alice, through aws login") {
		t.Errorf("stderr: %s", errOut)
	}
}

// An ended session signs in again, with aws login or aws sso login (their
// no-browser forms over SSH), saying why, with the profile's MFA code on
// the clipboard while it runs; over SSH, where the clipboard is the remote
// computer's, the code is printed instead.
func TestAWSLogin_SignsIn(t *testing.T) {
	for _, tc := range []struct {
		kind string
		want []string
		ssh  bool
	}{
		{"aws login", []string{"login"}, false},
		{"aws login", []string{"login", "--remote"}, true},
		{"SSO", []string{"sso", "login"}, false},
		{"SSO", []string{"sso", "login", "--no-browser"}, true},
	} {
		loginVault(t)
		if tc.ssh {
			t.Setenv("SSH_CONNECTION", "10.0.0.1 22 10.0.0.2 22")
		}
		f := &fakeLogin{kind: tc.kind, sessions: []error{errSessionEnded, nil}}
		stubLogin(t, f)
		app, copied := cliApp("", true)
		now := time.Date(2026, 10, 16, 12, 0, 5, 0, time.UTC)
		app.TimeNow = func() time.Time { return now }
		_, errOut, err := runCLI(app, runAWS, "--profile", "work", "--no-subshell")
		if err != nil {
			t.Fatalf("%s: sesh aws: %v\n%s", tc.kind, err, errOut)
		}
		code, err := totp.CodeAt([]byte("JBSWY3DPEHPK3PXP"), totp.Params{}, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(f.logins) != 1 || !slices.Equal(f.logins[0], tc.want) || !strings.Contains(errOut, "doesn't work (unable to load a existing login session") {
			t.Errorf("%s (ssh %v): signed in with %q, want %q\n%s", tc.kind, tc.ssh, f.logins, tc.want, errOut)
		}
		switch {
		case tc.ssh && (len(*copied) != 0 || !strings.Contains(errOut, "MFA code for the sign-in: "+code)):
			t.Errorf("%s over SSH: copied %q\n%s", tc.kind, *copied, errOut)
		case !tc.ssh && (len(*copied) == 0 || (*copied)[0] != code):
			t.Errorf("%s: copied %q, want %s", tc.kind, *copied, code)
		}
	}
}

// A profile the AWS CLI says has no credentials signs in with aws login,
// which sets it up, with the MFA code on the clipboard.
func TestAWSLogin_NotSetUp(t *testing.T) {
	loginVault(t)
	f := &fakeLogin{sessions: []error{errors.New("aws sts get-caller-identity: aws: [ERROR]: The config profile (work) could not be found"), nil}}
	stubLogin(t, f)
	awsProfileKind = aws.SignInKind
	dir := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	cli := "#!/bin/sh\necho 'aws: [ERROR]: Unable to retrieve credentials: The config profile (work) could not be found' >&2\nexit 253\n"
	if err := os.WriteFile(filepath.Join(dir, "aws"), []byte(cli), 0o700); err != nil { //nolint:gosec // a test's AWS CLI
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	app, copied := cliApp("", true)
	_, errOut, err := runCLI(app, runAWS, "--profile", "work", "--no-subshell")
	if err != nil {
		t.Fatalf("sesh aws: %v\n%s", err, errOut)
	}
	if len(f.logins) != 1 || !slices.Equal(f.logins[0], []string{"login"}) || len(*copied) == 0 || !strings.Contains(errOut, "could not be found): signing in with aws login") {
		t.Errorf("signed in with %q, copied %d codes\n%s", f.logins, len(*copied), errOut)
	}
}

// While the sign-in waits, the clipboard gets each new code, as long as it
// still holds sesh's: once something else is copied, it's left alone.
func TestAWSLogin_CodeKeptCurrent(t *testing.T) {
	for _, userCopies := range []bool{false, true} {
		loginVault(t)
		app, copied := cliApp("", true)
		var mu sync.Mutex
		now := time.Date(2026, 10, 16, 12, 0, 29, 0, time.UTC) // a second left
		app.TimeNow = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
		held := ""
		app.ClipboardCopyFor = func(s string, _ time.Duration) error {
			mu.Lock()
			defer mu.Unlock()
			*copied, held = append(*copied, s), s
			now = now.Add(30 * time.Second) // the next check is a window on
			return nil
		}
		app.ClipboardRead = func() (string, error) {
			mu.Lock()
			defer mu.Unlock()
			if userCopies {
				return "hunter2", nil
			}
			return held, nil
		}
		f := &fakeLogin{kind: "aws login", sessions: []error{errSessionEnded, nil}, during: func() {
			time.Sleep(1500 * time.Millisecond)
		}}
		stubLogin(t, f)
		if _, errOut, err := runCLI(app, runAWS, "--profile", "work", "--no-subshell"); err != nil {
			t.Fatalf("sesh aws: %v\n%s", err, errOut)
		}
		mu.Lock()
		got := slices.Clone(*copied)
		mu.Unlock()
		switch {
		case userCopies && len(got) != 1:
			t.Errorf("copied %q over what the user copied", got)
		case !userCopies && (len(got) < 2 || got[0] == got[1]):
			t.Errorf("copied %q; want a new code when the first ran out", got)
		}
	}
}

// Inside a shell sesh aws opened, an ended session is signed in again,
// and no other shell opens; with the session working, it's refused.
func TestAWSLogin_Nested(t *testing.T) {
	loginVault(t)
	t.Setenv("SESH_ACTIVE", "1")
	f := &fakeLogin{kind: "aws login", sessions: []error{errSessionEnded, nil}}
	stubLogin(t, f)
	app, _ := cliApp("", true)
	if _, errOut, err := runCLI(app, runAWS, "--profile", "work"); err != nil || len(f.logins) != 1 || !strings.Contains(errOut, "Signed in again") {
		t.Errorf("ended session: %v, logins %q\n%s", err, f.logins, errOut)
	}
	stubLogin(t, &fakeLogin{kind: "aws login", sessions: []error{nil}})
	app, _ = cliApp("", true)
	if _, _, err := runCLI(app, runAWS, "--profile", "work"); err == nil || !strings.Contains(err.Error(), "already in a sesh environment") {
		t.Errorf("working session: %v", err)
	}
}

// Where nothing can be copied, the code is printed; without an MFA key for
// the profile, the sign-in runs with none; a sign-in that fails says so.
func TestAWSLogin_Edges(t *testing.T) {
	loginVault(t)
	f := &fakeLogin{kind: "aws login", sessions: []error{errSessionEnded, nil}}
	stubLogin(t, f)
	app, copied := cliApp("", true)
	app.ClipboardCheck = func() error { return clipboard.ErrNoDisplay }
	if _, errOut, err := runCLI(app, runAWS, "--profile", "work", "--no-subshell"); err != nil || !strings.Contains(errOut, "MFA code for the sign-in: ") || len(*copied) != 0 {
		t.Errorf("no clipboard: %v, copied %q\n%s", err, *copied, errOut)
	}

	f = &fakeLogin{kind: "aws login", sessions: []error{errSessionEnded, nil}}
	stubLogin(t, f)
	app, _ = cliApp("", true)
	app.ClipboardCopy = func(string) error { return errors.New("pbcopy: not found") }
	if _, errOut, err := runCLI(app, runAWS, "--profile", "work", "--no-subshell"); err != nil || len(f.logins) != 1 || !strings.Contains(errOut, "can't copy the MFA code: pbcopy: not found") || !strings.Contains(errOut, "MFA code for the sign-in: ") {
		t.Errorf("copy fails: %v, logins %q\n%s", err, f.logins, errOut)
	}

	// No MFA key for the profile: no master password is asked for (none set,
	// no terminal), and the sign-in runs with no code.
	t.Setenv("SESH_MASTER_PASSWORD", "")
	f = &fakeLogin{kind: "aws login", sessions: []error{errSessionEnded, nil}}
	stubLogin(t, f)
	app, copied = cliApp("", false)
	if _, errOut, err := runCLI(app, runAWS, "--profile", "other", "--no-subshell"); err != nil || len(f.logins) != 1 || len(*copied) != 0 || strings.Contains(errOut, "warning") {
		t.Errorf("no MFA key: %v, logins %q, copied %q\n%s", err, f.logins, *copied, errOut)
	}
	// An MFA key the vault can't be unlocked for: said, and the sign-in
	// still runs.
	f = &fakeLogin{kind: "aws login", sessions: []error{errSessionEnded, nil}}
	stubLogin(t, f)
	app, _ = cliApp("", false)
	if _, errOut, err := runCLI(app, runAWS, "--profile", "work", "--no-subshell"); err != nil || len(f.logins) != 1 || !strings.Contains(errOut, "warning: the MFA code can't be offered") {
		t.Errorf("locked vault: %v, logins %q\n%s", err, f.logins, errOut)
	}
	t.Setenv("SESH_MASTER_PASSWORD", "login-password-1234")

	f = &fakeLogin{kind: "aws login", sessions: []error{errSessionEnded}, loginErr: errors.New("exit status 255")}
	stubLogin(t, f)
	app, _ = cliApp("", true)
	if _, _, err := runCLI(app, runAWS, "--profile", "work", "--no-subshell"); err == nil || !strings.Contains(err.Error(), "aws login didn't sign profile work in: exit status 255") {
		t.Errorf("failed sign-in: %v", err)
	}
}

// A role's profile: the AWS CLI asks for the code itself, which --clip
// copies.
func TestAWSLogin_RoleProfile(t *testing.T) {
	loginVault(t)
	stubLogin(t, &fakeLogin{kind: "a role", sessions: []error{nil}})
	app, _ := cliApp("", true)
	if _, _, err := runCLI(app, runAWS, "--profile", "work"); err == nil || !strings.Contains(err.Error(), "sesh aws --profile work --clip copies the code") {
		t.Errorf("role: %v", err)
	}
}

// The shell for the default profile has neither AWS_PROFILE nor
// AWS_DEFAULT_PROFILE naming another, and no credentials in variables.
func TestAWSLogin_ShellConfig(t *testing.T) {
	for profile, wantVars := range map[string]map[string]string{"": {}, "work": {"AWS_PROFILE": "work"}} {
		// AWS_DEFAULT_PROFILE goes either way: boto3 reads it before AWS_PROFILE.
		p := &awsLoginProvider{profile: profile}
		creds, err := p.GetCredentials()
		if err != nil {
			t.Fatal(err)
		}
		cfg := p.NewSubshellConfig(&creds).(subshell.Config)
		if len(cfg.Variables) != len(wantVars) || cfg.Variables["AWS_PROFILE"] != wantVars["AWS_PROFILE"] {
			t.Errorf("%q: variables %v", profile, cfg.Variables)
		}
		if slices.Contains(cfg.Unset, "AWS_PROFILE") != (profile == "") || !slices.Contains(cfg.Unset, "AWS_DEFAULT_PROFILE") || !slices.Contains(cfg.Unset, "AWS_SESSION_TOKEN") {
			t.Errorf("%q: unset %v", profile, cfg.Unset)
		}
	}
}

// A profile sesh has no MFA key for says so before the sign-in, copying
// nothing.
func TestAWSLogin_NoKeySaysSo(t *testing.T) {
	loginVault(t)
	f := &fakeLogin{kind: "aws login", sessions: []error{errSessionEnded, nil}}
	stubLogin(t, f)
	app, copied := cliApp("", true)
	_, errOut, err := runCLI(app, runAWS, "--profile", "personal", "--no-subshell")
	if err != nil {
		t.Fatalf("sesh aws: %v\n%s", err, errOut)
	}
	if len(*copied) != 0 || !strings.Contains(errOut, "sesh has no MFA key for profile personal (sesh aws setup --profile personal stores one)") {
		t.Errorf("copied %q\n%s", *copied, errOut)
	}
}
