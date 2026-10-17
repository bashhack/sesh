package main

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

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

// A profile whose session works opens with no sign-in and no vault: its
// shell gets the profile, and no credentials in variables.
func TestAWSLogin_SessionWorks(t *testing.T) {
	loginVault(t)
	f := &fakeLogin{kind: "aws login", sessions: []error{nil}}
	stubLogin(t, f)
	app, copied := cliApp("", true)
	out, errOut, err := runCLI(app, runAWS, "--profile", "work", "--no-subshell")
	if err != nil {
		t.Fatalf("sesh aws: %v\n%s", err, errOut)
	}
	if len(f.logins) != 0 || len(*copied) != 0 {
		t.Errorf("signed in %q, copied %q", f.logins, *copied)
	}
	if want := "unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_SECURITY_TOKEN\nexport AWS_PROFILE=work\n"; out != want {
		t.Errorf("exports:\n%s\nwant\n%s", out, want)
	}
	if !strings.Contains(errOut, "signs in as arn:aws:iam::123456789012:user/alice, through aws login") {
		t.Errorf("stderr: %s", errOut)
	}
}

// An ended session signs in again, with aws login or aws sso login (their
// no-browser forms over SSH), with the profile's MFA code on the
// clipboard while it runs.
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
		if len(f.logins) != 1 || !slices.Equal(f.logins[0], tc.want) || len(*copied) == 0 || (*copied)[0] != code {
			t.Errorf("%s (ssh %v): signed in with %q, copied %q; want %q and %s", tc.kind, tc.ssh, f.logins, *copied, tc.want, code)
		}
	}
}

// While the sign-in waits, the clipboard gets each new code.
func TestAWSLogin_CodeKeptCurrent(t *testing.T) {
	loginVault(t)
	app, copied := cliApp("", true)
	now := time.Date(2026, 10, 16, 12, 0, 29, 0, time.UTC) // a second left
	app.TimeNow = func() time.Time { return now }
	f := &fakeLogin{kind: "aws login", sessions: []error{errSessionEnded, nil}, during: func() {
		time.Sleep(1500 * time.Millisecond)
	}}
	stubLogin(t, f)
	if _, errOut, err := runCLI(app, runAWS, "--profile", "work", "--no-subshell"); err != nil {
		t.Fatalf("sesh aws: %v\n%s", err, errOut)
	}
	if len(*copied) < 2 {
		t.Errorf("copied %d codes; want a fresh one when the first ran out", len(*copied))
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

	f = &fakeLogin{kind: "aws login", sessions: []error{errSessionEnded, nil}}
	stubLogin(t, f)
	app, copied = cliApp("", true)
	if _, errOut, err := runCLI(app, runAWS, "--profile", "other", "--no-subshell"); err != nil || len(f.logins) != 1 || len(*copied) != 0 {
		t.Errorf("no MFA key: %v, logins %q, copied %q\n%s", err, f.logins, *copied, errOut)
	}

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
		p := &awsLoginProvider{profile: profile}
		creds, err := p.GetCredentials()
		if err != nil {
			t.Fatal(err)
		}
		cfg := p.NewSubshellConfig(&creds).(subshell.Config)
		if len(cfg.Variables) != len(wantVars) || cfg.Variables["AWS_PROFILE"] != wantVars["AWS_PROFILE"] {
			t.Errorf("%q: variables %v", profile, cfg.Variables)
		}
		if hasProfileVars := slices.Contains(cfg.Unset, "AWS_PROFILE") && slices.Contains(cfg.Unset, "AWS_DEFAULT_PROFILE"); hasProfileVars != (profile == "") || !slices.Contains(cfg.Unset, "AWS_SESSION_TOKEN") {
			t.Errorf("%q: unset %v", profile, cfg.Unset)
		}
	}
}
