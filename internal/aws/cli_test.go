package aws

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/testutil"
)

// fakeCLI makes execCommand run script in sh in place of the AWS CLI, with
// the CLI's arguments as its own.
func fakeCLI(t *testing.T, script string) {
	t.Helper()
	orig := execCommand
	t.Cleanup(func() { execCommand = orig })
	execCommand = func(_ string, args ...string) *exec.Cmd {
		return exec.Command("sh", append([]string{"-c", script, "aws"}, args...)...)
	}
}

// The AWS CLI's own message comes with its failure.
func TestRunCLI_ErrorCarriesTheMessage(t *testing.T) {
	fakeCLI(t, `echo "The config profile (work) could not be found" >&2; exit 255`)
	_, err := RunCLI("work", "sts", "get-caller-identity", "--output", "json")
	if wantSub := "aws sts get-caller-identity: The config profile (work) could not be found"; err == nil || !strings.Contains(err.Error(), wantSub) {
		t.Fatalf("RunCLI() = %v, want %q", err, wantSub)
	}
}

// Security keys and hardware tokens are left out of the devices listed.
func TestListMFADevices_AuthenticatorAppsOnly(t *testing.T) {
	fakeCLI(t, `cat <<'JSON'
{"MFADevices": [
  {"UserName": "alice", "SerialNumber": "arn:aws:iam::123456789012:u2f/user/alice/fidosecuritykey1-7XNL7NFNLZ123456789EXAMPLE"},
  {"UserName": "alice", "SerialNumber": "GAKT12345678"},
  {"UserName": "alice", "SerialNumber": "arn:aws:iam::123456789012:mfa/alice"}
]}
JSON`)
	devices, err := ListMFADevices("")
	if err != nil || !slices.Equal(devices, []string{"arn:aws:iam::123456789012:mfa/alice"}) {
		t.Fatalf("ListMFADevices() = %q, %v", devices, err)
	}
}

func TestCallerIdentity(t *testing.T) {
	fakeCLI(t, `echo '{"UserId": "AIDA", "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/alice"}'`)
	if arn, err := CallerIdentity(""); err != nil || arn != "arn:aws:iam::123456789012:user/alice" {
		t.Fatalf("CallerIdentity() = %q, %v", arn, err)
	}
	fakeCLI(t, `echo 'arn:aws:iam::123456789012:user/alice'`)
	if _, err := CallerIdentity(""); err == nil {
		t.Error("CallerIdentity() took text that isn't JSON")
	}
}

// For the default profile, AWS_PROFILE and AWS_DEFAULT_PROFILE are dropped,
// so the CLI uses the profile named default; credentials in variables are
// dropped for any profile.
func TestCLIEnv(t *testing.T) {
	t.Setenv("AWS_PROFILE", "work")
	t.Setenv("AWS_DEFAULT_PROFILE", "old")
	t.Setenv("AWS_ACCESS_KEY_ID", "ASIA")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "s")
	t.Setenv("AWS_SESSION_TOKEN", "t")
	t.Setenv("AWS_SECURITY_TOKEN", "t")
	t.Setenv("AWS_REGION", "eu-west-1")
	t.Setenv("SESH_MASTER_PASSWORD", "hunter2-hunter2")
	has := func(env []string, name string) bool {
		return slices.ContainsFunc(env, func(e string) bool { return strings.HasPrefix(e, name+"=") })
	}
	for _, profile := range []string{"", "work"} {
		env := CLIEnv(profile)
		for _, name := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "SESH_MASTER_PASSWORD"} {
			if has(env, name) {
				t.Errorf("CLIEnv(%q) keeps %s", profile, name)
			}
		}
		if !has(env, "AWS_REGION") {
			t.Errorf("CLIEnv(%q) dropped AWS_REGION", profile)
		}
		if got := has(env, "AWS_PROFILE") || has(env, "AWS_DEFAULT_PROFILE"); got != (profile != "") {
			t.Errorf("CLIEnv(%q) keeps the profile variables: %v", profile, got)
		}
	}
}

// --profile is added after the arguments, without changing the caller's.
func TestCLIArgs(t *testing.T) {
	args := make([]string, 2, 8)
	copy(args, []string{"sts", "get-caller-identity"})
	got := CLIArgs("work", args...)
	if !slices.Equal(got, []string{"sts", "get-caller-identity", "--profile", "work"}) {
		t.Errorf("CLIArgs() = %q", got)
	}
	if extended := args[:4]; extended[2] == "--profile" {
		t.Error("CLIArgs wrote into the caller's slice")
	}
	if got := CLIArgs("", "sts"); !slices.Equal(got, []string{"sts"}) {
		t.Errorf("CLIArgs(\"\") = %q", got)
	}
}

func TestIsVirtualMFADevice(t *testing.T) {
	for arn, want := range map[string]bool{
		"arn:aws:iam::123456789012:mfa/alice":               true,
		"arn:aws:iam::123456789012:mfa/path/to/alice.phone": true,
		"arn:aws:iam::123456789012:mfa/team~a!/alice":       true,
		"arn:aws-us-gov:iam::123456789012:mfa/alice":        true,
		"arn:aws-cn:iam::123456789012:mfa/alice":            true,
		"arn:aws:iam::123456789012:mfa/ has spaces":         false,
		"arn:aws:iam::123456789012:mfa/":                    false,
		"arn:aws:iam::12345:mfa/alice":                      false,
		"arn:aws:iam::123456789012:u2f/user/alice/key-1":    false,
		"GAKT12345678":                                            false,
		"arn:aws:sts::123456789012:mfa/alice":                     false,
		"xarn:aws:iam::123456789012:mfa/alice":                    false,
		"arn:aws:iam::123456789012:mfa/alice\narn:aws:iam::1:mfa": false,
	} {
		if got := IsVirtualMFADevice(arn); got != want {
			t.Errorf("IsVirtualMFADevice(%q) = %v, want %v", arn, got, want)
		}
	}
}

// How a profile signs in is read from its settings: the first one set.
// How a profile signs in is read from its section of the AWS config file.
func TestProfileKind(t *testing.T) {
	config := `# the AWS CLI's config
[default]
login_session = arn:aws:iam::123456789012:user/alice
region = us-east-1

[profile keys]
region = us-east-1
; login_session = commented out

[profile sso]
sso_session = corp

[profile sso-old]
sso_start_url = https://corp.awsapps.com/start

[profile admin]
role_arn = arn:aws:iam::123456789012:role/Admin
source_profile = keys

[sso-session corp]
sso_start_url = https://corp.awsapps.com/start
`
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", path)
	for profile, want := range map[string]string{"": "aws login", "keys": "", "sso": "SSO", "sso-old": "SSO", "admin": "a role", "missing": "", "corp": ""} {
		if got := ProfileKind(profile); got != want {
			t.Errorf("ProfileKind(%q) = %q, want %q", profile, got, want)
		}
	}
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "none"))
	if got := ProfileKind(""); got != "" {
		t.Errorf("no config file: %q", got)
	}
}

// The AWS CLI's own output goes to stderr: sesh's stdout is for what eval
// reads.
func TestRunCLIInteractive_OutputToStderr(t *testing.T) {
	fakeCLI(t, `echo "Attempting to open your default browser."`)
	var err error
	out := testutil.CaptureStdout(func() { err = RunCLIInteractive("work", "login") })
	if err != nil || out != "" {
		t.Errorf("stdout %q, %v", out, err)
	}
}

// One authenticator app is the profile's device; with several, the key's
// can't be told apart, so none is chosen.
func TestGetFirstMFADevice_SeveralRefused(t *testing.T) {
	fakeCLI(t, `echo '{"MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/old"}, {"SerialNumber": "arn:aws:iam::123456789012:mfa/new"}]}'`)
	if _, err := GetFirstMFADevice(""); err == nil || !strings.Contains(err.Error(), "AWS lists 2 authenticator apps") {
		t.Errorf("GetFirstMFADevice() = %v", err)
	}
}

func TestAccountOf(t *testing.T) {
	for arn, want := range map[string]string{
		"arn:aws:iam::123456789012:user/alice":               "123456789012",
		"arn:aws:sts::123456789012:assumed-role/Admin/alice": "123456789012",
		"arn:aws-us-gov:iam::210987654321:mfa/alice":         "210987654321",
		"not an arn":  "",
		"arn:aws:iam": "",
	} {
		if got := AccountOf(arn); got != want {
			t.Errorf("AccountOf(%q) = %q, want %q", arn, got, want)
		}
	}
}

// A profile ProfileKind takes for access keys is aws login only when the
// AWS CLI says it has no credentials, or no profile by its name; anything
// else keeps it as it was. A kind the config file says isn't asked about,
// and the credentials printed when there are some aren't read.
func TestSignInKind(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config")
	if err := os.WriteFile(config, []byte("[profile sso]\nsso_session = corp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", config)
	asked := filepath.Join(dir, "asked")
	t.Setenv("ASKED", asked)
	for _, tc := range []struct{ name, cli, want string }{
		{"credentials", `printf 'export AWS_ACCESS_KEY_ID=AKIAFAKE\n'`, ""},
		{"none", `echo "aws: [ERROR]: An error occurred (Configuration): Unable to retrieve credentials: no credentials found" >&2; exit 253`, "aws login"},
		{"older wording", `echo "Unable to locate credentials. You can configure credentials by running \"aws login\"." >&2; exit 253`, "aws login"},
		{"no such profile", `echo "aws: [ERROR]: Unable to retrieve credentials: The config profile (work) could not be found" >&2; exit 253`, "aws login"},
		{"another failure", `echo "aws: [ERROR]: [Errno 2] No such file or directory: '/opt/creds'" >&2; exit 255`, ""},
		{"an older CLI", `echo "Unknown configure subcommand 'export-credentials'" >&2; exit 2`, ""},
	} {
		fakeCLI(t, `echo "$@" > "$ASKED"; `+tc.cli)
		if got := SignInKind("work"); got != tc.want {
			t.Errorf("%s: SignInKind = %q, want %q", tc.name, got, tc.want)
		}
		if b, err := os.ReadFile(asked); err != nil || strings.TrimSpace(string(b)) != "configure export-credentials --profile work" { //nolint:gosec // the test's own file
			t.Errorf("%s: the CLI was asked %q (%v)", tc.name, b, err)
		}
	}
	if err := os.Remove(asked); err != nil {
		t.Fatal(err)
	}
	if got := SignInKind("sso"); got != KindSSO {
		t.Errorf("an SSO profile: %q", got)
	}
	if _, err := os.Stat(asked); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the CLI was asked about an SSO profile: %v", err)
	}
}
