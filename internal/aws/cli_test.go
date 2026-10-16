package aws

import (
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// fakeCLI makes execCommand run script in sh in place of the AWS CLI.
func fakeCLI(t *testing.T, script string) {
	t.Helper()
	orig := execCommand
	t.Cleanup(func() { execCommand = orig })
	execCommand = func(string, ...string) *exec.Cmd { return exec.Command("sh", "-c", script) }
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
	has := func(env []string, name string) bool {
		return slices.ContainsFunc(env, func(e string) bool { return strings.HasPrefix(e, name+"=") })
	}
	for _, profile := range []string{"", "work"} {
		env := CLIEnv(profile)
		for _, name := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"} {
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
