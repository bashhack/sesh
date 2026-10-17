package aws

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
)

// CLIEnv is the environment the AWS CLI runs in for profile: this
// process's, without credentials in variables (inside sesh aws's shell, or
// left from an export), which the CLI would use over the profile's, and
// without SESH_MASTER_PASSWORD, which neither it nor a browser it opens
// needs. For the
// default profile ("") AWS_PROFILE and AWS_DEFAULT_PROFILE go too, so the
// CLI uses the profile named default.
func CLIEnv(profile string) []string {
	drop := []string{"AWS_ACCESS_KEY_ID=", "AWS_SECRET_ACCESS_KEY=", "AWS_SESSION_TOKEN=", "AWS_SECURITY_TOKEN=", "SESH_MASTER_PASSWORD="}
	if profile == "" {
		drop = append(drop, "AWS_PROFILE=", "AWS_DEFAULT_PROFILE=")
	}
	env := os.Environ()
	out := make([]string, 0, len(env))
	for _, e := range env {
		keep := true
		for _, d := range drop {
			if strings.HasPrefix(e, d) {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, e)
		}
	}
	return out
}

// CLIArgs is args with --profile profile after them, when it's named.
func CLIArgs(profile string, args ...string) []string {
	if profile == "" {
		return args
	}
	return append(slices.Clone(args), "--profile", profile)
}

// RunCLI runs the AWS CLI for profile, with nothing on its input, and
// returns what it printed. A failure carries the CLI's own message, which
// says what's wrong (a profile it can't find, an expired token).
func RunCLI(profile string, args ...string) ([]byte, error) {
	cmd := execCommand("aws", CLIArgs(profile, args...)...)
	cmd.Env = CLIEnv(profile)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) { //nolint:modernize // errors.AsType would leave a blank error value, which errcheck's check-blank rejects
			if msg := strings.TrimSpace(string(exitErr.Stderr)); msg != "" {
				return nil, fmt.Errorf("aws %s: %s", strings.Join(args[:min(2, len(args))], " "), msg)
			}
		}
		return nil, fmt.Errorf("aws %s: %w", strings.Join(args[:min(2, len(args))], " "), err)
	}
	return out, nil
}

// ListMFADevices returns the virtual MFA devices (authenticator apps) of
// the IAM user profile signs in as. Security keys and hardware tokens are
// left out: sesh makes codes for an app's key, which they don't have.
func ListMFADevices(profile string) ([]string, error) {
	out, err := RunCLI(profile, "iam", "list-mfa-devices", "--output", "json")
	if err != nil {
		return nil, err
	}
	var parsed ListDevicesResponse
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, fmt.Errorf("read the AWS CLI's list of MFA devices: %w", err)
	}
	var devices []string
	for _, d := range parsed.MFADevices {
		if IsVirtualMFADevice(d.SerialNumber) {
			devices = append(devices, d.SerialNumber)
		}
	}
	return devices, nil
}

// mfaARN is a virtual MFA device's ARN, in any partition (aws, aws-cn,
// aws-us-gov): arn:aws:iam::123456789012:mfa/name, the name in IAM's
// characters, perhaps under a path, which IAM lets hold any printable
// ASCII character.
var mfaARN = regexp.MustCompile(`^arn:aws(-[a-z]+)*:iam::(\d{12}):mfa(/[\x21-\x7f]+)?/[A-Za-z0-9+=,.@_-]+$`)

// IsVirtualMFADevice says whether serial is a virtual MFA device's ARN.
func IsVirtualMFADevice(serial string) bool {
	return mfaARN.MatchString(serial)
}

// SessionCredentialsMessage is what AWS says when get-session-token is
// asked with temporary credentials (aws login, SSO, a role), which it
// gives no MFA session to.
const SessionCredentialsMessage = "Cannot call GetSessionToken with session credentials"

// AccountOf is the account number in an IAM or STS ARN, or "".
func AccountOf(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 || parts[0] != "arn" {
		return ""
	}
	return parts[4]
}

// CallerIdentity is who profile signs in as: its ARN.
func CallerIdentity(profile string) (string, error) {
	out, err := RunCLI(profile, "sts", "get-caller-identity", "--output", "json")
	if err != nil {
		return "", err
	}
	var parsed struct {
		Arn string `json:"Arn"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil || parsed.Arn == "" {
		return "", fmt.Errorf("read the AWS CLI's identity: %q", strings.TrimSpace(string(out)))
	}
	return parsed.Arn, nil
}
