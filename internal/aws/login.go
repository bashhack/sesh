package aws

import (
	"os"
	"path/filepath"
	"strings"
)

// The kinds of profile ProfileKind tells apart, by how they sign in.
const (
	KindLogin = "aws login"
	KindSSO   = "SSO"
	KindRole  = "a role"
)

// LoginArgs is the AWS CLI command that signs a profile of kind in, in the
// browser, and whether there is one: aws login, or aws sso login. remote
// is for a computer without a browser of its own (over SSH): the CLI then
// shows a link to open elsewhere, and, for aws login, asks for the code
// that page gives.
func LoginArgs(kind string, remote bool) ([]string, bool) {
	switch kind {
	case KindLogin:
		if remote {
			return []string{"login", "--remote"}, true
		}
		return []string{"login"}, true
	case KindSSO:
		if remote {
			return []string{"sso", "login", "--no-browser"}, true
		}
		return []string{"sso", "login"}, true
	}
	return nil, false
}

// RunCLIInteractive runs the AWS CLI for profile on this terminal, as
// aws login asks questions and shows links there. What it prints goes to
// stderr, so sesh's stdout keeps only what's meant for it (the exports
// eval reads).
func RunCLIInteractive(profile string, args ...string) error {
	cmd := execCommand("aws", CLIArgs(profile, args...)...)
	cmd.Env = CLIEnv(profile)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
	return cmd.Run()
}

// ProfileKind says how profile signs in, when it isn't with an IAM user's
// access keys: "aws login" (a login_session), "SSO" (an sso_session or
// sso_start_url), or "a role" (a role_arn); "" otherwise, or when the
// config file can't be read. Those give temporary credentials, which AWS
// gives no MFA session to. It reads the AWS CLI's config file
// (AWS_CONFIG_FILE, or ~/.aws/config) itself, which is quicker than
// starting the CLI to ask.
func ProfileKind(profile string) string {
	path := os.Getenv("AWS_CONFIG_FILE")
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		path = filepath.Join(home, ".aws", "config")
	}
	b, err := os.ReadFile(path) //nolint:gosec // the AWS CLI's own config file
	if err != nil {
		return ""
	}
	return profileKindIn(string(b), profile)
}

// profileKindIn is ProfileKind for a config file's text: the section for
// profile is [profile NAME], or [default] (or [profile default]) for the
// default profile.
func profileKindIn(config, profile string) string {
	if profile == "" {
		profile = "default"
	}
	settings := map[string]string{}
	in := false
	for line := range strings.Lines(config) {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || line[0] == '#' || line[0] == ';':
		case line[0] == '[':
			name := strings.TrimSpace(strings.Trim(line, "[]"))
			in = name == "profile "+profile || (profile == "default" && name == "default")
			if p, ok := strings.CutPrefix(name, "profile "); ok {
				in = strings.TrimSpace(p) == profile
			}
		case in:
			if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(v) != "" {
				settings[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
	}
	switch {
	case settings["login_session"] != "":
		return KindLogin
	case settings["sso_session"] != "" || settings["sso_start_url"] != "":
		return KindSSO
	case settings["role_arn"] != "":
		return KindRole
	}
	return ""
}

// SignInKind is ProfileKind, but a profile it takes for an IAM user's
// access keys that the AWS CLI says has no credentials at all (none of
// any kind, or no profile by that name) is "aws login": that's how such a
// profile signs in, and aws login writes the profile's login_session the
// first time. Whether there are any is the CLI's own answer, not read from
// its files here, so a profile with credentials however written keeps its
// way in.
func SignInKind(profile string) string {
	if kind := ProfileKind(profile); kind != "" {
		return kind
	}
	if noCredentials(profile) {
		return KindLogin
	}
	return ""
}

// noCredentialsMessages are what the AWS CLI says of a profile with no
// credentials, or none by its name.
var noCredentialsMessages = []string{"no credentials found", "Unable to locate credentials", "could not be found"}

// noCredentials says whether the AWS CLI says profile has no credentials,
// asked with aws configure export-credentials, which works them out as
// the CLI does for any command; what it prints, the credentials when
// there are some, is thrown away. Anything else it says (or the CLI not
// being there) is no.
var noCredentials = func(profile string) bool {
	cmd := execCommand("aws", CLIArgs(profile, "configure", "export-credentials")...)
	cmd.Env = CLIEnv(profile)
	var stderr strings.Builder
	cmd.Stderr = &stderr // stdout, unset, goes nowhere
	if cmd.Run() == nil {
		return false
	}
	for _, m := range noCredentialsMessages {
		if strings.Contains(stderr.String(), m) {
			return true
		}
	}
	return false
}
