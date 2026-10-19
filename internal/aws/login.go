package aws

import (
	"errors"
	"io/fs"
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
// sso_start_url), or "a role" (a role_arn); "" otherwise, or when a file
// can't be read. Those give temporary credentials, which AWS gives no MFA
// session to. A profile with no credentials at all (no access keys, no
// credential_process or web identity token, in either file, or no section
// of its own) is "aws login" too: aws login is how such a profile signs
// in, and it writes the profile's login_session the first time. It reads
// the AWS CLI's config and credentials files (AWS_CONFIG_FILE and
// AWS_SHARED_CREDENTIALS_FILE, or ~/.aws/config and ~/.aws/credentials)
// itself, which is quicker than starting the CLI to ask; credentials in
// variables don't count, as sesh runs the CLI without them (CLIEnv).
func ProfileKind(profile string) string {
	config, ok := readCLIFile("AWS_CONFIG_FILE", "config")
	if !ok {
		return ""
	}
	creds, ok := readCLIFile("AWS_SHARED_CREDENTIALS_FILE", "credentials")
	if !ok {
		return ""
	}
	return profileKindIn(config, creds, profile)
}

// readCLIFile is the text of the AWS CLI's file that env names, or of
// ~/.aws/name; "" for a file that isn't there, and false for one that
// can't be read.
func readCLIFile(env, name string) (string, bool) {
	path := os.Getenv(env)
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", false
		}
		path = filepath.Join(home, ".aws", name)
	}
	b, err := os.ReadFile(path) //nolint:gosec // the AWS CLI's own file
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "", true
	case err != nil:
		return "", false
	}
	return string(b), true
}

// profileKindIn is ProfileKind for the config and credentials files' text.
func profileKindIn(config, creds, profile string) string {
	conf := sectionOf(config, profile, true)
	switch {
	case conf["login_session"] != "":
		return KindLogin
	case conf["sso_session"] != "" || conf["sso_start_url"] != "":
		return KindSSO
	case conf["role_arn"] != "":
		return KindRole
	case hasCredentials(conf) || hasCredentials(sectionOf(creds, profile, false)):
		return ""
	}
	return KindLogin
}

// hasCredentials says whether a profile's settings give it credentials of
// its own: access keys, or a process or web identity token that makes
// them.
func hasCredentials(settings map[string]string) bool {
	return settings["aws_access_key_id"] != "" || settings["credential_process"] != "" || settings["web_identity_token_file"] != ""
}

// sectionOf is the settings of profile's section in an AWS CLI file's
// text: in the config file (inConfig) [profile NAME], or [default] (or
// [profile default]) for the default profile; in the credentials file,
// [NAME].
func sectionOf(text, profile string, inConfig bool) map[string]string {
	if profile == "" {
		profile = "default"
	}
	settings := map[string]string{}
	in := false
	for line := range strings.Lines(text) {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || line[0] == '#' || line[0] == ';':
		case line[0] == '[':
			name := strings.TrimSpace(strings.Trim(line, "[]"))
			p, named := strings.CutPrefix(name, "profile ")
			switch {
			case !inConfig:
				in = name == profile
			case named:
				in = strings.TrimSpace(p) == profile
			default:
				in = profile == "default" && name == "default"
			}
		case in:
			if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(v) != "" {
				settings[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
	}
	return settings
}
