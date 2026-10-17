package aws

import (
	"os"
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
// aws login asks questions and shows links there.
func RunCLIInteractive(profile string, args ...string) error {
	cmd := execCommand("aws", CLIArgs(profile, args...)...)
	cmd.Env = CLIEnv(profile)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}
