package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/bashhack/sesh/internal/aws"
	"github.com/bashhack/sesh/internal/provider"
	awsProvider "github.com/bashhack/sesh/internal/provider/aws"
	"github.com/bashhack/sesh/internal/tui"
	"github.com/bashhack/sesh/internal/vault"
)

// uiAWSSignIn is sesh aws --profile for the app, the profile the one whose
// MFA entry k is: as far as it goes with the app open, and the shell to
// open once the app has ended. A profile with an IAM user's access keys
// gets its session now, so AWS refusing it is said in the app; one that
// signs in with aws login or SSO signs in, when it must, once the app has
// ended, since the AWS CLI's sign-in is a terminal program's.
func uiAWSSignIn(app *App, v tui.Vault, k vault.Key) (func(release func()) error, error) {
	if os.Getenv("SESH_ACTIVE") == "1" {
		return nil, errors.New("this app is running in a shell sesh opened: exit that shell, then sign in from a new one")
	}
	profile := k.Username
	if k == vault.AWSKey("") {
		profile = "" // the default profile, as sesh aws without --profile
	}
	switch kind := awsProfileKind(profile); kind {
	case "":
	case aws.KindRole:
		return nil, fmt.Errorf("%s assumes a role (role_arn): the AWS CLI asks for its MFA code itself; Enter copies the code", awsProfileName(profile))
	default:
		return func(release func()) error { return runAWSLogin(app, profile, kind, false, release) }, nil
	}
	u, ok := v.(*uiVault)
	if !ok {
		return nil, errors.New("the vault can't be read for the sign-in")
	}
	p := newAWSProvider(u.store).ForProfile(profile)
	if err := p.ValidateRequest(); err != nil {
		return nil, uiLocked(err)
	}
	creds, err := p.GetCredentials()
	if err != nil {
		return nil, uiLocked(err)
	}
	signed := &signedIn{Provider: p, creds: creds}
	return func(release func()) error { return app.LaunchSubshell(signed, release) }, nil
}

// signedIn is the AWS sign-in with the session the app got: the shell
// opens with it, without the vault, which is closed by then.
type signedIn struct {
	*awsProvider.Provider
	creds provider.Credentials
}

func (s *signedIn) ValidateRequest() error                        { return nil }
func (s *signedIn) GetCredentials() (provider.Credentials, error) { return s.creds, nil }
