package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/bashhack/sesh/internal/aws"
	"github.com/bashhack/sesh/internal/provider"
	awsProvider "github.com/bashhack/sesh/internal/provider/aws"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/tui"
	"github.com/bashhack/sesh/internal/vault"
)

// uiAWSSignIn is sesh aws --profile for the app, the profile the one whose
// MFA entry is, or would be, k, in three steps, so the app isn't held up:
// how the profile signs in, which may ask the AWS CLI, with the vault let
// go; what the sign-in needs of the vault; and the sign-in, talking to
// AWS with the vault let go again, which gives the shell to open once the
// app has ended. A profile with an IAM user's access keys gets its
// session in the sign-in, so AWS refusing is said in the app; one that
// signs in with aws login or SSO signs in, when it must, once the app has
// ended, since the AWS CLI's sign-in is a terminal program's.
func uiAWSSignIn(app *App, k vault.Key) (tui.AWSVaultStep, error) {
	if os.Getenv("SESH_ACTIVE") == "1" {
		return nil, errors.New("this app is running in a shell sesh opened: exit that shell, then sign in from a new one")
	}
	profile := k.Username
	if k == vault.AWSKey("") {
		profile = "" // the profile named default, as sesh aws signs in with
	}
	kind := awsProfileKind(profile)
	return func(v tui.Vault) (tui.AWSSignInStep, error) {
		u, ok := v.(*uiVault)
		if !ok {
			return nil, errors.New("the vault can't be read for the sign-in")
		}
		// aws login or SSO: nothing of the vault is needed now.
		if kind != "" && kind != aws.KindRole {
			shell := func(release func()) error { return runAWSLogin(app, profile, kind, false, release) }
			return func() (tui.AWSShell, error) { return shell, nil }, nil
		}
		e, err := u.store.Lookup(k)
		has := err == nil
		if err != nil && !errors.Is(err, vault.ErrNotFound) {
			return nil, uiLocked(err)
		}
		if kind == aws.KindRole {
			if has {
				return nil, fmt.Errorf("%s assumes a role (role_arn): the AWS CLI asks for its MFA code itself; Enter on its entry copies the code", awsProfileName(profile))
			}
			return nil, fmt.Errorf("%s assumes a role (role_arn): the AWS CLI asks for its MFA code itself; set up AWS MFA… stores its key, and Enter on its entry then copies the code", awsProfileName(profile))
		}
		if !has {
			return nil, fmt.Errorf("sesh has no MFA key for %s, which signs in with an IAM user's access keys: AWS gives a session for it only with an MFA code; set up AWS MFA… stores the key", awsProfileName(profile))
		}
		if err := newAWSProvider(u.store).ForProfile(profile).ValidateRequest(); err != nil {
			return nil, uiLocked(err)
		}
		secret, err := u.store.Get(k)
		if err != nil {
			return nil, uiLocked(err)
		}
		held := &heldMFA{e: e, secret: secret}
		return func() (tui.AWSShell, error) {
			defer held.wipe()
			p := newAWSProvider(held).ForProfile(profile)
			creds, err := p.GetCredentials()
			if err != nil {
				return nil, err
			}
			signed := &signedIn{Provider: p, creds: creds}
			return func(release func()) error { return app.LaunchSubshell(signed, release) }, nil
		}, nil
	}, nil
}

// envAWSProfile is the profile sesh aws signs in with when it isn't given
// one: AWS_PROFILE, or AWS_DEFAULT_PROFILE.
func envAWSProfile() string {
	if p := os.Getenv("AWS_PROFILE"); p != "" {
		return p
	}
	return os.Getenv("AWS_DEFAULT_PROFILE")
}

// heldMFA is the one entry the AWS sign-in reads, an MFA entry, held so
// the sign-in can talk to AWS with the vault let go: its Lookup and Get.
// The store's other methods aren't there; nothing that holds it calls
// them.
type heldMFA struct {
	vault.Store
	secret []byte
	e      vault.Entry
}

func (h *heldMFA) Lookup(k vault.Key) (vault.Entry, error) {
	if k != h.e.Key {
		return vault.Entry{}, fmt.Errorf("%s: %w", k, vault.ErrNotFound)
	}
	return h.e, nil
}

// Get is a copy of the key, which the caller zeroes.
func (h *heldMFA) Get(k vault.Key) ([]byte, error) {
	if k != h.e.Key {
		return nil, fmt.Errorf("%s: %w", k, vault.ErrNotFound)
	}
	return bytes.Clone(h.secret), nil
}

func (h *heldMFA) wipe() { secure.SecureZeroBytes(h.secret) }

// signedIn is the AWS sign-in with the session the app got: the shell
// opens with it, without the vault, which is closed by then.
type signedIn struct {
	*awsProvider.Provider
	creds provider.Credentials
}

func (s *signedIn) ValidateRequest() error                        { return nil }
func (s *signedIn) GetCredentials() (provider.Credentials, error) { return s.creds, nil }
