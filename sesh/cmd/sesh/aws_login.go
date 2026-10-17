package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/aws"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/shell"
	"github.com/bashhack/sesh/internal/subshell"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// The AWS CLI as sesh aws's sign-in sees it; tests replace them.
var (
	awsProfileKind    = aws.ProfileKind
	awsCallerIdentity = aws.CallerIdentity
	awsRunLogin       = aws.RunCLIInteractive
)

// credentialVars are the variables that hold AWS credentials, which the
// AWS CLI uses over a profile's.
var credentialVars = []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"}

// runAWSLogin is sesh aws for a profile that signs in with aws login or
// SSO. Its credentials last minutes at a time, and the AWS CLI renews
// them from the session (for up to 12 hours with aws login), so the shell
// gets the profile, not the credentials. When the session has ended, sesh
// signs in again with the AWS CLI, keeping the MFA code it holds for the
// profile on the clipboard (or printing it) while the browser asks.
func runAWSLogin(app *App, profile, kind string, noSubshell bool) error {
	if kind == aws.KindRole {
		return fmt.Errorf("%s assumes a role (role_arn): the AWS CLI asks for its MFA code itself; sesh aws%s --clip copies the code", awsProfileName(profile), awsProfileFlag(profile))
	}
	identity, err := awsCallerIdentity(profile)
	if err != nil {
		if identity, err = signIn(app, profile, kind); err != nil {
			return err
		}
	}
	fmt.Fprintf(app.Stderr, "✅ %s signs in as %s, through %s\n", strings.ToUpper(awsProfileName(profile)[:1])+awsProfileName(profile)[1:], identity, kind) //nolint:errcheck // a status line
	p := &awsLoginProvider{profile: profile}
	if noSubshell {
		return p.printExports(app)
	}
	return app.LaunchSubshell(p, nil)
}

// signIn runs aws login (or aws sso login) for profile, with the MFA code
// sesh holds for it, if any, on the clipboard while it runs, and returns
// who the profile then signs in as.
func signIn(app *App, profile, kind string) (string, error) {
	args, _ := aws.LoginArgs(kind, overSSH())
	fmt.Fprintf(app.Stderr, "🔐 %s's session has ended: signing in with aws %s\n", strings.ToUpper(awsProfileName(profile)[:1])+awsProfileName(profile)[1:], strings.Join(args, " ")) //nolint:errcheck // a status line
	stop, err := offerMFACode(app, profile)
	if err != nil {
		return "", err
	}
	err = awsRunLogin(profile, args...)
	stop()
	if err != nil {
		return "", fmt.Errorf("aws %s didn't sign %s in: %w", strings.Join(args, " "), awsProfileName(profile), err)
	}
	identity, err := awsCallerIdentity(profile)
	if err != nil {
		return "", fmt.Errorf("signed in, but AWS still can't say who %s is: %w", awsProfileName(profile), err)
	}
	return identity, nil
}

// offerMFACode puts the MFA code sesh holds for profile on the clipboard,
// and a fresh one each time it changes, until the returned stop is called;
// where nothing can be copied (over SSH), it prints the code. Without an
// MFA key for the profile, it does nothing: the browser asks for the code
// as it would anyway. The vault is opened only for this, and closed before
// it returns.
func offerMFACode(app *App, profile string) (stop func(), err error) {
	stop = func() {}
	cfg, err := settings()
	if err != nil {
		return stop, err
	}
	if vaultMissing(cfg.DBPath.Value) {
		return stop, nil // no vault, so no MFA key to offer
	}
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		return stop, err
	}
	defer closeAuditStore(store)
	k := vault.AWSKey(profile)
	e, err := store.Lookup(k)
	if errors.Is(err, vault.ErrNotFound) {
		return stop, nil
	}
	if err != nil {
		return stop, err
	}
	secret, err := store.Get(k)
	if err != nil {
		return stop, err
	}
	params := e.Settings.TOTP
	clock := app.TimeNow
	if clock == nil {
		clock = time.Now
	}
	code := func(at time.Time) (string, int, error) {
		c, err := totp.CodeAt(secret, params, at)
		return c, totp.SecondsLeft(params, at), err
	}
	now := clock()
	first, left, err := code(now)
	if err != nil {
		secure.SecureZeroBytes(secret)
		return stop, err
	}
	// Where nothing can be copied (over SSH, or the copy fails), the code
	// is printed instead: the sign-in goes ahead either way.
	canCopy := app.ClipboardCheck == nil || app.ClipboardCheck() == nil
	if canCopy {
		if err := app.ClipboardCopy(first); err != nil {
			fmt.Fprintf(app.Stderr, "warning: can't copy the MFA code: %v\n", err) //nolint:errcheck // a warning
			canCopy = false
		}
	}
	if !canCopy {
		secure.SecureZeroBytes(secret)
		fmt.Fprintf(app.Stderr, "🔑 MFA code for the sign-in: %s (for %ds more; sesh code %s gives the next)\n", first, left, shell.Quote(k.String())) //nolint:errcheck // a status line
		return stop, nil
	}
	fmt.Fprintf(app.Stderr, "🔑 The MFA code is on the clipboard, kept current while you sign in: paste it when AWS asks\n") //nolint:errcheck // a status line
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		defer secure.SecureZeroBytes(secret)
		for {
			select {
			case <-done:
				return
			case <-time.After(time.Duration(left)*time.Second + 100*time.Millisecond):
			}
			var c string
			if c, left, err = code(clock()); err != nil || app.ClipboardCopy(c) != nil {
				return
			}
		}
	}()
	return func() { close(done); <-finished }, nil
}

// awsLoginProvider is the shell sesh aws opens for a profile that signs
// in with aws login or SSO: it has the profile (none, for the default
// profile), and no credentials of its own, so the AWS CLI's renewed ones
// are used.
type awsLoginProvider struct{ profile string }

var (
	_ provider.ServiceProvider  = (*awsLoginProvider)(nil)
	_ provider.SubshellProvider = (*awsLoginProvider)(nil)
)

func (p *awsLoginProvider) Name() string                      { return "aws" }
func (p *awsLoginProvider) SetupFlags(provider.FlagSet) error { return nil }
func (p *awsLoginProvider) ValidateRequest() error            { return nil }
func (p *awsLoginProvider) GetFlagInfo() []provider.FlagInfo  { return nil }
func (p *awsLoginProvider) GetClipboardValue() (provider.Credentials, error) {
	return provider.Credentials{}, errors.New("sesh aws --clip copies a code from the profile's MFA entry")
}

// GetCredentials is the profile, for the shell's AWS_PROFILE.
func (p *awsLoginProvider) GetCredentials() (provider.Credentials, error) {
	vars := map[string]string{}
	if p.profile != "" {
		vars["AWS_PROFILE"] = p.profile
	}
	return provider.Credentials{Provider: "aws", Variables: vars}, nil
}

// NewSubshellConfig is the shell, with the profile, without credentials in
// variables (they'd be used over the profile's), and, for the default
// profile, without AWS_PROFILE or AWS_DEFAULT_PROFILE naming another.
func (p *awsLoginProvider) NewSubshellConfig(creds *provider.Credentials) any {
	unset := credentialVars
	if p.profile == "" {
		unset = append(append([]string{}, credentialVars...), "AWS_PROFILE", "AWS_DEFAULT_PROFILE")
	}
	return subshell.Config{
		ServiceName:     "aws",
		Variables:       creds.Variables,
		ShellCustomizer: aws.NewCustomizer(),
		Unset:           unset,
	}
}

// printExports is sesh aws --no-subshell for the profile: the lines that
// make a shell use it, to eval.
func (p *awsLoginProvider) printExports(app *App) error {
	lines := "unset " + strings.Join(credentialVars, " ") + "\n"
	if p.profile == "" {
		lines += "unset AWS_PROFILE AWS_DEFAULT_PROFILE\n"
	} else {
		lines += "export AWS_PROFILE=" + shell.Quote(p.profile) + "\n"
	}
	_, err := fmt.Fprint(app.Stdout, lines)
	return err
}

// awsProfileName is how a profile is named in what sesh aws says.
func awsProfileName(profile string) string {
	if profile == "" {
		return "the default profile"
	}
	return "profile " + profile
}

// awsProfileFlag is --profile P for a named profile.
func awsProfileFlag(profile string) string {
	if profile == "" {
		return ""
	}
	return " --profile " + shell.Quote(profile)
}
