package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/aws"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/shell"
	"github.com/bashhack/sesh/internal/subshell"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// The AWS CLI as sesh aws's sign-in sees it; tests replace them.
var (
	awsProfileKind    = aws.SignInKind
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
// signs in again with the AWS CLI, offering the MFA code it holds for the
// profile while the browser asks. Inside a shell sesh aws opened, it signs
// in if it must, and opens no other. release, when set, is called once
// the shell no longer needs the vault, before it starts.
func runAWSLogin(app *App, profile, kind string, noSubshell bool, release func()) error {
	if kind == aws.KindRole {
		return fmt.Errorf("%s assumes a role (role_arn): the AWS CLI asks for its MFA code itself; sesh aws%s --clip copies the code", awsProfileName(profile), awsProfileFlag(profile))
	}
	nested := !noSubshell && os.Getenv("SESH_ACTIVE") == "1"
	identity, err := awsCallerIdentity(profile)
	if err != nil {
		if identity, err = signIn(app, profile, kind, err); err != nil {
			return err
		}
	} else if nested {
		return errors.New("already in a sesh environment, and the session still works: nested sessions are not supported")
	}
	fmt.Fprintf(app.Stderr, "✅ %s signs in as %s, through %s\n", capitalizedName(profile), identity, kind) //nolint:errcheck // a status line
	p := &awsLoginProvider{profile: profile}
	switch {
	case noSubshell:
		return p.printExports(app)
	case nested:
		_, err := fmt.Fprintln(app.Stderr, "Signed in again: this shell, sesh's already, goes on with the renewed session.")
		return err
	}
	return app.LaunchSubshell(p, release)
}

// signIn runs aws login (or aws sso login) for profile, offering the MFA
// code sesh holds for it, if any, while it runs, and returns who the
// profile then signs in as. why is how the session was found not to work.
func signIn(app *App, profile, kind string, why error) (string, error) {
	args, _ := aws.LoginArgs(kind, overSSH())
	fmt.Fprintf(app.Stderr, "🔐 %s's session doesn't work (%s): signing in with aws %s\n", capitalizedName(profile), firstLine(why), strings.Join(args, " ")) //nolint:errcheck // a status line
	stop := offerMFACode(app, profile)
	err := awsRunLogin(profile, args...)
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

// firstLine is err's message up to its first line break: the reason, short.
func firstLine(err error) string {
	msg, _, _ := strings.Cut(strings.TrimSpace(err.Error()), "\n")
	return msg
}

// capitalizedName is awsProfileName, starting with a capital.
func capitalizedName(profile string) string {
	n := awsProfileName(profile)
	return strings.ToUpper(n[:1]) + n[1:]
}

// offerMFACode offers the MFA code sesh holds for profile until the
// returned stop is called: on the clipboard, with each new code put there
// as the last runs out, as long as the clipboard still holds sesh's (so a
// password copied meanwhile isn't replaced); printed instead where it
// can't be copied (over SSH, the clipboard is the remote computer's). The
// vault is unlocked only when it has an MFA key for the profile, and
// closed before this returns; anything that keeps the code from being
// offered is said, and the sign-in goes ahead without it.
func offerMFACode(app *App, profile string) (stop func()) {
	stop = func() {}
	k := vault.AWSKey(profile)
	secret, params, err := readMFAKey(k)
	if err != nil {
		fmt.Fprintf(app.Stderr, "warning: the MFA code can't be offered: %v\n", err) //nolint:errcheck // a warning
		return stop
	}
	if secret == nil {
		// No MFA key for the profile: the browser asks as usual.
		fmt.Fprintf(app.Stderr, "🔑 sesh has no MFA key for %s (sesh aws setup%s stores one), so no code is copied: if the sign-in asks for an MFA code, it's your MFA device's\n", awsProfileName(profile), awsProfileFlag(profile)) //nolint:errcheck // a status line
		return stop
	}
	clock := app.TimeNow
	if clock == nil {
		clock = time.Now
	}
	code := func(at time.Time) (string, int, error) {
		c, err := totp.CodeAt(secret, params, at)
		return c, totp.SecondsLeft(params, at), err
	}
	first, left, err := code(clock())
	if err != nil {
		secure.SecureZeroBytes(secret)
		fmt.Fprintf(app.Stderr, "warning: the MFA code can't be offered: %v\n", err) //nolint:errcheck // a warning
		return stop
	}
	printCode := func(c string, left int) {
		fmt.Fprintf(app.Stderr, "🔑 MFA code for the sign-in: %s (for %ds more; sesh code %s gives the next)\n", c, left, shell.Quote(k.String())) //nolint:errcheck // a status line
	}
	copyFor := app.ClipboardCopyFor
	if copyFor == nil {
		copyFor = func(text string, _ time.Duration) error { return app.ClipboardCopy(text) }
	}
	canCopy := !overSSH() && (app.ClipboardCheck == nil || app.ClipboardCheck() == nil)
	if canCopy {
		if err := copyFor(first, time.Duration(left)*time.Second); err != nil {
			fmt.Fprintf(app.Stderr, "warning: can't copy the MFA code: %v\n", err) //nolint:errcheck // a warning
			canCopy = false
		}
	}
	if !canCopy {
		secure.SecureZeroBytes(secret)
		printCode(first, left)
		return stop
	}
	fmt.Fprintln(app.Stderr, "🔑 The MFA code is on the clipboard, kept current while you sign in: paste it when AWS asks") //nolint:errcheck // a status line
	done := make(chan struct{})
	finished := make(chan struct{})
	go func(last string, wait int) {
		defer close(finished)
		defer secure.SecureZeroBytes(secret)
		for {
			select {
			case <-done:
				return
			case <-time.After(time.Duration(wait)*time.Second + 100*time.Millisecond):
			}
			if app.ClipboardRead != nil {
				if held, err := app.ClipboardRead(); err != nil || strings.TrimSpace(held) != last {
					return // something else is on the clipboard now: it's left there
				}
			}
			c, l, err := code(clock())
			if err != nil {
				return
			}
			if err := copyFor(c, time.Duration(l)*time.Second); err != nil {
				printCode(c, l)
				return
			}
			last, wait = c, l
		}
	}(first, left)
	return func() { close(done); <-finished }
}

// readMFAKey reads the MFA key the vault holds at k, and its code settings;
// nil, with no error, when there's no vault or no such entry. Whether
// there's one is looked up without unlocking the vault (names aren't
// encrypted), so a profile without one never asks for the master password.
func readMFAKey(k vault.Key) ([]byte, totp.Params, error) {
	cfg, err := settings()
	if err != nil {
		return nil, totp.Params{}, err
	}
	if vaultMissing(cfg.DBPath.Value) {
		return nil, totp.Params{}, nil
	}
	meta, err := database.Open(cfg.DBPath.Value, nil)
	if err != nil {
		return nil, totp.Params{}, err
	}
	e, err := meta.Lookup(k)
	_ = meta.Close() //nolint:errcheck // a read; the unlocked store below is what's used
	if errors.Is(err, vault.ErrNotFound) {
		return nil, totp.Params{}, nil
	}
	if err != nil {
		return nil, totp.Params{}, err
	}
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		return nil, totp.Params{}, err
	}
	defer closeAuditStore(store)
	secret, err := store.Get(k)
	if err != nil {
		return nil, totp.Params{}, err
	}
	return secret, e.Settings.TOTP, nil
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
// variables (they'd be used over the profile's) or AWS_DEFAULT_PROFILE,
// and, for the default profile, without AWS_PROFILE naming another.
func (p *awsLoginProvider) NewSubshellConfig(creds *provider.Credentials) any {
	// AWS_DEFAULT_PROFILE goes for a named profile too: Python's AWS SDK
	// (boto3) reads it before AWS_PROFILE.
	unset := append(append([]string{}, credentialVars...), "AWS_DEFAULT_PROFILE")
	if p.profile == "" {
		unset = append(unset, "AWS_PROFILE")
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
	lines := "unset " + strings.Join(credentialVars, " ") + " AWS_DEFAULT_PROFILE\n"
	if p.profile == "" {
		lines += "unset AWS_PROFILE\n"
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
