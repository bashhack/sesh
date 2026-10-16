package main

import (
	"errors"
	"flag"
	"fmt"

	"github.com/bashhack/sesh/internal/aws"
	"github.com/bashhack/sesh/internal/clipboard"
	awsProvider "github.com/bashhack/sesh/internal/provider/aws"
	"github.com/bashhack/sesh/internal/setup"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

const awsUsage = `Usage:
  sesh aws [--profile P] [--no-subshell]   Sign in with your MFA code, in a shell with the session's credentials
                                           (--no-subshell prints them, to eval)
  sesh aws --clip [--profile P]            Copy the MFA code for the AWS console
  sesh aws setup [--profile P]             Store a profile's MFA key: from a QR code on screen, or typed

The profile's MFA entry is a TOTP entry named aws, with the profile as its
username: sesh list totp shows it.`

// newAWSProvider is the AWS sign-in over store; tests replace it.
var newAWSProvider = func(store vault.Store) *awsProvider.Provider {
	return awsProvider.NewProvider(aws.NewDefaultProvider(), store, totp.NewDefaultProvider())
}

// addAWSFlags defines sesh aws's flags on fs: --clip, and the AWS
// provider's, which it's made over the vault with once they're known to
// be right.
func addAWSFlags(fs *flag.FlagSet) (clip *bool, flags *awsProvider.Provider, err error) {
	clip = fs.Bool("clip", false, "Copy the MFA code for the AWS console")
	flags = newAWSProvider(nil)
	err = flags.SetupFlags(fs)
	return clip, flags, err
}

// runAWS is sesh aws: AWS sign-in with the MFA key in the vault.
func runAWS(app *App, args []string) error {
	if len(args) > 0 && isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, awsUsage)
		return err
	}
	fs := flag.NewFlagSet("aws", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	clip, flags, err := addAWSFlags(fs)
	if err != nil {
		return err
	}
	var p *awsProvider.Provider
	fs.Usage = func() { fmt.Fprintln(app.Stderr, awsUsage) } //nolint:errcheck // usage text
	words, err := parseAnywhere(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	setupAsked := len(words) == 1 && words[0] == "setup"
	switch {
	case len(words) > 0 && !setupAsked:
		return fmt.Errorf("sesh aws takes setup, or flags, not %q", words[0])
	case setupAsked && *clip:
		return errors.New("--clip copies a code; sesh aws setup stores the key it comes from")
	case !setupAsked && !flags.Filing().IsZero():
		return errors.New("--folder and --tag file the entry sesh aws setup stores")
	}
	// Copying, the clipboard is checked before the vault is unlocked.
	if *clip && app.ClipboardCheck != nil {
		if err := app.ClipboardCheck(); err != nil {
			if errors.Is(err, clipboard.ErrNoDisplay) {
				return fmt.Errorf("can't copy: %w; %s", err, insteadOfClip(flags))
			}
			return fmt.Errorf("can't copy: %w", err)
		}
	}

	cfg, err := settings()
	if err != nil {
		return err
	}
	// Setup's first entry makes the vault, as a first run does.
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	p = flags.WithStore(store)
	if setupAsked {
		return setup.NewAWSSetupHandler(store).Setup(p.GetProfile(), p.Filing())
	}
	switch {
	case *clip:
		return app.CopyToClipboard(p)
	case p.ShouldUseSubshell():
		return app.LaunchSubshell(p)
	}
	return app.GenerateCredentials(p)
}
