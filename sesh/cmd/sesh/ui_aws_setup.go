package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/aws"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/setup"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/tui"
	"github.com/bashhack/sesh/internal/vault"
)

// AWS as the app's setup sees it; tests replace them.
var (
	uiCheckIdentity   = setup.CheckIdentity
	uiListMFADevices  = aws.ListMFADevices
	uiAWSInstalled    = setup.AWSInstalled
	uiAWSProfileNames = func() []string {
		out, err := aws.RunCLI("", "configure", "list-profiles")
		if err != nil {
			return nil
		}
		return strings.Fields(string(out))
	}
)

// uiAWSSetup is sesh aws setup for the app: the same checks, the same
// keys, the same devices, asked one at a time.
type uiAWSSetup struct{}

var _ tui.AWSSetup = uiAWSSetup{}

func (uiAWSSetup) Profiles() []string { return uiAWSProfileNames() }

// Check checks profile as sesh aws setup does before it asks for the key.
func (uiAWSSetup) Check(profile string) (tui.AWSProfile, error) {
	if err := uiAWSInstalled(); err != nil {
		return tui.AWSProfile{}, err
	}
	if err := vault.CheckName("AWS profile", profile); err != nil {
		return tui.AWSProfile{}, err
	}
	k := vault.AWSKey(profile)
	if err := k.Validate(); err != nil {
		return tui.AWSProfile{}, err
	}
	p := tui.AWSProfile{Profile: profile, Kind: awsProfileKind(profile)}
	if p.Kind == "" {
		identity, err := uiCheckIdentity(profile)
		if err != nil {
			return tui.AWSProfile{}, err
		}
		p.Identity, p.Account = identity, aws.AccountOf(identity)
	}
	p.Done = setup.Done(profile, p.Kind)
	return p, nil
}

// Existing is the entry the vault has for profile, and whether it keeps
// earlier keys.
func (uiAWSSetup) Existing(v tui.Vault, profile string) (*vault.Entry, bool, error) {
	u, ok := v.(*uiVault)
	if !ok {
		return nil, false, errors.New("the vault can't be read for the setup")
	}
	keeps := u.store.HistoryKeep() > 0
	switch e, err := u.store.Lookup(vault.AWSKey(profile)); {
	case err == nil:
		return &e, keeps, nil
	case errors.Is(err, vault.ErrNotFound):
		return nil, keeps, nil
	default:
		return nil, false, uiLocked(err)
	}
}

// ReadKey is the key typed, or an otpauth:// link's, which must make AWS's
// codes.
func (uiAWSSetup) ReadKey(typed []byte) ([]byte, error) {
	key, params, err := readTOTPKey(typed)
	if err != nil {
		return nil, err
	}
	if params != nil && !setup.AWSCodes(*params) {
		secure.SecureZeroBytes(key)
		return nil, errors.New("that link makes codes AWS doesn't use (AWS's are 6 digits every 30 seconds, with SHA-1)")
	}
	return key, nil
}

// FromEntry is the key of the TOTP entry src, for k, as setup's e choice
// takes it.
func (uiAWSSetup) FromEntry(v tui.Vault, src, k vault.Key) ([]byte, error) {
	u, ok := v.(*uiVault)
	if !ok {
		return nil, errors.New("the vault can't be read for the setup")
	}
	if err := setup.SourceEntry(u.store, src, k); err != nil {
		return nil, uiLocked(err)
	}
	raw, err := v.Secret(src, "in sesh ui, to set up AWS MFA with it")
	if err != nil {
		return nil, err
	}
	defer secure.SecureZeroBytes(raw)
	key, err := totp.ValidateAndNormalizeSecret(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("%s's key can't make codes: %w", src, err)
	}
	return []byte(key), nil
}

func (uiAWSSetup) Codes(key []byte) (first, second string, err error) {
	return totp.GenerateConsecutiveCodesForTimeBytes(key, time.Now())
}

func (uiAWSSetup) Devices(profile string) ([]string, error) { return uiListMFADevices(profile) }

func (uiAWSSetup) CheckDevice(arn, account string) error { return setup.CheckDevice(arn, account) }

func (uiAWSSetup) KeyOnly(k vault.Key, inHistory bool, why error) string {
	return setup.KeyOnly(k, inHistory, why).Error()
}
