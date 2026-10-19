package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/aws"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// stubAWSSetup has the app's setup take profiles to be of kind, signing
// in as identity, with the AWS CLI there or not.
func stubAWSSetup(t *testing.T, kind, identity string, installed error) {
	t.Helper()
	k, id, inst := awsProfileKind, uiCheckIdentity, uiAWSInstalled
	t.Cleanup(func() { awsProfileKind, uiCheckIdentity, uiAWSInstalled = k, id, inst })
	awsProfileKind = func(string) string { return kind }
	uiCheckIdentity = func(string) (string, error) {
		if identity == "" {
			return "", errors.New("AWS couldn't say who it signs in as")
		}
		return identity, nil
	}
	uiAWSInstalled = func() error { return installed }
}

// The app's AWS setup checks as sesh aws setup does: the AWS CLI, the
// name, who an access-key profile signs in as, and the entry sesh has;
// a key, from a link or an entry, must make AWS's codes.
func TestUI_AWSSetup(t *testing.T) {
	env := setupRekeyEnv(t)
	useConfigFile(t, "")
	t.Setenv("SESH_MASTER_PASSWORD", "aws-setup-password-1234")
	populatePasswordStore(t, env, map[string]string{"totp/aws/work": "JBSWY3DPEHPK3PXP", "totp/phone/alice": "JBSWY3DPEHPK3PXP"})
	store, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	eight := vault.Key{Kind: vault.KindTOTP, Service: "bank", Username: "me"}
	if err := store.Save(&vault.Entry{Key: eight, Settings: vault.Settings{TOTP: totp.Params{Digits: 8}}}, []byte("JBSWY3DPEHPK3PXP")); err != nil {
		t.Fatal(err)
	}
	u := newUIVault(store)
	defer u.Close() //nolint:errcheck // test cleanup
	s := uiAWSSetup{}

	stubAWSSetup(t, "", "arn:aws:iam::123456789012:user/alice", errors.New("the AWS CLI isn't installed"))
	if _, err := s.Check("work"); err == nil || !strings.Contains(err.Error(), "isn't installed") {
		t.Errorf("no AWS CLI: %v", err)
	}
	stubAWSSetup(t, "", "arn:aws:iam::123456789012:user/alice", nil)
	p, err := s.Check("work")
	if err != nil || p.Account != "123456789012" || !strings.Contains(p.Done, "AWS MFA is set up for profile work") {
		t.Errorf("work: %+v, %v", p, err)
	}
	if e, keeps, err := s.Existing(u, "work"); err != nil || e == nil || e.Key != vault.AWSKey("work") || keeps != (store.HistoryKeep() > 0) {
		t.Errorf("work's entry: %+v, keeps %v, %v", e, keeps, err)
	}
	if e, _, err := s.Existing(u, "new"); err != nil || e != nil {
		t.Errorf("a new profile's entry: %+v, %v", e, err)
	}
	stubAWSSetup(t, "", "", nil)
	if _, err := s.Check("work"); err == nil || !strings.Contains(err.Error(), "couldn't say who") {
		t.Errorf("AWS can't say who: %v", err)
	}
	stubAWSSetup(t, aws.KindLogin, "", nil)
	if p, err := s.Check("work"); err != nil || p.Identity != "" || !strings.Contains(p.Done, "signs in with aws login") {
		t.Errorf("aws login, AWS not asked: %+v, %v", p, err)
	}
	if _, err := s.Check("bad\tname"); err == nil {
		t.Error("a profile name with a tab was taken")
	}

	if key, err := s.ReadKey([]byte("otpauth://totp/AWS:alice?secret=JBSWY3DPEHPK3PXP&issuer=AWS")); err != nil || string(key) != "JBSWY3DPEHPK3PXP" {
		t.Errorf("a link: %q, %v", key, err)
	}
	if _, err := s.ReadKey([]byte("otpauth://totp/AWS:alice?secret=JBSWY3DPEHPK3PXP&digits=8")); err == nil || !strings.Contains(err.Error(), "codes AWS doesn't use") {
		t.Errorf("an 8-digit link: %v", err)
	}
	phone, work := vault.Key{Kind: vault.KindTOTP, Service: "phone", Username: "alice"}, vault.AWSKey("work")
	if key, err := s.FromEntry(u, phone, work); err != nil || string(key) != "JBSWY3DPEHPK3PXP" {
		t.Errorf("from an entry: %q, %v", key, err)
	}
	if _, err := s.FromEntry(u, eight, work); err == nil || !strings.Contains(err.Error(), "codes AWS doesn't use") {
		t.Errorf("from an 8-digit entry: %v", err)
	}
	if _, err := s.FromEntry(u, work, work); err == nil || !strings.Contains(err.Error(), "the entry being set up") {
		t.Errorf("from itself: %v", err)
	}
	if log := mustRun(t, runAudit); !strings.Contains(log, "to set up AWS MFA with it") {
		t.Errorf("the entry's key read isn't in the audit log:\n%s", log)
	}
}
