package setup

import (
	"bufio"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/qrcode"
	"github.com/bashhack/sesh/internal/testutil"
	"github.com/bashhack/sesh/internal/vault"
)

const (
	testSecret = "JBSWY3DPEHPK3PXP"
	testDevice = "arn:aws:iam::123456789012:mfa/alice"
	testUser   = "arn:aws:iam::123456789012:user/alice"
)

// fakeAWS is the AWS CLI as the setup sees it: who a profile signs in as,
// and the devices it lists, each call taking the next answer.
type fakeAWS struct {
	identity    string
	identityErr error
	listings    [][]string // one per list-mfa-devices call; the last repeats
	listErr     error
	profiles    []string // the profile each call was for
}

// stub replaces the setup's seams for one test: a terminal, the AWS CLI
// installed and answering as aws says, the secret key typed as typed,
// and screen capture as screen says.
func stub(t *testing.T, aws *fakeAWS, typed string, screen bool) {
	t.Helper()
	origs := []func(){
		restore(&awsInstalled), restore(&callerIdentity), restore(&listMFADevices), restore(&readPassword),
		restore(&scanQRCode), restore(&readQRImage), restore(&stdinIsTerminal), restore(&timeNow),
		restore(&screenCapture), restore(&homeDir),
	}
	t.Cleanup(func() {
		for _, o := range origs {
			o()
		}
	})
	awsInstalled = func() error { return nil }
	stdinIsTerminal = func() bool { return true }
	timeNow = func() time.Time { return time.Date(2026, 10, 16, 12, 0, 5, 0, time.UTC) }
	screenCapture = screen
	homeDir = func() (string, error) { return "/home/alice", nil }
	callerIdentity = func(profile string) (string, error) {
		aws.profiles = append(aws.profiles, profile)
		if aws.identityErr != nil {
			return "", aws.identityErr
		}
		return aws.identity, nil
	}
	listMFADevices = func(profile string) ([]string, error) {
		aws.profiles = append(aws.profiles, profile)
		if aws.listErr != nil {
			return nil, aws.listErr
		}
		if len(aws.listings) == 0 {
			return nil, nil
		}
		l := aws.listings[0]
		if len(aws.listings) > 1 {
			aws.listings = aws.listings[1:]
		}
		return l, nil
	}
	readPassword = func(int) ([]byte, error) { return []byte(typed), nil }
	scanQRCode = func() (qrcode.TOTPInfo, error) { return qrcode.TOTPInfo{Secret: testSecret}, nil }
	readQRImage = func(path string) (qrcode.TOTPInfo, error) {
		if path != "/home/alice/aws.png" {
			return qrcode.TOTPInfo{}, errors.New("open " + path + ": no such file or directory")
		}
		return qrcode.TOTPInfo{Secret: testSecret}, nil
	}
}

// restore saves *v and returns what puts it back.
func restore[T any](v *T) func() {
	old := *v
	return func() { *v = old }
}

func defaultAWS() *fakeAWS {
	return &fakeAWS{identity: testUser, listings: [][]string{{testDevice}}}
}

// run is a setup over store with input typed, for profile; it returns
// what the setup printed and its error.
func run(store vault.Store, profile, input string, filing vault.Filing) (string, error) {
	h := &AWSSetupHandler{store: store, reader: bufio.NewReader(strings.NewReader(input))}
	var err error
	out := testutil.CaptureStdout(func() { err = h.Setup(profile, filing) })
	return out, err
}

// countingSave is a store whose Save fails from the call numbered failAt.
type countingSave struct {
	*vault.MemStore
	calls, failAt int
}

func (s *countingSave) Save(e *vault.Entry, secret []byte) error {
	s.calls++
	if s.calls >= s.failAt {
		return errors.New("disk full")
	}
	return s.MemStore.Save(e, secret)
}

// The whole setup: profile asked, the key typed, the codes, the device
// chosen, the folder and tags asked; the key and device saved together.
func TestSetup_StoresKeyAndDevice(t *testing.T) {
	for name, profile := range map[string]string{"default profile": "", "named profile": "work"} {
		t.Run(name, func(t *testing.T) {
			aws := defaultAWS()
			stub(t, aws, testSecret, false)
			store := vault.NewMemStore()
			out, err := run(store, "", profile+"\n1\n\n1\nwork/aws\nprod mfa\n", vault.Filing{})
			if err != nil {
				t.Fatalf("Setup(): %v\n%s", err, out)
			}
			k := vault.AWSKey(profile)
			e, err := store.Lookup(k)
			if err != nil {
				t.Fatalf("no entry at %s: %v", k, err)
			}
			if e.Settings.AWSMFADevice != testDevice || e.Folder != "work/aws" || !slices.Equal(e.Tags, []string{"mfa", "prod"}) {
				t.Errorf("entry = %+v", e)
			}
			if secret, err := store.Get(k); err != nil || string(secret) != testSecret {
				t.Errorf("secret = %q, %v", secret, err)
			}
			if !slices.Equal(aws.profiles, []string{profile, profile}) {
				t.Errorf("AWS asked for profiles %q, want %q twice", aws.profiles, profile)
			}
			for _, want := range []string{"MFA code 1: ", "MFA code 2: ", "✅ AWS MFA is set up for " + profileName(profile), "sesh aws" + profileFlag(profile) + " --clip"} {
				if !strings.Contains(out, want) {
					t.Errorf("output lacks %q:\n%s", want, out)
				}
			}
		})
	}
}

// A profile given (--profile, or AWS_PROFILE) isn't asked for, and is the
// one AWS is asked about and the entry is saved under.
func TestSetup_ProfileGiven(t *testing.T) {
	aws := defaultAWS()
	stub(t, aws, testSecret, false)
	store := vault.NewMemStore()
	out, err := run(store, "work", "1\n\n1\n\n\n", vault.Filing{})
	if err != nil {
		t.Fatalf("Setup(): %v\n%s", err, out)
	}
	if strings.Contains(out, "AWS CLI profile (") {
		t.Errorf("asked for the profile:\n%s", out)
	}
	if _, err := store.Lookup(vault.AWSKey("work")); err != nil {
		t.Errorf("no entry for profile work: %v", err)
	}
	if !slices.Equal(aws.profiles, []string{"work", "work"}) {
		t.Errorf("AWS asked for profiles %q", aws.profiles)
	}
}

// Setup needs a terminal and the AWS CLI, refuses a profile no entry can
// have, and one that signs in with a temporary session, and says AWS's own
// message when it can't tell who the profile is; nothing is saved.
func TestSetup_RefusesEarly(t *testing.T) {
	for name, tc := range map[string]struct {
		prep    func(*fakeAWS)
		profile string
		wantSub string
	}{
		"no terminal": {func(*fakeAWS) { stdinIsTerminal = func() bool { return false } }, "", "at a terminal"},
		"no AWS CLI":  {func(*fakeAWS) { awsInstalled = func() error { return errors.New("not found") } }, "", "the AWS CLI isn't installed"},
		"bad profile": {func(*fakeAWS) {}, "bad/name", "AWS profile"},
		"session login": {func(a *fakeAWS) {
			a.identity = "arn:aws:sts::123456789012:assumed-role/Admin/alice"
		}, "", "a temporary session"},
		"identity fails": {func(a *fakeAWS) {
			a.identityErr = errors.New("aws sts get-caller-identity: The config profile (work) could not be found")
		}, "work", "aws sts get-caller-identity --profile work"},
	} {
		t.Run(name, func(t *testing.T) {
			aws := defaultAWS()
			stub(t, aws, testSecret, false)
			tc.prep(aws)
			store := vault.NewMemStore()
			out, err := run(store, tc.profile, "\n1\n\n1\n\n\n", vault.Filing{})
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("Setup() = %v, want an error containing %q\n%s", err, tc.wantSub, out)
			}
			if aws.identityErr != nil && !strings.Contains(err.Error(), "could not be found") {
				t.Errorf("AWS's own message is missing: %v", err)
			}
			if entries, err := store.List(&vault.Filter{}); err != nil || len(entries) != 0 {
				t.Errorf("a refused setup saved %+v (%v)", entries, err)
			}
		})
	}
}

// Declining to replace an existing key changes nothing, and isn't an error.
func TestSetup_DecliningKeepsTheEntry(t *testing.T) {
	stub(t, defaultAWS(), testSecret, false)
	store := vault.NewMemStore()
	if err := store.Save(&vault.Entry{Key: vault.AWSKey(""), Settings: vault.Settings{AWSMFADevice: "arn:aws:iam::123456789012:mfa/old"}}, []byte("OLDSECRETOLDSECR")); err != nil {
		t.Fatal(err)
	}
	out, err := run(store, "", "\nn\n", vault.Filing{})
	if err != nil || !strings.Contains(out, "Nothing changed") {
		t.Fatalf("Setup() = %v\n%s", err, out)
	}
	if secret, err := store.Get(vault.AWSKey("")); err != nil || string(secret) != "OLDSECRETOLDSECR" {
		t.Errorf("secret = %q, %v; want the old one", secret, err)
	}
}

// Replacing a key keeps the entry's folder, tags and creation time; the
// flags add to the tags, and the folder question isn't asked.
func TestSetup_ReplacingKeepsTheFiling(t *testing.T) {
	stub(t, defaultAWS(), testSecret, false)
	store := vault.NewMemStore()
	k := vault.AWSKey("")
	created := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := store.Save(&vault.Entry{Key: k, Folder: "work", Tags: []string{"x"}, CreatedAt: created, Settings: vault.Settings{AWSMFADevice: "arn:aws:iam::123456789012:mfa/old"}}, []byte("OLDSECRETOLDSECR")); err != nil {
		t.Fatal(err)
	}
	out, err := run(store, "", "\ny\n1\n\n1\n", vault.Filing{Tags: []string{"y"}})
	if err != nil {
		t.Fatalf("Setup(): %v\n%s", err, out)
	}
	e, err := store.Lookup(k)
	if err != nil || e.Folder != "work" || !slices.Equal(e.Tags, []string{"x", "y"}) || !e.CreatedAt.Equal(created) || e.Settings.AWSMFADevice != testDevice {
		t.Errorf("entry = %+v", e)
	}
}

// The key is saved before AWS is told of it: input ending at the AWS
// console step, or while the device is chosen, leaves the key in the
// vault, and says so.
func TestSetup_KeySavedBeforeTheConsole(t *testing.T) {
	for name, input := range map[string]string{
		"input ends at the console step": "\n1\n",
		"input ends choosing the device": "\n1\n\n",
	} {
		t.Run(name, func(t *testing.T) {
			stub(t, defaultAWS(), testSecret, false)
			store := vault.NewMemStore()
			out, err := run(store, "", input, vault.Filing{})
			if wantSub := "The MFA key is saved, as totp/aws/default, but not which MFA device"; err == nil || !strings.Contains(err.Error(), wantSub) {
				t.Fatalf("Setup() = %v, want %q\n%s", err, wantSub, out)
			}
			if strings.Contains(err.Error(), "sesh history") {
				t.Errorf("a new entry has no earlier key to point to: %v", err)
			}
			e, lerr := store.Lookup(vault.AWSKey(""))
			secret, gerr := store.Get(vault.AWSKey(""))
			if lerr != nil || gerr != nil || string(secret) != testSecret || e.Settings.AWSMFADevice != "" {
				t.Errorf("entry = %+v, %v; secret = %q, %v", e, lerr, secret, gerr)
			}
		})
	}
}

// A key that replaced another points to the entry's history, where the
// one replaced is, when the device can't be saved.
func TestSetup_ReplacedKeyPointsToHistory(t *testing.T) {
	stub(t, defaultAWS(), testSecret, false)
	store := &countingSave{MemStore: vault.NewMemStore(), failAt: 3}
	if err := store.Save(&vault.Entry{Key: vault.AWSKey("")}, []byte("OLDSECRETOLDSECR")); err != nil {
		t.Fatal(err)
	}
	_, err := run(store, "", "\ny\n1\n\n1\n\n\n", vault.Filing{})
	for _, want := range []string{"failed to store the MFA device", "disk full", "sesh history totp/aws/default"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Setup() = %v, want %q", err, want)
		}
	}
}

// A key that can't be saved stops the setup before the codes are given,
// so AWS is never told of a key sesh doesn't have.
func TestSetup_KeyNotSavedStopsBeforeTheCodes(t *testing.T) {
	stub(t, defaultAWS(), testSecret, false)
	store := &countingSave{MemStore: vault.NewMemStore(), failAt: 1}
	out, err := run(store, "", "\n1\n\n1\n\n\n", vault.Filing{})
	if wantSub := "failed to store the MFA key: disk full"; err == nil || !strings.Contains(err.Error(), wantSub) {
		t.Fatalf("Setup() = %v, want %q", err, wantSub)
	}
	if strings.Contains(out, "MFA code 1") {
		t.Errorf("the codes were given for a key that wasn't saved:\n%s", out)
	}
}

// The key is asked for again until it's one: a wrong choice, a key that
// isn't base32, an image that can't be read; the image path takes ~/.
func TestSetup_KeyAskedAgain(t *testing.T) {
	stub(t, defaultAWS(), "not a key!", false)
	store := vault.NewMemStore()
	input := "\n" +
		"3\n" + // screen capture isn't offered here
		"1\n" + // typed: not a key
		"2\nshot.png\n" + // a relative path
		"2\n~/missing.png\n" + // can't be read
		"2\n~/aws.png\n" + // read
		"\n1\n\n\n"
	out, err := run(store, "", input, vault.Filing{})
	if err != nil {
		t.Fatalf("Setup(): %v\n%s", err, out)
	}
	for _, want := range []string{"❌ Choose 1 to 2.", "❌ That isn't a key sesh can make codes from", "give a full path, or one starting with ~/", "/home/alice/missing.png: no such file"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "3: Select the QR code on screen") {
		t.Errorf("screen capture offered where it can't work:\n%s", out)
	}
	if secret, err := store.Get(vault.AWSKey("")); err != nil || string(secret) != testSecret {
		t.Errorf("secret = %q, %v", secret, err)
	}
}

// On macOS the QR code can be selected on screen.
func TestSetup_ScreenCapture(t *testing.T) {
	stub(t, defaultAWS(), "", true)
	store := vault.NewMemStore()
	out, err := run(store, "", "\n3\n\n\n1\n\n\n", vault.Filing{})
	if err != nil || !strings.Contains(out, "3: Select the QR code on screen") {
		t.Fatalf("Setup() = %v\n%s", err, out)
	}
	if secret, err := store.Get(vault.AWSKey("")); err != nil || string(secret) != testSecret {
		t.Errorf("secret = %q, %v", secret, err)
	}
}

// n at the console step makes new codes.
func TestSetup_NewCodes(t *testing.T) {
	stub(t, defaultAWS(), testSecret, false)
	out, err := run(vault.NewMemStore(), "", "\n1\nn\n\n1\n\n\n", vault.Filing{})
	if err != nil || strings.Count(out, "MFA code 1: ") != 2 {
		t.Fatalf("Setup() = %v; want the codes given twice:\n%s", err, out)
	}
}

// The device: AWS listing none yet is looked at again; a wrong answer is
// asked again; r looks again.
func TestSetup_ChoosingTheDevice(t *testing.T) {
	aws := defaultAWS()
	other := "arn:aws:iam::123456789012:mfa/phone"
	aws.listings = [][]string{nil, {other}, {other, testDevice}}
	stub(t, aws, testSecret, false)
	store := vault.NewMemStore()
	// none yet (Enter), one (r), two: 3 is out of range, 1x isn't a
	// number, 2 is the one
	out, err := run(store, "", "\n1\n\n\nr\n3\n1x\n2\n\n\n", vault.Filing{})
	if err != nil {
		t.Fatalf("Setup(): %v\n%s", err, out)
	}
	if strings.Count(out, "❌ Choose 1 to 2, r or m.") != 2 || !strings.Contains(out, "AWS lists no authenticator app for this user yet") {
		t.Errorf("output:\n%s", out)
	}
	if e, err := store.Lookup(vault.AWSKey("")); err != nil || e.Settings.AWSMFADevice != testDevice {
		t.Errorf("device = %q, %v", e.Settings.AWSMFADevice, err)
	}
}

// A device list AWS refuses says why, and goes to typing the ARN, which
// must be an authenticator app's, in the profile's account.
func TestSetup_TypedDevice(t *testing.T) {
	aws := defaultAWS()
	aws.listErr = errors.New("aws iam list-mfa-devices: AccessDenied: not authorized to perform iam:ListMFADevices")
	stub(t, aws, testSecret, false)
	store := vault.NewMemStore()
	gov := "arn:aws-us-gov:iam::123456789012:mfa/alice"
	input := "\n1\n\n" +
		"arn:aws:iam::123456789012:mfa/ has spaces\n" +
		"arn:aws:iam::123456789012:u2f/user/alice/key-ABC\n" +
		"arn:aws:iam::999999999999:mfa/alice\n" +
		gov + "\n\n\n"
	out, err := run(store, "", input, vault.Filing{})
	if err != nil {
		t.Fatalf("Setup(): %v\n%s", err, out)
	}
	for _, want := range []string{"not authorized to perform iam:ListMFADevices", "arn:aws:iam::123456789012:mfa/NAME", "That device is in account 999999999999, but the profile signs in to account 123456789012"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Count(out, "❌ That isn't an authenticator app's ARN") != 2 {
		t.Errorf("want two ARNs refused:\n%s", out)
	}
	if e, err := store.Lookup(vault.AWSKey("")); err != nil || e.Settings.AWSMFADevice != gov {
		t.Errorf("device = %q, %v; want the GovCloud one", e.Settings.AWSMFADevice, err)
	}
}

func TestExpandHome(t *testing.T) {
	stub(t, defaultAWS(), "", false)
	for in, want := range map[string]string{"~/a.png": "/home/alice/a.png", "/tmp/a.png": "/tmp/a.png"} {
		if got, err := expandHome(in); err != nil || got != want {
			t.Errorf("expandHome(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "a.png", "~alice/a.png"} {
		if _, err := expandHome(in); err == nil {
			t.Errorf("expandHome(%q) took it", in)
		}
	}
}
