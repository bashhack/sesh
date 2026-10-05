package setup

import (
	"bufio"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/qrcode"
	"github.com/bashhack/sesh/internal/vault"
)

// assertEmpty fails t if store holds any entry.
func assertEmpty(t *testing.T, store vault.Store) {
	t.Helper()
	entries, err := store.List(vault.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("a failed setup left entries: %+v", entries)
	}
}

// failingSave is a store whose Save fails.
type failingSave struct{ *vault.MemStore }

func (failingSave) Save(*vault.Entry, []byte) error { return errors.New("disk full") }

// stubAWSSetup replaces the AWS setup seams for one test: the AWS CLI is
// installed, answers get-caller-identity, and lists devices as given; the
// typed secret is a valid one.
func stubAWSSetup(t *testing.T, mfaDevices string) {
	t.Helper()
	origExecLookPath, origRunCommand, origValidate := execLookPath, runCommand, validateAndNormalizeSecret
	origScan, origReadPassword, origSleep := scanQRCodeFull, readPassword, timeSleep
	t.Cleanup(func() {
		execLookPath, runCommand, validateAndNormalizeSecret = origExecLookPath, origRunCommand, origValidate
		scanQRCodeFull, readPassword, timeSleep = origScan, origReadPassword, origSleep
	})
	timeSleep = func(time.Duration) {}
	execLookPath = func(string) (string, error) { return "/usr/local/bin/aws", nil }
	// A profile goes after the first argument: sts --profile work get-caller-identity.
	runCommand = func(_ string, args ...string) ([]byte, error) {
		switch {
		case slices.Contains(args, "get-caller-identity"):
			return []byte(`{"UserId": "AIDAI23HBD", "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/testuser"}`), nil
		case slices.Contains(args, "list-mfa-devices"):
			return []byte(mfaDevices), nil
		}
		return nil, nil
	}
	validateAndNormalizeSecret = func(secret string) (string, error) { return secret, nil }
	scanQRCodeFull = func() (qrcode.TOTPInfo, error) {
		return qrcode.TOTPInfo{Secret: "JBSWY3DPEHPK3PXP", Issuer: "AWS"}, nil
	}
	readPassword = func(int) ([]byte, error) { return []byte("JBSWY3DPEHPK3PXP"), nil }
}

func TestAWSSetupHandler_Setup(t *testing.T) {
	tests := map[string]struct {
		validateSecretError error
		wantErrMsg          string
		userInput           string
		existing            bool
		awsNotFound         bool
		awsCommandFails     bool
	}{
		"aws cli not found": {
			awsNotFound: true,
			wantErrMsg:  "AWS CLI not found",
		},
		"verify credentials fails": {
			awsCommandFails: true,
			wantErrMsg:      "failed to get AWS identity",
			userInput:       "test-profile\n",
		},
		"invalid mfa setup choice": {
			wantErrMsg: "invalid choice",
			userInput:  "\n3\n", // empty profile, invalid choice
		},
		"empty mfa setup choice": {
			wantErrMsg: "invalid choice, please select 1 or 2",
			userInput:  "\n\n", // empty profile, empty choice
		},
		"invalid totp secret": {
			validateSecretError: fmt.Errorf("invalid base32"),
			wantErrMsg:          "invalid TOTP secret",
			userInput:           "\n1\n\n", // empty profile, manual entry
		},
		"existing entry cancelled by user": {
			existing:   true,
			wantErrMsg: "setup cancelled by user",
			userInput:  "\nn\n", // empty profile, no to overwrite
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			stubAWSSetup(t, "")
			if tc.awsNotFound {
				execLookPath = func(string) (string, error) { return "", fmt.Errorf("not found") }
			}
			if tc.awsCommandFails {
				runCommand = func(string, ...string) ([]byte, error) { return nil, fmt.Errorf("mock aws error") }
			}
			if tc.validateSecretError != nil {
				validateAndNormalizeSecret = func(string) (string, error) { return "", tc.validateSecretError }
			}

			store := vault.NewMemStore()
			if tc.existing {
				if err := store.Put(vault.AWSKey(""), []byte("EXISTINGSECRET")); err != nil {
					t.Fatal(err)
				}
			}
			handler := &AWSSetupHandler{store: store, reader: bufio.NewReader(strings.NewReader(tc.userInput))}

			err := handler.Setup()
			if err == nil || !strings.Contains(err.Error(), tc.wantErrMsg) {
				t.Fatalf("Setup() = %v, want an error containing %q", err, tc.wantErrMsg)
			}
			if !tc.existing {
				if _, err := store.Lookup(vault.AWSKey("")); !errors.Is(err, vault.ErrNotFound) {
					t.Errorf("a failed setup stored an entry (lookup: %v)", err)
				}
			}
		})
	}
}

// The MFA secret and its device are stored together, as one entry.
func TestAWSSetupHandler_Setup_StoresSecretAndDevice(t *testing.T) {
	const device = "arn:aws:iam::123456789012:mfa/testuser"
	for name, profile := range map[string]string{"default profile": "", "named profile": "work"} {
		t.Run(name, func(t *testing.T) {
			stubAWSSetup(t, device)
			store := vault.NewMemStore()
			// profile, manual entry, Enter after the console codes, first device
			input := profile + "\n1\n\n1\n"
			handler := &AWSSetupHandler{store: store, reader: bufio.NewReader(strings.NewReader(input))}

			if err := handler.Setup(); err != nil {
				t.Fatalf("Setup(): %v", err)
			}
			k := vault.AWSKey(profile)
			e, err := store.Lookup(k)
			if err != nil {
				t.Fatalf("no entry at %s: %v", k, err)
			}
			if e.Settings.AWSMFADevice != device {
				t.Errorf("device = %q, want %q", e.Settings.AWSMFADevice, device)
			}
			if secret, err := store.Get(k); err != nil || string(secret) != "JBSWY3DPEHPK3PXP" {
				t.Errorf("secret = %q, %v; want the typed one", secret, err)
			}
		})
	}
}

func TestAWSSetupHandler_Setup_FailedSaveLeavesNothing(t *testing.T) {
	stubAWSSetup(t, "arn:aws:iam::123456789012:mfa/testuser")
	store := failingSave{vault.NewMemStore()}
	handler := &AWSSetupHandler{store: store, reader: bufio.NewReader(strings.NewReader("\n1\n\n1\n"))}

	err := handler.Setup()
	if wantSub := "failed to store the MFA secret"; err == nil || !strings.Contains(err.Error(), wantSub) || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("Setup() = %v, want an error containing %q and the cause", err, wantSub)
	}
	assertEmpty(t, store)
}
