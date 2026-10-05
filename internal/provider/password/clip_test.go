package password

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/keychain/mocks"
	"github.com/bashhack/sesh/internal/totp"
)

// clipStore is an in-memory store holding a password and a TOTP secret
// under the same name, github/alice.
func clipStore() (*mocks.MockProvider, map[string]string) {
	secrets := map[string]string{
		"sesh-password/password/github/alice": "the-password",
		"sesh-password/totp/github/alice":     "JBSWY3DPEHPK3PXP",
	}
	return &mocks.MockProvider{
		GetSecretFunc: func(_, service string) ([]byte, error) {
			if s, ok := secrets[service]; ok {
				return []byte(s), nil
			}
			return nil, errNotFound
		},
		SetSecretFunc: func(_, service string, secret []byte) error {
			secrets[service] = string(secret)
			return nil
		},
	}, secrets
}

var errNotFound = errors.New("secret not found")

func TestGetClipboardValue_FollowsTheAction(t *testing.T) {
	t.Run("get copies the stored secret", func(t *testing.T) {
		for _, action := range []string{"get", ""} {
			kc, _ := clipStore()
			p, _ := newTestProvider(kc)
			p.action, p.service, p.username = action, "github", "alice"
			creds, err := p.GetClipboardValue()
			if err != nil {
				t.Fatalf("action %q: %v", action, err)
			}
			if creds.CopyValue != "the-password" {
				t.Errorf("action %q copied %q, want the stored password", action, creds.CopyValue)
			}
		}
	})

	t.Run("generate stores a new password and copies it", func(t *testing.T) {
		kc, secrets := clipStore()
		p, _ := newTestProvider(kc)
		p.action, p.service, p.username, p.pwLength = "generate", "newsite", "me", 24
		creds, err := p.GetClipboardValue()
		if err != nil {
			t.Fatalf("GetClipboardValue: %v", err)
		}
		stored := secrets["sesh-password/password/newsite/me"]
		if len(stored) != 24 {
			t.Fatalf("stored %q, want a new 24-character password", stored)
		}
		if creds.CopyValue != stored {
			t.Errorf("copied %q, want the password just stored (%q)", creds.CopyValue, stored)
		}
		if strings.Contains(creds.DisplayInfo, "--clip") {
			t.Errorf("DisplayInfo = %q, shouldn't suggest --clip after copying", creds.DisplayInfo)
		}
	})

	t.Run("totp-generate copies the current code, not a secret", func(t *testing.T) {
		kc, _ := clipStore()
		p, _ := newTestProvider(kc)
		p.action, p.service, p.username = "totp-generate", "github", "alice"
		before, after, err := totp.GenerateConsecutiveCodesBytesWithParams([]byte("JBSWY3DPEHPK3PXP"), totp.Params{})
		if err != nil {
			t.Fatal(err)
		}
		creds, err := p.GetClipboardValue()
		if err != nil {
			t.Fatalf("GetClipboardValue: %v", err)
		}
		if !regexp.MustCompile(`^[0-9]{6}$`).MatchString(creds.CopyValue) || (creds.CopyValue != before && creds.CopyValue != after) {
			t.Errorf("copied %q, want the current TOTP code (%s or, across a period boundary, %s)", creds.CopyValue, before, after)
		}
	})

	for _, action := range []string{"store", "search", "export", "import", "totp-store"} {
		t.Run(action+" has nothing to copy", func(t *testing.T) {
			kc, _ := clipStore()
			p, _ := newTestProvider(kc)
			p.action = action // no --service-name: the action is the problem to report
			_, err := p.GetClipboardValue()
			if wantSub := "--clip works with --action get, generate, or totp-generate"; err == nil || !strings.Contains(err.Error(), wantSub) {
				t.Errorf("GetClipboardValue for %s: err = %v, want it to contain %q", action, err, wantSub)
			}
		})
	}
}
