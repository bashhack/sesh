package aws

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/aws"
	awsMocks "github.com/bashhack/sesh/internal/aws/mocks"
	keychainMocks "github.com/bashhack/sesh/internal/keychain/mocks"
	totpMocks "github.com/bashhack/sesh/internal/totp/mocks"
)

func TestDebugGetCredentials(t *testing.T) {
	// Redirect stderr to capture debug output
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	
	// Create mocks with debug output
	mockKeychain := &keychainMocks.MockProvider{
		GetSecretFunc: func(account, service string) ([]byte, error) {
			t.Logf("Keychain GetSecret called: account=%q, service=%q", account, service)
			switch service {
			case "sesh-aws-mfa-default":
				return []byte("arn:aws:iam::123456789012:mfa/user"), nil
			case "sesh-aws-default":
				return []byte("MYSECRET"), nil
			default:
				return nil, fmt.Errorf("unexpected service: %s", service)
			}
		},
	}
	
	mockTOTP := &totpMocks.MockProvider{
		GenerateConsecutiveCodesBytesFunc: func(secret []byte) (string, string, error) {
			t.Logf("TOTP GenerateConsecutiveCodesBytes called with secret: %q", string(secret))
			return "123456", "654321", nil
		},
	}
	
	callCount := 0
	mockAWS := &awsMocks.MockProvider{
		GetSessionTokenFunc: func(profile, serial string, code []byte) (aws.Credentials, error) {
			callCount++
			t.Logf("AWS GetSessionToken call #%d: profile=%q, serial=%q, code=%q", callCount, profile, serial, string(code))
			if profile == "" && serial == "arn:aws:iam::123456789012:mfa/user" && string(code) == "123456" {
				return aws.Credentials{
					AccessKeyId:     "AKIAIOSFODNN7EXAMPLE",
					SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
					SessionToken:    "AQoDYXdzEJr...",
					Expiration:      time.Now().Add(time.Hour).Format(time.RFC3339),
				}, nil
			}
			return aws.Credentials{}, fmt.Errorf("unexpected call with profile=%q, serial=%q, code=%q", profile, serial, string(code))
		},
	}

	// Create provider
	p := &Provider{
		aws:      mockAWS,
		keychain: mockKeychain,
		totp:     mockTOTP,
		profile:  "", // default profile
		keyUser:  "testuser",
		keyName:  "sesh-aws",
	}

	// Test GetCredentials
	creds, err := p.GetCredentials()
	
	// Close and restore stderr
	w.Close()
	os.Stderr = oldStderr
	
	if err != nil {
		t.Fatalf("GetCredentials() error: %v", err)
	}
	
	t.Logf("Credentials: Provider=%q, MFAAuthenticated=%v, Variables=%d", 
		creds.Provider, creds.MFAAuthenticated, len(creds.Variables))
}