package aws

import (
	"fmt"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/aws"
	awsMocks "github.com/bashhack/sesh/internal/aws/mocks"
	keychainMocks "github.com/bashhack/sesh/internal/keychain/mocks"
	totpMocks "github.com/bashhack/sesh/internal/totp/mocks"
)

func TestProvider_GetCredentials_Fixed(t *testing.T) {
	// Test successful credential generation
	t.Run("successful credential generation", func(t *testing.T) {
		// Create mocks
		mockKeychain := &keychainMocks.MockProvider{
			GetSecretFunc: func(account, service string) ([]byte, error) {
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
				return "123456", "654321", nil
			},
		}
		
		mockAWS := &awsMocks.MockProvider{
			GetSessionTokenFunc: func(profile, serial string, code []byte) (aws.Credentials, error) {
				t.Logf("GetSessionToken called with profile=%q, serial=%q, code=%q", profile, serial, string(code))
				// The provider passes empty string for default profile
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
		if err != nil {
			t.Fatalf("GetCredentials() unexpected error: %v", err)
		}
		
		// Check results
		if creds.Provider != "aws" {
			t.Errorf("Provider = %v, want 'aws'", creds.Provider)
		}
		if !creds.MFAAuthenticated {
			t.Error("MFAAuthenticated should be true")
		}
		if len(creds.Variables) != 3 {
			t.Errorf("Variables count = %d, want 3", len(creds.Variables))
		}
		if _, ok := creds.Variables["AWS_ACCESS_KEY_ID"]; !ok {
			t.Error("Missing AWS_ACCESS_KEY_ID")
		}
		if _, ok := creds.Variables["AWS_SECRET_ACCESS_KEY"]; !ok {
			t.Error("Missing AWS_SECRET_ACCESS_KEY")
		}
		if _, ok := creds.Variables["AWS_SESSION_TOKEN"]; !ok {
			t.Error("Missing AWS_SESSION_TOKEN")
		}
	})
}