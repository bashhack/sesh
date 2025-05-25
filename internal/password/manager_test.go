package password

import (
	"errors"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/keychain/mocks"
)

func TestNewManager(t *testing.T) {
	mockKeychain := &mocks.MockProvider{}
	testUser := "testuser"
	
	manager := NewManager(mockKeychain, testUser)
	
	if manager == nil {
		t.Fatal("NewManager returned nil")
	}
	if manager.keychain != mockKeychain {
		t.Error("Manager keychain not set correctly")
	}
	if manager.user != testUser {
		t.Error("Manager user not set correctly")
	}
}

func TestStorePasswordString(t *testing.T) {
	mockKeychain := &mocks.MockProvider{}
	testUser := "testuser"
	manager := NewManager(mockKeychain, testUser)
	
	testCases := []struct {
		name            string
		service         string
		username        string
		password        string
		entryType       EntryType
		setSecretErr    error
		metadataErr     error
		wantErr         bool
		errMsg          string
	}{
		{
			name:      "valid password storage",
			service:   "test-service",
			username:  "user",
			password:  "secretpassword123",
			entryType: EntryTypePassword,
			wantErr:   false,
		},
		{
			name:      "empty service",
			service:   "",
			username:  "user",
			password:  "password",
			entryType: EntryTypePassword,
			wantErr:   false, // Should work with empty service
		},
		{
			name:      "API key storage",
			service:   "aws",
			username:  "access-key",
			password:  "SECRET_ACCESS_KEY",
			entryType: EntryTypeAPIKey,
			wantErr:   false,
		},
		{
			name:         "keychain storage fails",
			service:      "test-service",
			username:     "user",
			password:     "password",
			entryType:    EntryTypePassword,
			setSecretErr: errors.New("keychain access denied"),
			wantErr:      true,
			errMsg:       "failed to store password",
		},
		{
			name:        "metadata storage fails",
			service:     "test-service",
			username:    "user",
			password:    "password",
			entryType:   EntryTypePassword,
			metadataErr: errors.New("keychain access denied"),
			wantErr:     false, // Metadata failure is non-fatal
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock expectations
			expectedServiceKey := manager.generateServiceKey(tc.service, tc.username, tc.entryType)
			
			// Mock SetSecret call
			mockKeychain.SetSecretFunc = func(account, service string, secret []byte) error {
				if tc.setSecretErr != nil {
					return tc.setSecretErr
				}
				if account != testUser {
					t.Errorf("Expected account %q, got %q", testUser, account)
				}
				if service != expectedServiceKey {
					t.Errorf("Expected service key %q, got %q", expectedServiceKey, service)
				}
				if string(secret) != tc.password {
					t.Errorf("Expected password %q, got %q", tc.password, string(secret))
				}
				return nil
			}
			
			// Mock StoreEntryMetadata call (may fail, but non-fatal)
			mockKeychain.StoreEntryMetadataFunc = func(servicePrefix, service, account, description string) error {
				if tc.metadataErr != nil {
					return tc.metadataErr
				}
				return nil
			}
			
			// Store password
			err := manager.StorePasswordString(tc.service, tc.username, tc.password, tc.entryType)
			if tc.wantErr && err == nil {
				t.Error("Expected error but got none")
			} else if !tc.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			
			if tc.wantErr && tc.errMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tc.errMsg) {
					t.Errorf("Expected error containing %q, got %q", tc.errMsg, err.Error())
				}
			}
		})
	}
}

func TestGetPasswordString(t *testing.T) {
	mockKeychain := &mocks.MockProvider{}
	testUser := "testuser"
	manager := NewManager(mockKeychain, testUser)
	
	testCases := map[string]struct {
		service      string
		username     string
		entryType    EntryType
		returnSecret []byte
		getSecretErr error
		expected     string
		wantErr      bool
		errMsg       string
	}{
		"successful retrieval": {
			service:      "test-service",
			username:     "user",
			entryType:    EntryTypePassword,
			returnSecret: []byte("secretpassword123"),
			expected:     "secretpassword123",
			wantErr:      false,
		},
		"entry not found": {
			service:      "nonexistent",
			username:     "user",
			entryType:    EntryTypePassword,
			getSecretErr: errors.New("entry not found"),
			wantErr:      true,
			errMsg:       "failed to retrieve password",
		},
		"keychain access denied": {
			service:      "test-service",
			username:     "user",
			entryType:    EntryTypePassword,
			getSecretErr: errors.New("keychain access denied"),
			wantErr:      true,
			errMsg:       "failed to retrieve password",
		},
		"empty password": {
			service:      "test-service",
			username:     "user",
			entryType:    EntryTypePassword,
			returnSecret: []byte(""),
			expected:     "",
			wantErr:      false,
		},
	}
	
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			expectedServiceKey := manager.generateServiceKey(tc.service, tc.username, tc.entryType)
			
			// Setup mock to return password
			mockKeychain.GetSecretFunc = func(account, service string) ([]byte, error) {
				if account != testUser {
					t.Errorf("Expected account %q, got %q", testUser, account)
				}
				if service != expectedServiceKey {
					t.Errorf("Expected service key %q, got %q", expectedServiceKey, service)
				}
				if tc.getSecretErr != nil {
					return nil, tc.getSecretErr
				}
				return tc.returnSecret, nil
			}
			
			// Retrieve password
			retrieved, err := manager.GetPasswordString(tc.service, tc.username, tc.entryType)
			
			if (err != nil) != tc.wantErr {
				t.Errorf("GetPasswordString() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			
			if tc.wantErr && tc.errMsg != "" {
				if !strings.Contains(err.Error(), tc.errMsg) {
					t.Errorf("Expected error containing %q, got %q", tc.errMsg, err.Error())
				}
				return
			}
			
			if !tc.wantErr && retrieved != tc.expected {
				t.Errorf("Retrieved password %q doesn't match expected %q", retrieved, tc.expected)
			}
		})
	}
}

func TestStoreTOTPSecret(t *testing.T) {
	mockKeychain := &mocks.MockProvider{}
	testUser := "testuser"
	manager := NewManager(mockKeychain, testUser)
	
	testCases := []struct {
		name       string
		service    string
		username   string
		secret     string
		expectNorm string
		wantErr    bool
	}{
		{
			name:       "valid TOTP secret",
			service:    "github",
			username:   "account",
			secret:     "JBSWY3DPEHPK3PXP",
			expectNorm: "JBSWY3DPEHPK3PXP",
			wantErr:    false,
		},
		{
			name:       "secret with spaces",
			service:    "github",
			username:   "account",
			secret:     "JBSW Y3DP EHPK 3PXP",
			expectNorm: "JBSWY3DPEHPK3PXP",
			wantErr:    false,
		},
		{
			name:     "invalid secret",
			service:  "github",
			username: "account",
			secret:   "invalid-chars-!@#",
			wantErr:  true,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantErr {
				err := manager.StoreTOTPSecret(tc.service, tc.username, tc.secret)
				if err == nil {
					t.Error("Expected validation error but got none")
				}
				return
			}
			
			// Setup successful storage mock
			expectedServiceKey := manager.generateServiceKey(tc.service, tc.username, EntryTypeTOTP)
			
			mockKeychain.SetSecretFunc = func(account, service string, secret []byte) error {
				if account != testUser {
					t.Errorf("Expected account %q, got %q", testUser, account)
				}
				if service != expectedServiceKey {
					t.Errorf("Expected service key %q, got %q", expectedServiceKey, service)
				}
				if string(secret) != tc.expectNorm {
					t.Errorf("Expected normalized secret %q, got %q", tc.expectNorm, string(secret))
				}
				return nil
			}
			
			mockKeychain.StoreEntryMetadataFunc = func(servicePrefix, service, account, description string) error {
				return nil
			}
			
			err := manager.StoreTOTPSecret(tc.service, tc.username, tc.secret)
			if err != nil {
				t.Fatalf("StoreTOTPSecret failed: %v", err)
			}
		})
	}
}

func TestGenerateServiceKey(t *testing.T) {
	mockKeychain := &mocks.MockProvider{}
	testUser := "testuser"
	manager := NewManager(mockKeychain, testUser)
	
	testCases := []struct {
		name      string
		service   string
		username  string
		entryType EntryType
		expected  string
	}{
		{
			name:      "password with username",
			service:   "github",
			username:  "myuser",
			entryType: EntryTypePassword,
			expected:  "sesh-password-password-github-myuser",
		},
		{
			name:      "password without username",
			service:   "github",
			username:  "",
			entryType: EntryTypePassword,
			expected:  "sesh-password-password-github",
		},
		{
			name:      "TOTP entry",
			service:   "aws",
			username:  "root",
			entryType: EntryTypeTOTP,
			expected:  "sesh-password-totp-aws-root",
		},
		{
			name:      "API key",
			service:   "stripe",
			username:  "",
			entryType: EntryTypeAPIKey,
			expected:  "sesh-password-api_key-stripe",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := manager.generateServiceKey(tc.service, tc.username, tc.entryType)
			if result != tc.expected {
				t.Errorf("Expected service key %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestDeleteEntry(t *testing.T) {
	mockKeychain := &mocks.MockProvider{}
	testUser := "testuser"
	manager := NewManager(mockKeychain, testUser)
	
	testCases := map[string]struct {
		service   string
		username  string
		entryType EntryType
		deleteErr error
		wantErr   bool
		errMsg    string
	}{
		"successful delete": {
			service:   "test-service",
			username:  "user",
			entryType: EntryTypePassword,
			wantErr:   false,
		},
		"entry not found": {
			service:   "nonexistent",
			username:  "user",
			entryType: EntryTypePassword,
			deleteErr: errors.New("entry not found"),
			wantErr:   true,
			errMsg:    "failed to delete entry",
		},
		"keychain access denied": {
			service:   "test-service",
			username:  "user",
			entryType: EntryTypePassword,
			deleteErr: errors.New("keychain access denied"),
			wantErr:   true,
			errMsg:    "failed to delete entry",
		},
		"delete without username": {
			service:   "test-service",
			username:  "",
			entryType: EntryTypeAPIKey,
			wantErr:   false,
		},
	}
	
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			expectedServiceKey := manager.generateServiceKey(tc.service, tc.username, tc.entryType)
			
			// Setup mock expectations
			mockKeychain.DeleteEntryFunc = func(account, service string) error {
				if account != testUser {
					t.Errorf("Expected account %q, got %q", testUser, account)
				}
				if service != expectedServiceKey {
					t.Errorf("Expected service key %q, got %q", expectedServiceKey, service)
				}
				if tc.deleteErr != nil {
					return tc.deleteErr
				}
				return nil
			}
			
			err := manager.DeleteEntry(tc.service, tc.username, tc.entryType)
			
			if (err != nil) != tc.wantErr {
				t.Errorf("DeleteEntry() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			
			if tc.wantErr && tc.errMsg != "" {
				if !strings.Contains(err.Error(), tc.errMsg) {
					t.Errorf("Expected error containing %q, got %q", tc.errMsg, err.Error())
				}
			}
		})
	}
}

func TestListEntries(t *testing.T) {
	mockKeychain := &mocks.MockProvider{}
	testUser := "testuser"
	manager := NewManager(mockKeychain, testUser)
	
	testCases := map[string]struct {
		mockEntries   []keychain.KeychainEntry
		listErr       error
		expectedCount int
		wantErr       bool
		errMsg        string
	}{
		"successful list": {
			mockEntries: []keychain.KeychainEntry{
				{
					Service:     "sesh-password-password-github-user1",
					Account:     testUser,
					Description: "password for github",
				},
				{
					Service:     "sesh-password-totp-aws-root",
					Account:     testUser,
					Description: "totp for aws",
				},
			},
			expectedCount: 2,
			wantErr:       false,
		},
		"empty list": {
			mockEntries:   []keychain.KeychainEntry{},
			expectedCount: 0,
			wantErr:       false,
		},
		"keychain error": {
			listErr: errors.New("keychain access denied"),
			wantErr: true,
			errMsg:  "failed to list entries",
		},
		"list with invalid entries": {
			mockEntries: []keychain.KeychainEntry{
				{
					Service:     "sesh-password-password-github-user1",
					Account:     testUser,
					Description: "password for github",
				},
				{
					Service:     "invalid-entry", // Will be skipped by parseEntry
					Account:     testUser,
					Description: "invalid",
				},
				{
					Service:     "sesh-password-totp-aws-root",
					Account:     testUser,
					Description: "totp for aws",
				},
			},
			expectedCount: 3, // parseEntry in the actual code doesn't fail, so all entries are included
			wantErr:       false,
		},
	}
	
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			mockKeychain.ListEntriesFunc = func(service string) ([]keychain.KeychainEntry, error) {
				if service != "sesh-password" {
					t.Errorf("Expected service prefix 'sesh-password', got %q", service)
				}
				if tc.listErr != nil {
					return nil, tc.listErr
				}
				return tc.mockEntries, nil
			}
			
			entries, err := manager.ListEntries()
			
			if (err != nil) != tc.wantErr {
				t.Errorf("ListEntries() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			
			if tc.wantErr && tc.errMsg != "" {
				if !strings.Contains(err.Error(), tc.errMsg) {
					t.Errorf("Expected error containing %q, got %q", tc.errMsg, err.Error())
				}
				return
			}
			
			if !tc.wantErr {
				if len(entries) != tc.expectedCount {
					t.Errorf("Expected %d entries, got %d", tc.expectedCount, len(entries))
				}
				
				// Basic validation that entries are parsed correctly
				for i, entry := range entries {
					if i < len(tc.mockEntries) {
						if entry.Service != tc.mockEntries[i].Service {
							t.Errorf("Entry %d: expected service %q, got %q", i, tc.mockEntries[i].Service, entry.Service)
						}
						if entry.Description != tc.mockEntries[i].Description {
							t.Errorf("Entry %d: expected description %q, got %q", i, tc.mockEntries[i].Description, entry.Description)
						}
					}
				}
			}
		})
	}
}

func TestGenerateTOTPCode(t *testing.T) {
	mockKeychain := &mocks.MockProvider{}
	testUser := "testuser"
	manager := NewManager(mockKeychain, testUser)

	testCases := map[string]struct {
		service       string
		username      string
		storedSecret  []byte
		expectedCode  string
		getSecretErr  error
		generateErr   error
		wantErr       bool
		errMsg        string
	}{
		"valid TOTP generation": {
			service:      "github",
			username:     "user",
			storedSecret: []byte("JBSWY3DPEHPK3PXP"),
			expectedCode: "123456", // This would be the actual TOTP code
			wantErr:      false,
		},
		"secret not found": {
			service:      "nonexistent",
			username:     "user",
			getSecretErr: errors.New("entry not found"),
			wantErr:      true,
			errMsg:       "failed to retrieve TOTP secret",
		},
		"invalid secret format": {
			service:      "github",
			username:     "user",
			storedSecret: []byte("invalid!@#$"),
			wantErr:      true,
			errMsg:       "failed to generate TOTP code",
		},
		"empty secret": {
			service:      "github",
			username:     "user",
			storedSecret: []byte(""),
			wantErr:      true,
			errMsg:       "failed to generate TOTP code",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			expectedServiceKey := manager.generateServiceKey(tc.service, tc.username, EntryTypeTOTP)

			// Setup mock for GetSecret
			mockKeychain.GetSecretFunc = func(account, service string) ([]byte, error) {
				if account != testUser {
					t.Errorf("Expected account %q, got %q", testUser, account)
				}
				if service != expectedServiceKey {
					t.Errorf("Expected service key %q, got %q", expectedServiceKey, service)
				}
				if tc.getSecretErr != nil {
					return nil, tc.getSecretErr
				}
				return tc.storedSecret, nil
			}

			// Generate TOTP code
			code, err := manager.GenerateTOTPCode(tc.service, tc.username)

			if (err != nil) != tc.wantErr {
				t.Errorf("GenerateTOTPCode() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if tc.wantErr && tc.errMsg != "" {
				if !strings.Contains(err.Error(), tc.errMsg) {
					t.Errorf("Expected error containing %q, got %q", tc.errMsg, err.Error())
				}
				return
			}

			if !tc.wantErr {
				// Validate the code format (should be 6 digits)
				if len(code) != 6 {
					t.Errorf("Expected 6-digit code, got %q (length %d)", code, len(code))
				}
				// Check if all characters are digits
				for _, c := range code {
					if c < '0' || c > '9' {
						t.Errorf("Expected numeric code, got %q", code)
						break
					}
				}
			}
		})
	}
}