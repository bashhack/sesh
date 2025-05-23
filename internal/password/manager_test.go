package password

import (
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
		name      string
		service   string
		username  string
		password  string
		entryType EntryType
		wantErr   bool
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
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock expectations
			expectedServiceKey := manager.generateServiceKey(tc.service, tc.username, tc.entryType)
			
			// Mock SetSecret call
			mockKeychain.SetSecretFunc = func(account, service string, secret []byte) error {
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
				return nil // Success for simplicity
			}
			
			// Store password
			err := manager.StorePasswordString(tc.service, tc.username, tc.password, tc.entryType)
			if tc.wantErr && err == nil {
				t.Error("Expected error but got none")
			} else if !tc.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestGetPasswordString(t *testing.T) {
	mockKeychain := &mocks.MockProvider{}
	testUser := "testuser"
	manager := NewManager(mockKeychain, testUser)
	
	testService := "test-service"
	testUsername := "user"
	testPassword := "secretpassword123"
	entryType := EntryTypePassword
	
	expectedServiceKey := manager.generateServiceKey(testService, testUsername, entryType)
	
	// Setup mock to return password
	mockKeychain.GetSecretFunc = func(account, service string) ([]byte, error) {
		if account != testUser {
			t.Errorf("Expected account %q, got %q", testUser, account)
		}
		if service != expectedServiceKey {
			t.Errorf("Expected service key %q, got %q", expectedServiceKey, service)
		}
		return []byte(testPassword), nil
	}
	
	// Retrieve password
	retrieved, err := manager.GetPasswordString(testService, testUsername, entryType)
	if err != nil {
		t.Fatalf("GetPasswordString failed: %v", err)
	}
	
	if retrieved != testPassword {
		t.Errorf("Retrieved password %q doesn't match expected %q", retrieved, testPassword)
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
	
	testService := "test-service"
	testUsername := "user"
	entryType := EntryTypePassword
	expectedServiceKey := manager.generateServiceKey(testService, testUsername, entryType)
	
	// Setup mock expectations
	mockKeychain.DeleteEntryFunc = func(account, service string) error {
		if account != testUser {
			t.Errorf("Expected account %q, got %q", testUser, account)
		}
		if service != expectedServiceKey {
			t.Errorf("Expected service key %q, got %q", expectedServiceKey, service)
		}
		return nil
	}
	
	err := manager.DeleteEntry(testService, testUsername, entryType)
	if err != nil {
		t.Fatalf("DeleteEntry failed: %v", err)
	}
}

func TestListEntries(t *testing.T) {
	mockKeychain := &mocks.MockProvider{}
	testUser := "testuser"
	manager := NewManager(mockKeychain, testUser)
	
	// Setup mock keychain entries
	mockEntries := []keychain.KeychainEntry{
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
	}
	
	mockKeychain.ListEntriesFunc = func(service string) ([]keychain.KeychainEntry, error) {
		if service != "sesh-password" {
			t.Errorf("Expected service prefix 'sesh-password', got %q", service)
		}
		return mockEntries, nil
	}
	
	entries, err := manager.ListEntries()
	if err != nil {
		t.Fatalf("ListEntries failed: %v", err)
	}
	
	if len(entries) != len(mockEntries) {
		t.Errorf("Expected %d entries, got %d", len(mockEntries), len(entries))
	}
	
	// Basic validation that entries are parsed
	for i, entry := range entries {
		if entry.Service != mockEntries[i].Service {
			t.Errorf("Entry %d: expected service %q, got %q", i, mockEntries[i].Service, entry.Service)
		}
		if entry.Description != mockEntries[i].Description {
			t.Errorf("Entry %d: expected description %q, got %q", i, mockEntries[i].Description, entry.Description)
		}
	}
}