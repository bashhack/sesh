package password

import (
	"errors"
	"strings"
	"testing"
	"time"

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

	testCases := map[string]struct {
		service      string
		username     string
		password     string
		entryType    EntryType
		expectedKey  string
		setSecretErr error
		metadataErr  error
		wantErr      bool
		errMsg       string
	}{
		"valid password storage": {
			service:     "test-service",
			username:    "user",
			password:    "secretpassword123",
			entryType:   EntryTypePassword,
			expectedKey: "sesh-password/password/test-service/user",
		},
		"empty service is rejected": {
			service:   "",
			username:  "user",
			password:  "password",
			entryType: EntryTypePassword,
			wantErr:   true,
			errMsg:    "failed to build service key",
		},
		"API key storage": {
			service:     "aws",
			username:    "access-key",
			password:    "SECRET_ACCESS_KEY",
			entryType:   EntryTypeAPIKey,
			expectedKey: "sesh-password/api_key/aws/access-key",
		},
		"keychain storage fails": {
			service:      "test-service",
			username:     "user",
			password:     "password",
			entryType:    EntryTypePassword,
			expectedKey:  "sesh-password/password/test-service/user",
			setSecretErr: errors.New("keychain access denied"),
			wantErr:      true,
			errMsg:       "failed to store password",
		},
		"metadata storage fails": {
			service:     "test-service",
			username:    "user",
			password:    "password",
			entryType:   EntryTypePassword,
			expectedKey: "sesh-password/password/test-service/user",
			metadataErr: errors.New("keychain access denied"),
			wantErr:     false, // Metadata failure is non-fatal
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// Mock SetSecret call
			mockKeychain.SetSecretFunc = func(account, service string, secret []byte) error {
				if tc.setSecretErr != nil {
					return tc.setSecretErr
				}
				if account != testUser {
					t.Errorf("Expected account %q, got %q", testUser, account)
				}
				if service != tc.expectedKey {
					t.Errorf("Expected service key %q, got %q", tc.expectedKey, service)
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
		expectedKey  string
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
			expectedKey:  "sesh-password/password/test-service/user",
			returnSecret: []byte("secretpassword123"),
			expected:     "secretpassword123",
			wantErr:      false,
		},
		"entry not found": {
			service:      "nonexistent",
			username:     "user",
			entryType:    EntryTypePassword,
			expectedKey:  "sesh-password/password/nonexistent/user",
			getSecretErr: errors.New("entry not found"),
			wantErr:      true,
			errMsg:       "failed to retrieve password",
		},
		"keychain access denied": {
			service:      "test-service",
			username:     "user",
			entryType:    EntryTypePassword,
			expectedKey:  "sesh-password/password/test-service/user",
			getSecretErr: errors.New("keychain access denied"),
			wantErr:      true,
			errMsg:       "failed to retrieve password",
		},
		"empty password": {
			service:      "test-service",
			username:     "user",
			entryType:    EntryTypePassword,
			expectedKey:  "sesh-password/password/test-service/user",
			returnSecret: []byte(""),
			expected:     "",
			wantErr:      false,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// Setup mock to return password
			mockKeychain.GetSecretFunc = func(account, service string) ([]byte, error) {
				if account != testUser {
					t.Errorf("Expected account %q, got %q", testUser, account)
				}
				if service != tc.expectedKey {
					t.Errorf("Expected service key %q, got %q", tc.expectedKey, service)
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

	testCases := map[string]struct {
		service     string
		username    string
		secret      string
		expectedKey string
		expectNorm  string
		wantErr     bool
	}{
		"valid TOTP secret": {
			service:     "github",
			username:    "account",
			secret:      "JBSWY3DPEHPK3PXP",
			expectedKey: "sesh-password/totp/github/account",
			expectNorm:  "JBSWY3DPEHPK3PXP",
			wantErr:     false,
		},
		"secret with spaces": {
			service:     "github",
			username:    "account",
			secret:      "JBSW Y3DP EHPK 3PXP",
			expectedKey: "sesh-password/totp/github/account",
			expectNorm:  "JBSWY3DPEHPK3PXP",
			wantErr:     false,
		},
		"invalid secret": {
			service:  "github",
			username: "account",
			secret:   "invalid-chars-!@#",
			wantErr:  true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			if tc.wantErr {
				err := manager.StoreTOTPSecret(tc.service, tc.username, tc.secret)
				if err == nil {
					t.Error("Expected validation error but got none")
				}
				return
			}

			// Setup successful storage mock
			mockKeychain.SetSecretFunc = func(account, service string, secret []byte) error {
				if account != testUser {
					t.Errorf("Expected account %q, got %q", testUser, account)
				}
				if service != tc.expectedKey {
					t.Errorf("Expected service key %q, got %q", tc.expectedKey, service)
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

	testCases := map[string]struct {
		service   string
		username  string
		entryType EntryType
		expected  string
	}{
		"password with username": {
			service:   "github",
			username:  "myuser",
			entryType: EntryTypePassword,
			expected:  "sesh-password/password/github/myuser",
		},
		"password without username": {
			service:   "github",
			username:  "",
			entryType: EntryTypePassword,
			expected:  "sesh-password/password/github",
		},
		"TOTP entry": {
			service:   "aws",
			username:  "root",
			entryType: EntryTypeTOTP,
			expected:  "sesh-password/totp/aws/root",
		},
		"API key": {
			service:   "stripe",
			username:  "",
			entryType: EntryTypeAPIKey,
			expected:  "sesh-password/api_key/stripe",
		},
		"service with hyphens": {
			service:   "github-prod",
			username:  "alice",
			entryType: EntryTypePassword,
			expected:  "sesh-password/password/github-prod/alice",
		},
		"ambiguous components stay distinct": {
			service:   "github",
			username:  "prod-alice",
			entryType: EntryTypePassword,
			expected:  "sesh-password/password/github/prod-alice",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			result, err := manager.generateServiceKey(tc.service, tc.username, tc.entryType)
			if err != nil {
				t.Fatalf("generateServiceKey failed: %v", err)
			}
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
		service     string
		username    string
		entryType   EntryType
		expectedKey string
		deleteErr   error
		wantErr     bool
		errMsg      string
	}{
		"successful delete": {
			service:     "test-service",
			username:    "user",
			entryType:   EntryTypePassword,
			expectedKey: "sesh-password/password/test-service/user",
			wantErr:     false,
		},
		"entry not found": {
			service:     "nonexistent",
			username:    "user",
			entryType:   EntryTypePassword,
			expectedKey: "sesh-password/password/nonexistent/user",
			deleteErr:   errors.New("entry not found"),
			wantErr:     true,
			errMsg:      "failed to delete entry",
		},
		"keychain access denied": {
			service:     "test-service",
			username:    "user",
			entryType:   EntryTypePassword,
			expectedKey: "sesh-password/password/test-service/user",
			deleteErr:   errors.New("keychain access denied"),
			wantErr:     true,
			errMsg:      "failed to delete entry",
		},
		"delete without username": {
			service:     "test-service",
			username:    "",
			entryType:   EntryTypeAPIKey,
			expectedKey: "sesh-password/api_key/test-service",
			wantErr:     false,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// Setup mock expectations
			mockKeychain.DeleteEntryFunc = func(account, service string) error {
				if account != testUser {
					t.Errorf("Expected account %q, got %q", testUser, account)
				}
				if service != tc.expectedKey {
					t.Errorf("Expected service key %q, got %q", tc.expectedKey, service)
				}
				if tc.deleteErr != nil {
					return tc.deleteErr
				}
				return nil
			}

			mockKeychain.RemoveEntryMetadataFunc = func(servicePrefix, service, account string) error {
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

	type expectedEntry struct {
		service   string
		username  string
		typ       EntryType
		createdAt time.Time
		updatedAt time.Time
	}

	createdTime := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	updatedTime := time.Date(2026, 3, 1, 14, 30, 0, 0, time.UTC)

	testCases := map[string]struct {
		mockEntries []keychain.KeychainEntry
		mockMeta    []keychain.KeychainEntryMeta
		listErr     error
		expected    []expectedEntry
		wantErr     bool
		errMsg      string
	}{
		"successful list with timestamps": {
			mockEntries: []keychain.KeychainEntry{
				{
					Service:     "sesh-password/password/github/user1",
					Account:     testUser,
					Description: "password for github",
				},
				{
					Service:     "sesh-password/totp/aws/root",
					Account:     testUser,
					Description: "totp for aws",
				},
			},
			mockMeta: []keychain.KeychainEntryMeta{
				{
					Service:     "sesh-password/password/github/user1",
					Account:     testUser,
					ServiceType: "sesh-password",
					CreatedAt:   createdTime,
					UpdatedAt:   updatedTime,
				},
				{
					Service:     "sesh-password/totp/aws/root",
					Account:     testUser,
					ServiceType: "sesh-password",
					CreatedAt:   createdTime,
					UpdatedAt:   createdTime,
				},
			},
			expected: []expectedEntry{
				{service: "github", username: "user1", typ: EntryTypePassword, createdAt: createdTime, updatedAt: updatedTime},
				{service: "aws", username: "root", typ: EntryTypeTOTP, createdAt: createdTime, updatedAt: createdTime},
			},
		},
		"empty list": {
			mockEntries: []keychain.KeychainEntry{},
			expected:    []expectedEntry{},
		},
		"keychain error": {
			listErr: errors.New("keychain access denied"),
			wantErr: true,
			errMsg:  "failed to list entries",
		},
		"invalid entries are skipped": {
			mockEntries: []keychain.KeychainEntry{
				{
					Service:     "sesh-password/password/github/user1",
					Account:     testUser,
					Description: "password for github",
				},
				{
					Service:     "invalid-entry",
					Account:     testUser,
					Description: "invalid",
				},
				{
					Service:     "sesh-password/totp/aws/root",
					Account:     testUser,
					Description: "totp for aws",
				},
			},
			expected: []expectedEntry{
				{service: "github", username: "user1", typ: EntryTypePassword},
				{service: "aws", username: "root", typ: EntryTypeTOTP},
			},
		},
		"other accounts are skipped": {
			mockEntries: []keychain.KeychainEntry{
				{
					Service:     "sesh-password/password/github/user1",
					Account:     testUser,
					Description: "password for github",
				},
				{
					Service:     "sesh-password/password/gitlab/other",
					Account:     "someone-else",
					Description: "password for gitlab",
				},
			},
			expected: []expectedEntry{
				{service: "github", username: "user1", typ: EntryTypePassword},
			},
		},
		"entry without username": {
			mockEntries: []keychain.KeychainEntry{
				{
					Service:     "sesh-password/api_key/stripe",
					Account:     testUser,
					Description: "api_key for stripe",
				},
			},
			expected: []expectedEntry{
				{service: "stripe", username: "", typ: EntryTypeAPIKey},
			},
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

			mockKeychain.LoadEntryMetadataFunc = func(servicePrefix string) ([]keychain.KeychainEntryMeta, error) {
				if tc.mockMeta != nil {
					return tc.mockMeta, nil
				}
				return []keychain.KeychainEntryMeta{}, nil
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
				if len(entries) != len(tc.expected) {
					t.Fatalf("Expected %d entries, got %d", len(tc.expected), len(entries))
				}

				for i, want := range tc.expected {
					if entries[i].Service != want.service {
						t.Errorf("Entry %d: expected service %q, got %q", i, want.service, entries[i].Service)
					}
					if entries[i].Username != want.username {
						t.Errorf("Entry %d: expected username %q, got %q", i, want.username, entries[i].Username)
					}
					if entries[i].Type != want.typ {
						t.Errorf("Entry %d: expected type %q, got %q", i, want.typ, entries[i].Type)
					}
					if !entries[i].CreatedAt.Equal(want.createdAt) {
						t.Errorf("Entry %d: expected CreatedAt %v, got %v", i, want.createdAt, entries[i].CreatedAt)
					}
					if !entries[i].UpdatedAt.Equal(want.updatedAt) {
						t.Errorf("Entry %d: expected UpdatedAt %v, got %v", i, want.updatedAt, entries[i].UpdatedAt)
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
		service      string
		username     string
		expectedKey  string
		storedSecret []byte
		getSecretErr error
		wantErr      bool
		errMsg       string
	}{
		"valid TOTP generation": {
			service:      "github",
			username:     "user",
			expectedKey:  "sesh-password/totp/github/user",
			storedSecret: []byte("JBSWY3DPEHPK3PXP"),
			wantErr:      false,
		},
		"secret not found": {
			service:      "nonexistent",
			username:     "user",
			expectedKey:  "sesh-password/totp/nonexistent/user",
			getSecretErr: errors.New("entry not found"),
			wantErr:      true,
			errMsg:       "failed to retrieve TOTP secret",
		},
		"invalid secret format": {
			service:      "github",
			username:     "user",
			expectedKey:  "sesh-password/totp/github/user",
			storedSecret: []byte("invalid!@#$"),
			wantErr:      true,
			errMsg:       "failed to generate TOTP code",
		},
		"empty secret": {
			service:      "github",
			username:     "user",
			expectedKey:  "sesh-password/totp/github/user",
			storedSecret: []byte(""),
			wantErr:      true,
			errMsg:       "failed to generate TOTP code",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// Setup mock for GetSecret
			mockKeychain.GetSecretFunc = func(account, service string) ([]byte, error) {
				if account != testUser {
					t.Errorf("Expected account %q, got %q", testUser, account)
				}
				if service != tc.expectedKey {
					t.Errorf("Expected service key %q, got %q", tc.expectedKey, service)
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
