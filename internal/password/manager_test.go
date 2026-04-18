package password

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/keychain/mocks"
	"github.com/bashhack/sesh/internal/totp"
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
		setSecretErr error
		metadataErr  error
		service      string
		username     string
		password     string
		entryType    EntryType
		expectedKey  string
		errMsg       string
		wantErr      bool
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

			// Mock SetDescription call (may fail, but non-fatal)
			mockKeychain.SetDescriptionFunc = func(service, account, description string) error {
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
		getSecretErr error
		service      string
		username     string
		entryType    EntryType
		expectedKey  string
		expected     string
		errMsg       string
		returnSecret []byte
		wantErr      bool
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

			mockKeychain.SetDescriptionFunc = func(service, account, description string) error {
				return nil
			}

			err := manager.StoreTOTPSecret(tc.service, tc.username, tc.secret)
			if err != nil {
				t.Fatalf("StoreTOTPSecret failed: %v", err)
			}
		})
	}
}

func TestStoreTOTPSecretWithParams(t *testing.T) {
	// Covers the non-default-params branch: description is serialized and
	// SetDescription is invoked with the Params JSON.
	mockKeychain := &mocks.MockProvider{}
	manager := NewManager(mockKeychain, "alice")

	var gotDesc string
	mockKeychain.SetDescriptionFunc = func(_, _, description string) error {
		gotDesc = description
		return nil
	}

	params := totp.Params{Algorithm: "SHA256", Digits: 8, Period: 60}
	if err := manager.StoreTOTPSecretWithParams("github", "alice", "JBSWY3DPEHPK3PXP", params); err != nil {
		t.Fatalf("StoreTOTPSecretWithParams: %v", err)
	}

	if !strings.Contains(gotDesc, `"algorithm":"SHA256"`) {
		t.Errorf("description should carry params JSON, got %q", gotDesc)
	}
	if !strings.Contains(gotDesc, `"digits":8`) {
		t.Errorf("description missing digits, got %q", gotDesc)
	}
}

func TestStoreTOTPSecretWithParams_InvalidSecret(t *testing.T) {
	manager := NewManager(&mocks.MockProvider{}, "alice")
	err := manager.StoreTOTPSecretWithParams("github", "alice", "not-base32!@#", totp.Params{Digits: 8})
	if err == nil || !strings.Contains(err.Error(), "invalid TOTP secret") {
		t.Errorf("want invalid-secret error, got %v", err)
	}
}

func TestStoreTOTPSecretWithParams_DescriptionFailureSurfaces(t *testing.T) {
	// Non-default params live in the description. If SetDescription fails,
	// the entry would persist with defaults and silently produce wrong
	// codes forever — the caller must see the failure.
	var descCallCount int
	mockKeychain := &mocks.MockProvider{
		SetDescriptionFunc: func(_, _, description string) error {
			descCallCount++
			// First call (from StorePassword, cosmetic label) succeeds;
			// second call (the params JSON, load-bearing) fails.
			if descCallCount == 2 {
				return errors.New("simulated keychain write failure")
			}
			return nil
		},
	}
	manager := NewManager(mockKeychain, "alice")

	err := manager.StoreTOTPSecretWithParams("github", "alice", "JBSWY3DPEHPK3PXP", totp.Params{Algorithm: "SHA256", Digits: 8, Period: 60})
	if err == nil {
		t.Fatal("expected error when params description write fails, got nil")
	}
	if !strings.Contains(err.Error(), "failed to persist params") {
		t.Errorf("error should mention params persistence failure, got: %v", err)
	}
}

func TestStoreTOTPSecretWithParams_DefaultParamsSkipsDescription(t *testing.T) {
	// Zero-valued params + no issuer ⇒ nothing to persist, so a failing
	// SetDescription on the params path must not reach this function.
	// StorePassword's cosmetic description write still runs but is
	// non-fatal upstream; we only check that the params write is skipped.
	var paramDescWriteAttempted bool
	mockKeychain := &mocks.MockProvider{
		SetDescriptionFunc: func(_, _, description string) error {
			// Params JSON starts with {; the generic label starts with totp
			if strings.HasPrefix(description, "{") {
				paramDescWriteAttempted = true
			}
			return nil
		},
	}
	manager := NewManager(mockKeychain, "alice")

	if err := manager.StoreTOTPSecretWithParams("github", "alice", "JBSWY3DPEHPK3PXP", totp.Params{}); err != nil {
		t.Fatalf("StoreTOTPSecretWithParams(default): %v", err)
	}
	if paramDescWriteAttempted {
		t.Error("default params should not trigger a params-description write")
	}
}

func TestGetTOTPParams(t *testing.T) {
	const user = "alice"
	const svcKey = "sesh-password/totp/github/alice"

	tests := map[string]struct {
		entries []keychain.KeychainEntry
		listErr error
		want    totp.Params
	}{
		"no entries returns zero params": {
			entries: nil,
			want:    totp.Params{},
		},
		"list error returns zero params": {
			listErr: errors.New("boom"),
			want:    totp.Params{},
		},
		"service mismatch returns zero params (prefix sibling)": {
			// ListEntries is a prefix query — a longer service must not
			// be accepted as the params source.
			entries: []keychain.KeychainEntry{{
				Service:     svcKey + "ish",
				Account:     user,
				Description: `{"digits":8}`,
			}},
			want: totp.Params{},
		},
		"account mismatch returns zero params": {
			entries: []keychain.KeychainEntry{{
				Service:     svcKey,
				Account:     "not-alice",
				Description: `{"digits":8}`,
			}},
			want: totp.Params{},
		},
		"exact match returns parsed params": {
			entries: []keychain.KeychainEntry{{
				Service:     svcKey,
				Account:     user,
				Description: `{"algorithm":"SHA512","digits":8,"period":60}`,
			}},
			want: totp.Params{Algorithm: "SHA512", Digits: 8, Period: 60},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			mockKeychain := &mocks.MockProvider{
				ListEntriesFunc: func(_ string) ([]keychain.KeychainEntry, error) {
					return tc.entries, tc.listErr
				},
			}
			mgr := NewManager(mockKeychain, user)
			if got := mgr.GetTOTPParams("github", user); got != tc.want {
				t.Errorf("GetTOTPParams = %+v, want %+v", got, tc.want)
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
		deleteErr   error
		service     string
		username    string
		entryType   EntryType
		expectedKey string
		errMsg      string
		wantErr     bool
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
		createdAt time.Time
		updatedAt time.Time
		service   string
		username  string
		typ       EntryType
	}

	createdTime := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	updatedTime := time.Date(2026, 3, 1, 14, 30, 0, 0, time.UTC)

	testCases := map[string]struct {
		listErr     error
		errMsg      string
		mockEntries []keychain.KeychainEntry
		expected    []expectedEntry
		wantErr     bool
	}{
		"successful list with timestamps": {
			mockEntries: []keychain.KeychainEntry{
				{
					Service:     "sesh-password/password/github/user1",
					Account:     testUser,
					Description: "password for github",
					CreatedAt:   createdTime,
					UpdatedAt:   updatedTime,
				},
				{
					Service:     "sesh-password/totp/aws/root",
					Account:     testUser,
					Description: "totp for aws",
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

func TestListEntriesFiltered(t *testing.T) {
	mockKeychain := &mocks.MockProvider{}
	testUser := "testuser"
	manager := NewManager(mockKeychain, testUser)

	allEntries := []keychain.KeychainEntry{
		{Service: "sesh-password/password/github/user1", Account: testUser, Description: "password for github"},
		{Service: "sesh-password/api_key/stripe", Account: testUser, Description: "api_key for stripe"},
		{Service: "sesh-password/password/gitlab/user2", Account: testUser, Description: "password for gitlab"},
	}

	mockKeychain.ListEntriesFunc = func(service string) ([]keychain.KeychainEntry, error) {
		return allEntries, nil
	}

	testCases := map[string]struct {
		filter   ListFilter
		expected int
	}{
		"no filter": {
			filter:   ListFilter{},
			expected: 3,
		},
		"filter by type password": {
			filter:   ListFilter{EntryType: EntryTypePassword},
			expected: 2,
		},
		"filter by type api_key": {
			filter:   ListFilter{EntryType: EntryTypeAPIKey},
			expected: 1,
		},
		"filter by service": {
			filter:   ListFilter{Service: "github"},
			expected: 1,
		},
		"limit": {
			filter:   ListFilter{Limit: 2},
			expected: 2,
		},
		"offset beyond entries": {
			filter:   ListFilter{Offset: 10},
			expected: 0,
		},
		"offset and limit": {
			filter:   ListFilter{Offset: 1, Limit: 1},
			expected: 1,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			entries, err := manager.ListEntriesFiltered(tc.filter)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(entries) != tc.expected {
				t.Errorf("expected %d entries, got %d", tc.expected, len(entries))
			}
		})
	}
}

func TestSearchEntries(t *testing.T) {
	mockKeychain := &mocks.MockProvider{}
	testUser := "testuser"
	manager := NewManager(mockKeychain, testUser)

	allEntries := []keychain.KeychainEntry{
		{Service: "sesh-password/password/github/user1", Account: testUser, Description: "password for github"},
		{Service: "sesh-password/api_key/stripe", Account: testUser, Description: "api_key for stripe"},
		{Service: "sesh-password/password/gitlab/user2", Account: testUser, Description: "password for gitlab"},
	}

	mockKeychain.ListEntriesFunc = func(service string) ([]keychain.KeychainEntry, error) {
		return allEntries, nil
	}

	testCases := map[string]struct {
		query    string
		expected int
	}{
		"match service": {
			query:    "github",
			expected: 1,
		},
		"match multiple by prefix": {
			query:    "git",
			expected: 2,
		},
		"match username": {
			query:    "user1",
			expected: 1,
		},
		"match description": {
			query:    "stripe",
			expected: 1,
		},
		"case insensitive": {
			query:    "GITHUB",
			expected: 1,
		},
		"no match": {
			query:    "nonexistent",
			expected: 0,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			entries, err := manager.SearchEntries(tc.query)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(entries) != tc.expected {
				t.Errorf("expected %d entries, got %d", tc.expected, len(entries))
			}
		})
	}
}

// mockSearchableProvider embeds MockProvider and adds SearchEntries for FTS dispatch testing.
type mockSearchableProvider struct {
	mocks.MockProvider
	SearchEntriesFunc func(query string) ([]keychain.KeychainEntry, error)
}

func (m *mockSearchableProvider) SearchEntries(query string) ([]keychain.KeychainEntry, error) {
	return m.SearchEntriesFunc(query)
}

func TestSearchEntriesWithSearcher(t *testing.T) {
	testUser := "testuser"

	testCases := map[string]struct {
		ftsErr     error
		ftsResults []keychain.KeychainEntry
		expected   int
		wantErr    bool
	}{
		"uses FTS results": {
			ftsResults: []keychain.KeychainEntry{
				{Service: "sesh-password/password/github/user1", Account: testUser},
			},
			expected: 1,
		},
		"FTS error propagates": {
			ftsErr:  errors.New("fts broken"),
			wantErr: true,
		},
		"empty FTS results": {
			ftsResults: nil,
			expected:   0,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			mock := &mockSearchableProvider{
				SearchEntriesFunc: func(query string) ([]keychain.KeychainEntry, error) {
					return tc.ftsResults, tc.ftsErr
				},
			}
			// ListEntriesFunc must be set even though it shouldn't be called
			mock.ListEntriesFunc = func(service string) ([]keychain.KeychainEntry, error) {
				t.Fatal("ListEntries should not be called when Searcher is available")
				return nil, nil
			}

			manager := NewManager(mock, testUser)
			entries, err := manager.SearchEntries("github")

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(entries) != tc.expected {
				t.Errorf("expected %d entries, got %d", tc.expected, len(entries))
			}
		})
	}
}

func TestGetPasswordsByService(t *testing.T) {
	// GetPasswordsByService is password-only: non-password entries for
	// the matching service (totp, api_key, secure_note) must be excluded,
	// and entries for other services must be excluded.
	mockKeychain := &mocks.MockProvider{}
	testUser := "testuser"
	manager := NewManager(mockKeychain, testUser)

	mockKeychain.ListEntriesFunc = func(service string) ([]keychain.KeychainEntry, error) {
		return []keychain.KeychainEntry{
			{Service: "sesh-password/password/github/user1", Account: testUser},
			{Service: "sesh-password/api_key/github/ci", Account: testUser},         // wrong type, same service
			{Service: "sesh-password/totp/github/alice", Account: testUser},         // wrong type, same service
			{Service: "sesh-password/secure_note/github/backup", Account: testUser}, // wrong type, same service
			{Service: "sesh-password/password/stripe/admin", Account: testUser},     // right type, wrong service
			{Service: "sesh-password/password/github/user2", Account: testUser},
		}, nil
	}

	entries, err := manager.GetPasswordsByService("github")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 github password entries, got %d", len(entries))
	}
	for _, e := range entries {
		if e.Service != "github" {
			t.Errorf("service = %q, want github", e.Service)
		}
		if e.Type != EntryTypePassword {
			t.Errorf("type = %q, want %q (GetPasswordsByService must filter out non-password types)", e.Type, EntryTypePassword)
		}
	}
}

func TestEntryExists(t *testing.T) {
	const user = "alice"
	const svcKey = "sesh-password/password/github/alice"

	tests := map[string]struct {
		listErr error
		entries []keychain.KeychainEntry
		want    bool
		wantErr bool
	}{
		"exact match returns true": {
			entries: []keychain.KeychainEntry{{Service: svcKey, Account: user}},
			want:    true,
		},
		"no entries returns false": {
			entries: nil,
			want:    false,
		},
		"list error surfaces": {
			listErr: errors.New("backend unreachable"),
			wantErr: true,
		},
		"prefix sibling does not register": {
			// "sesh-password/password/github/alicia" starts with the
			// service prefix but is a different entry.
			entries: []keychain.KeychainEntry{{Service: svcKey + "ish", Account: user}},
			want:    false,
		},
		"cross-user entry does not register": {
			entries: []keychain.KeychainEntry{{Service: svcKey, Account: "not-alice"}},
			want:    false,
		},
		"exact match among siblings still returns true": {
			entries: []keychain.KeychainEntry{
				{Service: svcKey + "ish", Account: user},
				{Service: svcKey, Account: user},
			},
			want: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			mockKeychain := &mocks.MockProvider{
				ListEntriesFunc: func(_ string) ([]keychain.KeychainEntry, error) {
					return tc.entries, tc.listErr
				},
			}
			mgr := NewManager(mockKeychain, user)
			got, err := mgr.EntryExists("github", user, EntryTypePassword)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("EntryExists = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGenerateTOTPCode(t *testing.T) {
	mockKeychain := &mocks.MockProvider{}
	testUser := "testuser"
	manager := NewManager(mockKeychain, testUser)

	testCases := map[string]struct {
		getSecretErr error
		service      string
		username     string
		expectedKey  string
		errMsg       string
		storedSecret []byte
		wantErr      bool
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
			// GetTOTPParams calls ListEntries — return empty so defaults are used
			mockKeychain.ListEntriesFunc = func(service string) ([]keychain.KeychainEntry, error) {
				return nil, nil
			}

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
