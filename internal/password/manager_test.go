package password

import (
	"context"
	"strings"
	"testing"

	"github.com/joshmedeski/sesh/internal/keychain"
	"github.com/joshmedeski/sesh/internal/keychain/mocks"
	"github.com/joshmedeski/sesh/internal/totp"
	totp_mocks "github.com/joshmedeski/sesh/internal/totp/mocks"
)

func TestNewManager(t *testing.T) {
	mockKeychain := &mocks.MockKeychain{}
	mockTOTP := &totp_mocks.MockTOTP{}
	
	manager := NewManager(mockKeychain, mockTOTP)
	
	if manager == nil {
		t.Fatal("NewManager returned nil")
	}
	if manager.keychain != mockKeychain {
		t.Error("Manager keychain not set correctly")
	}
	if manager.totp != mockTOTP {
		t.Error("Manager TOTP not set correctly")
	}
}

func TestStoreAndGetPassword(t *testing.T) {
	mockKeychain := &mocks.MockKeychain{}
	mockTOTP := &totp_mocks.MockTOTP{}
	manager := NewManager(mockKeychain, mockTOTP)
	
	ctx := context.Background()
	testCases := []struct {
		name     string
		key      string
		password string
		wantErr  bool
	}{
		{
			name:     "valid password storage",
			key:      "test-service",
			password: "secretpassword123",
			wantErr:  false,
		},
		{
			name:     "empty key",
			key:      "",
			password: "password",
			wantErr:  true,
		},
		{
			name:     "empty password",
			key:      "test-service",
			password: "",
			wantErr:  true,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantErr {
				err := manager.StorePassword(ctx, tc.key, tc.password)
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}
			
			// Setup mock expectations
			expectedKey := "sesh:password:" + tc.key
			mockKeychain.On("Store", expectedKey, []byte(tc.password)).Return(nil)
			mockKeychain.On("Get", expectedKey).Return([]byte(tc.password), nil)
			
			// Store password
			err := manager.StorePassword(ctx, tc.key, tc.password)
			if err != nil {
				t.Fatalf("StorePassword failed: %v", err)
			}
			
			// Retrieve password
			retrieved, err := manager.GetPassword(ctx, tc.key)
			if err != nil {
				t.Fatalf("GetPassword failed: %v", err)
			}
			
			if retrieved != tc.password {
				t.Errorf("Retrieved password %q doesn't match stored %q", retrieved, tc.password)
			}
			
			// Verify all expectations were met
			mockKeychain.AssertExpectations(t)
		})
	}
}

func TestStoreTOTPSecret(t *testing.T) {
	mockKeychain := &mocks.MockKeychain{}
	mockTOTP := &totp_mocks.MockTOTP{}
	manager := NewManager(mockKeychain, mockTOTP)
	
	ctx := context.Background()
	testCases := []struct {
		name         string
		key          string
		secret       string
		validateResp string
		validateErr  error
		wantErr      bool
	}{
		{
			name:         "valid TOTP secret",
			key:          "github-account",
			secret:       "JBSWY3DPEHPK3PXP",
			validateResp: "JBSWY3DPEHPK3PXP",
			validateErr:  nil,
			wantErr:      false,
		},
		{
			name:        "invalid TOTP secret",
			key:         "github-account",
			secret:      "invalid-secret",
			validateErr: totp.ErrInvalidSecret,
			wantErr:     true,
		},
		{
			name:    "empty key",
			key:     "",
			secret:  "JBSWY3DPEHPK3PXP",
			wantErr: true,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantErr && tc.key == "" {
				err := manager.StoreTOTPSecret(ctx, tc.key, tc.secret)
				if err == nil {
					t.Error("Expected error for empty key but got none")
				}
				return
			}
			
			if tc.validateErr != nil {
				// Mock validation failure
				mockTOTP.On("ValidateAndNormalizeSecret", tc.secret).Return("", tc.validateErr)
				
				err := manager.StoreTOTPSecret(ctx, tc.key, tc.secret)
				if err == nil {
					t.Error("Expected validation error but got none")
				}
				if !strings.Contains(err.Error(), "invalid TOTP secret") {
					t.Errorf("Expected validation error message, got: %v", err)
				}
				
				mockTOTP.AssertExpectations(t)
				return
			}
			
			// Setup successful validation and storage
			expectedKey := "sesh:totp:" + tc.key
			mockTOTP.On("ValidateAndNormalizeSecret", tc.secret).Return(tc.validateResp, nil)
			mockKeychain.On("Store", expectedKey, []byte(tc.validateResp)).Return(nil)
			
			err := manager.StoreTOTPSecret(ctx, tc.key, tc.secret)
			if err != nil {
				t.Fatalf("StoreTOTPSecret failed: %v", err)
			}
			
			mockTOTP.AssertExpectations(t)
			mockKeychain.AssertExpectations(t)
		})
	}
}

func TestGenerateTOTPCode(t *testing.T) {
	mockKeychain := &mocks.MockKeychain{}
	mockTOTP := &totp_mocks.MockTOTP{}
	manager := NewManager(mockKeychain, mockTOTP)
	
	ctx := context.Background()
	testKey := "github-account"
	testSecret := "JBSWY3DPEHPK3PXP"
	expectedCode := "123456"
	
	// Setup mock expectations
	keychainKey := "sesh:totp:" + testKey
	mockKeychain.On("Get", keychainKey).Return([]byte(testSecret), nil)
	mockTOTP.On("GenerateCode", testSecret).Return(expectedCode, nil)
	
	code, err := manager.GenerateTOTPCode(ctx, testKey)
	if err != nil {
		t.Fatalf("GenerateTOTPCode failed: %v", err)
	}
	
	if code != expectedCode {
		t.Errorf("Generated code %q doesn't match expected %q", code, expectedCode)
	}
	
	mockKeychain.AssertExpectations(t)
	mockTOTP.AssertExpectations(t)
}

func TestListEntries(t *testing.T) {
	mockKeychain := &mocks.MockKeychain{}
	mockTOTP := &totp_mocks.MockTOTP{}
	manager := NewManager(mockKeychain, mockTOTP)
	
	ctx := context.Background()
	
	// Setup mock keychain with various entry types
	mockKeys := []string{
		"sesh:password:service1",
		"sesh:password:service2",
		"sesh:totp:github",
		"sesh:api_key:aws",
		"sesh:secure_note:backup-codes",
		"other:unrelated:key", // Should be filtered out
	}
	
	mockKeychain.On("List", "sesh:").Return(mockKeys, nil)
	
	entries, err := manager.ListEntries(ctx)
	if err != nil {
		t.Fatalf("ListEntries failed: %v", err)
	}
	
	expectedEntries := []Entry{
		{Key: "service1", Type: EntryTypePassword},
		{Key: "service2", Type: EntryTypePassword},
		{Key: "github", Type: EntryTypeTOTP},
		{Key: "aws", Type: EntryTypeAPIKey},
		{Key: "backup-codes", Type: EntryTypeSecureNote},
	}
	
	if len(entries) != len(expectedEntries) {
		t.Fatalf("Expected %d entries, got %d", len(expectedEntries), len(entries))
	}
	
	for i, expected := range expectedEntries {
		if entries[i].Key != expected.Key || entries[i].Type != expected.Type {
			t.Errorf("Entry %d: expected %+v, got %+v", i, expected, entries[i])
		}
	}
	
	mockKeychain.AssertExpectations(t)
}

func TestDeleteEntry(t *testing.T) {
	mockKeychain := &mocks.MockKeychain{}
	mockTOTP := &totp_mocks.MockTOTP{}
	manager := NewManager(mockKeychain, mockTOTP)
	
	ctx := context.Background()
	testCases := []struct {
		name       string
		key        string
		entryType  EntryType
		expectKey  string
		wantErr    bool
	}{
		{
			name:      "delete password",
			key:       "service1",
			entryType: EntryTypePassword,
			expectKey: "sesh:password:service1",
			wantErr:   false,
		},
		{
			name:      "delete TOTP",
			key:       "github",
			entryType: EntryTypeTOTP,
			expectKey: "sesh:totp:github",
			wantErr:   false,
		},
		{
			name:      "empty key",
			key:       "",
			entryType: EntryTypePassword,
			wantErr:   true,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantErr {
				err := manager.DeleteEntry(ctx, tc.key, tc.entryType)
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}
			
			mockKeychain.On("Delete", tc.expectKey).Return(nil)
			
			err := manager.DeleteEntry(ctx, tc.key, tc.entryType)
			if err != nil {
				t.Fatalf("DeleteEntry failed: %v", err)
			}
			
			mockKeychain.AssertExpectations(t)
		})
	}
}

func TestMemorySecurityDefensiveCopying(t *testing.T) {
	mockKeychain := &mocks.MockKeychain{}
	mockTOTP := &totp_mocks.MockTOTP{}
	manager := NewManager(mockKeychain, mockTOTP)
	
	ctx := context.Background()
	testKey := "test-service"
	originalPassword := "secretpassword123"
	
	// Setup mock to return a byte slice that we can modify
	passwordBytes := []byte(originalPassword)
	mockKeychain.On("Store", "sesh:password:"+testKey, passwordBytes).Return(nil)
	mockKeychain.On("Get", "sesh:password:"+testKey).Return(passwordBytes, nil)
	
	// Store password
	err := manager.StorePassword(ctx, testKey, originalPassword)
	if err != nil {
		t.Fatalf("StorePassword failed: %v", err)
	}
	
	// Modify the original bytes to simulate security concern
	for i := range passwordBytes {
		passwordBytes[i] = 'X'
	}
	
	// Retrieve password - should be unaffected by the modification
	retrieved, err := manager.GetPassword(ctx, testKey)
	if err != nil {
		t.Fatalf("GetPassword failed: %v", err)
	}
	
	if retrieved != originalPassword {
		t.Errorf("Retrieved password was affected by byte slice modification: got %q, want %q", retrieved, originalPassword)
	}
	
	mockKeychain.AssertExpectations(t)
}