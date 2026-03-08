package totp

import (
	"testing"
	"time"
)

func TestNewDefaultProvider(t *testing.T) {
	provider := NewDefaultProvider()

	_, ok := provider.(*DefaultProvider)
	if !ok {
		t.Errorf("Expected *DefaultProvider, got %T", provider)
	}
}

func TestDefaultProviderImplementsProvider(t *testing.T) {
	// Compile-time check that DefaultProvider implements Provider
	var _ Provider = (*DefaultProvider)(nil)
}

func TestDefaultProviderGenerate(t *testing.T) {
	// Invoking with a known test secret
	// Ref: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
	testSecret := "JBSWY3DPEHPK3PXP"

	provider := NewDefaultProvider()
	_, err := provider.Generate(testSecret)

	// ...just checking it can successfully generate a code
	if err != nil {
		t.Errorf("Generate failed with error: %v", err)
	}
}

func TestDefaultProviderGenerateConsecutiveCodes(t *testing.T) {
	testSecret := "JBSWY3DPEHPK3PXP"

	provider := NewDefaultProvider()
	code1, code2, err := provider.GenerateConsecutiveCodes(testSecret)

	if err != nil {
		t.Errorf("GenerateConsecutiveCodes failed with error: %v", err)
	}

	if code1 == "" {
		t.Error("First code is empty")
	}
	if code2 == "" {
		t.Error("Second code is empty")
	}

	// Check that they're different (should be, as they're for different time periods)
	if code1 == code2 {
		t.Errorf("Expected different codes, got %s and %s", code1, code2)
	}
}

func TestDefaultProviderGenerateForTime(t *testing.T) {
	testSecret := "JBSWY3DPEHPK3PXP"
	testTime := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)

	provider := NewDefaultProvider()
	code, err := provider.GenerateForTime(testSecret, testTime)

	if err != nil {
		t.Errorf("GenerateForTime failed with error: %v", err)
	}

	if code == "" {
		t.Error("Generated code is empty")
	}

	// Verify it generates 6 digit code
	if len(code) != 6 {
		t.Errorf("Expected 6 digit code, got %s (length %d)", code, len(code))
	}
}

func TestDefaultProviderGenerateSecure(t *testing.T) {
	testSecret := "JBSWY3DPEHPK3PXP"

	provider := NewDefaultProvider()
	code, err := provider.GenerateSecure(testSecret)

	if err != nil {
		t.Errorf("GenerateSecure failed with error: %v", err)
	}

	if code == "" {
		t.Error("Generated code is empty")
	}

	// Verify it generates 6 digit code
	if len(code) != 6 {
		t.Errorf("Expected 6 digit code, got %s (length %d)", code, len(code))
	}
}

func TestDefaultProviderGenerateForTimeSecure(t *testing.T) {
	testSecret := "JBSWY3DPEHPK3PXP"
	testTime := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)

	provider := NewDefaultProvider()
	code, err := provider.GenerateForTimeSecure(testSecret, testTime)

	if err != nil {
		t.Errorf("GenerateForTimeSecure failed with error: %v", err)
	}

	if code == "" {
		t.Error("Generated code is empty")
	}

	// Verify it generates 6 digit code
	if len(code) != 6 {
		t.Errorf("Expected 6 digit code, got %s (length %d)", code, len(code))
	}
}

func TestDefaultProviderGenerateBytes(t *testing.T) {
	testSecret := []byte("JBSWY3DPEHPK3PXP")

	provider := NewDefaultProvider()
	code, err := provider.GenerateBytes(testSecret)

	if err != nil {
		t.Errorf("GenerateBytes failed with error: %v", err)
	}

	if code == "" {
		t.Error("Generated code is empty")
	}

	// Verify it generates 6 digit code
	if len(code) != 6 {
		t.Errorf("Expected 6 digit code, got %s (length %d)", code, len(code))
	}
}

func TestDefaultProviderGenerateConsecutiveCodesBytes(t *testing.T) {
	testSecret := []byte("JBSWY3DPEHPK3PXP")

	provider := NewDefaultProvider()
	code1, code2, err := provider.GenerateConsecutiveCodesBytes(testSecret)

	if err != nil {
		t.Errorf("GenerateConsecutiveCodesBytes failed with error: %v", err)
	}

	if code1 == "" {
		t.Error("First code is empty")
	}
	if code2 == "" {
		t.Error("Second code is empty")
	}

	// Check that they're different (should be, as they're for different time periods)
	if code1 == code2 {
		t.Errorf("Expected different codes, got %s and %s", code1, code2)
	}
}

func TestDefaultProviderGenerateForTimeBytes(t *testing.T) {
	testSecret := []byte("JBSWY3DPEHPK3PXP")
	testTime := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)

	provider := NewDefaultProvider()
	code, err := provider.GenerateForTimeBytes(testSecret, testTime)

	if err != nil {
		t.Errorf("GenerateForTimeBytes failed with error: %v", err)
	}

	if code == "" {
		t.Error("Generated code is empty")
	}

	// Verify it generates 6 digit code
	if len(code) != 6 {
		t.Errorf("Expected 6 digit code, got %s (length %d)", code, len(code))
	}
}
