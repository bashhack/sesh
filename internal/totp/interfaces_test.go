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

	if len(code1) != 6 {
		t.Errorf("First code length = %d, want 6", len(code1))
	}
	if len(code2) != 6 {
		t.Errorf("Second code length = %d, want 6", len(code2))
	}
}

func TestDefaultProviderGenerateConsecutiveCodesForTime(t *testing.T) {
	testSecret := "JBSWY3DPEHPK3PXP"
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	provider := NewDefaultProvider()
	current, next, err := provider.GenerateConsecutiveCodesForTime(testSecret, baseTime)

	if err != nil {
		t.Errorf("GenerateConsecutiveCodesForTime failed with error: %v", err)
		return
	}

	wantCurrent, err := provider.GenerateForTime(testSecret, baseTime)
	if err != nil {
		t.Fatalf("GenerateForTime (current) failed: %v", err)
	}
	wantNext, err := provider.GenerateForTime(testSecret, baseTime.Add(30*time.Second))
	if err != nil {
		t.Fatalf("GenerateForTime (next) failed: %v", err)
	}

	if current != wantCurrent {
		t.Errorf("current = %q, want %q", current, wantCurrent)
	}
	if next != wantNext {
		t.Errorf("next = %q, want %q", next, wantNext)
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

	if len(code1) != 6 {
		t.Errorf("First code length = %d, want 6", len(code1))
	}
	if len(code2) != 6 {
		t.Errorf("Second code length = %d, want 6", len(code2))
	}
}

func TestDefaultProviderGenerateConsecutiveCodesForTimeBytes(t *testing.T) {
	testSecret := []byte("JBSWY3DPEHPK3PXP")
	baseTime := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	provider := NewDefaultProvider()
	current, next, err := provider.GenerateConsecutiveCodesForTimeBytes(testSecret, baseTime)

	if err != nil {
		t.Errorf("GenerateConsecutiveCodesForTimeBytes failed with error: %v", err)
		return
	}

	wantCurrent, err := provider.GenerateForTimeBytes(testSecret, baseTime)
	if err != nil {
		t.Fatalf("GenerateForTimeBytes (current) failed: %v", err)
	}
	wantNext, err := provider.GenerateForTimeBytes(testSecret, baseTime.Add(30*time.Second))
	if err != nil {
		t.Fatalf("GenerateForTimeBytes (next) failed: %v", err)
	}

	if current != wantCurrent {
		t.Errorf("current = %q, want %q", current, wantCurrent)
	}
	if next != wantNext {
		t.Errorf("next = %q, want %q", next, wantNext)
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
