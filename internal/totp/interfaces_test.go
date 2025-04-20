package totp

import (
	"testing"
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
