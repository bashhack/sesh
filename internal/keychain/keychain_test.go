package keychain

import (
	"os"
	"testing"
)

func TestGetSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping keychain test in short mode")
	}

	if os.Getenv("CI") == "true" || os.Getenv("SKIP_KEYCHAIN_TESTS") == "true" {
		t.Skip("Skipping keychain test in CI environment")
	}

	nonExistentService := "test-sesh-nonexistent-" + randomString(8)

	_, err := GetSecret("", nonExistentService)
	if err == nil {
		t.Error("Expected error for non-existent keychain item, got nil")
	}
}

func TestGetMFASerial(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping keychain test in short mode")
	}

	if os.Getenv("CI") == "true" || os.Getenv("SKIP_KEYCHAIN_TESTS") == "true" {
		t.Skip("Skipping keychain test in CI environment")
	}

	_, err := GetMFASerial("") // should use `whoami`...
	// ...doesn't really matter here that if it succeeds or fails, just that it doesn't panic!
	_ = err
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[i%len(charset)]
	}
	return string(result)
}
