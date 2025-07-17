package keychain

import (
	"testing"
)

func TestMetadataFunctions(t *testing.T) {
	services := []struct {
		input    string
		expected string
	}{
		{"sesh-totp-gmail", "sesh-totp"},
		{"sesh-aws-default", "sesh-aws"},
		{"sesh-unknown-service", "sesh-unknown"},
		{"invalid", "invalid"},
	}

	for _, s := range services {
		result := getServicePrefix(s.input)
		if result != s.expected {
			t.Errorf("getServicePrefix(%s) = %s, want %s", s.input, result, s.expected)
		}
	}
}
