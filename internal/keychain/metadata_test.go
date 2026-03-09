package keychain

import (
	"testing"
)

func TestMetadataFunctions(t *testing.T) {
	tests := map[string]struct {
		input    string
		expected string
	}{
		"totp service": {
			input:    "sesh-totp-gmail",
			expected: "sesh-totp",
		},
		"aws service": {
			input:    "sesh-aws-default",
			expected: "sesh-aws",
		},
		"unknown service": {
			input:    "sesh-unknown-service",
			expected: "sesh-unknown",
		},
		"invalid service": {
			input:    "invalid",
			expected: "invalid",
		},
		"slash-based password key": {
			input:    "sesh-password/password/github/alice",
			expected: "sesh-password",
		},
		"slash-based totp key": {
			input:    "sesh-totp/github/personal",
			expected: "sesh-totp",
		},
		"slash-based aws key": {
			input:    "sesh-aws/production",
			expected: "sesh-aws",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := getServicePrefix(tc.input)
			if result != tc.expected {
				t.Errorf("getServicePrefix(%s) = %s, want %s", tc.input, result, tc.expected)
			}
		})
	}
}
