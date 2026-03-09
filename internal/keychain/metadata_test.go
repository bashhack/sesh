package keychain

import (
	"testing"
)

func TestMetadataFunctions(t *testing.T) {
	tests := map[string]struct {
		input    string
		expected string
	}{
		"fixed key without segments": {
			input:    "sesh-mfa",
			expected: "sesh-mfa",
		},
		"fixed key returned as-is": {
			input:    "sesh-metadata",
			expected: "sesh-metadata",
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
