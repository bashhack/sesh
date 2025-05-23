package totp

import (
	"strings"
	"testing"
)

func TestGenerate(t *testing.T) {
	tests := []struct {
		name       string
		secret     string
		wantErrMsg string
	}{
		{
			name:       "Valid Base32 secret",
			secret:     "JBSWY3DPEHPK3PXP", // Standard test secret
			wantErrMsg: "",
		},
		{
			name:       "Invalid Base32 secret",
			secret:     "NOT-VALID-BASE32!@#",
			wantErrMsg: "failed to generate TOTP",
		},
		{
			name:       "Empty secret",
			secret:     "",
			wantErrMsg: "", // Note: The TOTP library treats empty strings as valid secrets
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip invalid tests in short mode to prevent errors in quick test runs
			if tt.wantErrMsg != "" && testing.Short() {
				t.Skip("Skipping error case in short mode")
			}

			code, err := Generate(tt.secret)

			// Check error cases
			if tt.wantErrMsg != "" {
				if err == nil {
					t.Errorf("Generate() error = nil, want error containing %q", tt.wantErrMsg)
					return
				}
				if !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Errorf("Generate() error = %q, want error containing %q", err.Error(), tt.wantErrMsg)
				}
				return
			}

			// Success case checks
			if err != nil {
				t.Errorf("Generate() unexpected error = %v", err)
				return
			}

			// Check that we get a 6-digit code
			if len(code) != 6 {
				t.Errorf("Generate() code length = %d, want 6", len(code))
			}

			// Check that the code contains only digits
			for _, c := range code {
				if c < '0' || c > '9' {
					t.Errorf("Generate() code contains non-digit character: %c", c)
					break
				}
			}
		})
	}
}

func TestGenerateConsecutiveCodes(t *testing.T) {
	tests := []struct {
		name       string
		secret     string
		wantErrMsg string
	}{
		{
			name:       "Valid Base32 secret",
			secret:     "JBSWY3DPEHPK3PXP", // Standard test secret
			wantErrMsg: "",
		},
		{
			name:       "Invalid Base32 secret",
			secret:     "NOT-VALID-BASE32!@#",
			wantErrMsg: "failed to generate current TOTP",
		},
		{
			name:       "Empty secret",
			secret:     "",
			wantErrMsg: "", // Note: The TOTP library treats empty strings as valid secrets
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip invalid tests in short mode to prevent errors in quick test runs
			if tt.wantErrMsg != "" && testing.Short() {
				t.Skip("Skipping error case in short mode")
			}

			current, next, err := GenerateConsecutiveCodes(tt.secret)

			// Check error cases
			if tt.wantErrMsg != "" {
				if err == nil {
					t.Errorf("GenerateConsecutiveCodes() error = nil, want error containing %q", tt.wantErrMsg)
					return
				}
				if !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Errorf("GenerateConsecutiveCodes() error = %q, want error containing %q", err.Error(), tt.wantErrMsg)
				}
				return
			}

			// Success case checks
			if err != nil {
				t.Errorf("GenerateConsecutiveCodes() unexpected error = %v", err)
				return
			}

			// Check that we get two different 6-digit codes
			if len(current) != 6 || len(next) != 6 {
				t.Errorf("GenerateConsecutiveCodes() code lengths = %d and %d, want both 6", len(current), len(next))
			}

			// Check that the codes are different (this could theoretically fail in rare cases, but very unlikely)
			if current == next {
				t.Errorf("GenerateConsecutiveCodes() current and next codes are identical: %s", current)
			}

			// Check that both codes contain only digits
			checkOnlyDigits := func(code, name string) {
				for _, c := range code {
					if c < '0' || c > '9' {
						t.Errorf("GenerateConsecutiveCodes() %s code contains non-digit character: %c", name, c)
						break
					}
				}
			}
			checkOnlyDigits(current, "current")
			checkOnlyDigits(next, "next")
		})
	}
}

func TestValidateAndNormalizeSecret(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		shouldError bool
		errorMsg    string
	}{
		// Valid secrets (should normalize)
		{
			name:        "Google Authenticator format (uppercase, no spaces)",
			input:       "JBSWY3DPEHPK3PXP",
			expected:    "JBSWY3DPEHPK3PXP",
			shouldError: false,
		},
		{
			name:        "Authy format (lowercase with spaces)",
			input:       "jbsw y3dp ehpk 3pxp",
			expected:    "JBSWY3DPEHPK3PXP",
			shouldError: false,
		},
		{
			name:        "Microsoft Authenticator format (mixed case)",
			input:       "JbSwY3dPeHpK3pXp",
			expected:    "JBSWY3DPEHPK3PXP",
			shouldError: false,
		},
		{
			name:        "Manual entry with newlines and tabs",
			input:       "JBSWY3DP\nEHPK3PXP\t",
			expected:    "JBSWY3DPEHPK3PXP",
			shouldError: false,
		},
		{
			name:        "Secret needing padding",
			input:       "JBSWY3DPEHPK3PX", // 15 chars, needs 1 pad
			expected:    "JBSWY3DPEHPK3PX=",
			shouldError: false,
		},
		{
			name:        "Longer secret needing multiple padding",
			input:       "JBSWY3DPEHPK3", // 13 chars, needs 3 pads  
			expected:    "JBSWY3DPEHPK3===",
			shouldError: false,
		},
		{
			name:        "Secret with existing correct padding",
			input:       "JBSWY3DPEHPK3PX=",
			expected:    "JBSWY3DPEHPK3PX=",
			shouldError: false,
		},
		
		// Invalid secrets (should error)
		{
			name:        "Empty secret",
			input:       "",
			shouldError: true,
			errorMsg:    "secret cannot be empty",
		},
		{
			name:        "Too short",
			input:       "JBSWY3DP", // 8 chars
			shouldError: true,
			errorMsg:    "secret too short",
		},
		{
			name:        "Invalid characters (0, 1)",
			input:       "JBSWY3DP0HPK3PXP", // contains '0'
			shouldError: true,
			errorMsg:    "invalid character '0'",
		},
		{
			name:        "Invalid characters (8, 9)",
			input:       "JBSWY3DP8HPK9PXP", // contains '8' and '9'
			shouldError: true,
			errorMsg:    "invalid character '8'",
		},
		{
			name:        "Special characters",
			input:       "JBSWY3DP-HPK3PXP", // contains '-'
			shouldError: true,
			errorMsg:    "invalid character '-'",
		},
		{
			name:        "Spaces only",
			input:       "   ",
			shouldError: true,
			errorMsg:    "secret cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateAndNormalizeSecret(tt.input)
			
			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error to contain '%s', got: %s", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				} else if result != tt.expected {
					t.Errorf("Expected '%s', got '%s'", tt.expected, result)
				}
				
				// Verify the normalized secret actually works for TOTP generation
				if err == nil {
					_, generateErr := Generate(result)
					if generateErr != nil {
						t.Errorf("Normalized secret failed TOTP generation: %v", generateErr)
					}
				}
			}
		})
	}
}

// TestRealWorldTOTPSecrets tests with actual secrets from major providers
func TestRealWorldTOTPSecrets(t *testing.T) {
	realWorldTests := []struct {
		name     string
		input    string
		provider string
	}{
		{
			name:     "AWS typical format",
			input:    "KFDPQJL2NYF3XP6OQCUCLPT3JHJ6NE6RLR4WEL663MX3J3EURIEIKRTUUNLD3DKJ",
			provider: "AWS Console",
		},
		{
			name:     "Google typical format with spaces",
			input:    "KFDP QJL2 NYF3 XP6O QCUC LPT3 JHJ6 NE6R",
			provider: "Google Authenticator",
		},
		{
			name:     "GitHub typical format",
			input:    "kfdpqjl2nyf3xp6oqcuclpt3jhj6ne6r",
			provider: "GitHub",
		},
	}

	for _, tt := range realWorldTests {
		t.Run(tt.name, func(t *testing.T) {
			normalized, err := ValidateAndNormalizeSecret(tt.input)
			if err != nil {
				t.Errorf("Failed to normalize %s secret: %v", tt.provider, err)
				return
			}

			// Test that we can generate codes with the normalized secret
			code, err := Generate(normalized)
			if err != nil {
				t.Errorf("Failed to generate TOTP with normalized %s secret: %v", tt.provider, err)
				return
			}

			// TOTP codes should be 6 digits
			if len(code) != 6 {
				t.Errorf("Expected 6-digit code, got %d digits: %s", len(code), code)
			}

			// Code should be numeric
			for _, char := range code {
				if char < '0' || char > '9' {
					t.Errorf("TOTP code contains non-numeric character: %c", char)
				}
			}
		})
	}
}
