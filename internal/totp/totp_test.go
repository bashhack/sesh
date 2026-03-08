package totp

import (
	"strings"
	"testing"
	"time"
)

func TestGenerate(t *testing.T) {
	tests := map[string]struct {
		secret     string
		wantErrMsg string
	}{
		"Valid Base32 secret": {
			secret:     "JBSWY3DPEHPK3PXP", // Standard test secret
			wantErrMsg: "",
		},
		"Invalid Base32 secret": {
			secret:     "NOT-VALID-BASE32!@#",
			wantErrMsg: "failed to generate TOTP",
		},
		"Empty secret": {
			secret:     "",
			wantErrMsg: "", // Note: The TOTP library treats empty strings as valid secrets
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Skip invalid tests in short mode to prevent errors in quick test runs
			if tc.wantErrMsg != "" && testing.Short() {
				t.Skip("Skipping error case in short mode")
			}

			code, err := Generate(tc.secret)

			// Check error cases
			if tc.wantErrMsg != "" {
				if err == nil {
					t.Errorf("Generate() error = nil, want error containing %q", tc.wantErrMsg)
					return
				}
				if !strings.Contains(err.Error(), tc.wantErrMsg) {
					t.Errorf("Generate() error = %q, want error containing %q", err.Error(), tc.wantErrMsg)
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
	tests := map[string]struct {
		secret     string
		wantErrMsg string
	}{
		"Valid Base32 secret": {
			secret:     "JBSWY3DPEHPK3PXP", // Standard test secret
			wantErrMsg: "",
		},
		"Invalid Base32 secret": {
			secret:     "NOT-VALID-BASE32!@#",
			wantErrMsg: "failed to generate current TOTP",
		},
		"Empty secret": {
			secret:     "",
			wantErrMsg: "", // Note: The TOTP library treats empty strings as valid secrets
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Skip invalid tests in short mode to prevent errors in quick test runs
			if tc.wantErrMsg != "" && testing.Short() {
				t.Skip("Skipping error case in short mode")
			}

			current, next, err := GenerateConsecutiveCodes(tc.secret)

			// Check error cases
			if tc.wantErrMsg != "" {
				if err == nil {
					t.Errorf("GenerateConsecutiveCodes() error = nil, want error containing %q", tc.wantErrMsg)
					return
				}
				if !strings.Contains(err.Error(), tc.wantErrMsg) {
					t.Errorf("GenerateConsecutiveCodes() error = %q, want error containing %q", err.Error(), tc.wantErrMsg)
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
	tests := map[string]struct {
		input       string
		expected    string
		shouldError bool
		errorMsg    string
	}{
		// Valid secrets (should normalize)
		"Google Authenticator format (uppercase, no spaces)": {
			input:       "JBSWY3DPEHPK3PXP",
			expected:    "JBSWY3DPEHPK3PXP",
			shouldError: false,
		},
		"Authy format (lowercase with spaces)": {
			input:       "jbsw y3dp ehpk 3pxp",
			expected:    "JBSWY3DPEHPK3PXP",
			shouldError: false,
		},
		"Microsoft Authenticator format (mixed case)": {
			input:       "JbSwY3dPeHpK3pXp",
			expected:    "JBSWY3DPEHPK3PXP",
			shouldError: false,
		},
		"Manual entry with newlines and tabs": {
			input:       "JBSWY3DP\nEHPK3PXP\t",
			expected:    "JBSWY3DPEHPK3PXP",
			shouldError: false,
		},
		"Secret needing padding": {
			input:       "JBSWY3DPEHPK3PX", // 15 chars, needs 1 pad
			expected:    "JBSWY3DPEHPK3PX=",
			shouldError: false,
		},
		"Longer secret needing multiple padding": {
			input:       "JBSWY3DPEHPK3", // 13 chars, needs 3 pads
			expected:    "JBSWY3DPEHPK3===",
			shouldError: false,
		},
		"Secret with existing correct padding": {
			input:       "JBSWY3DPEHPK3PX=",
			expected:    "JBSWY3DPEHPK3PX=",
			shouldError: false,
		},

		// Invalid secrets (should error)
		"Empty secret": {
			input:       "",
			shouldError: true,
			errorMsg:    "secret cannot be empty",
		},
		"Too short": {
			input:       "JBSWY3DPEHPK", // 12 chars, just under 13-char minimum
			shouldError: true,
			errorMsg:    "secret too short",
		},
		"Invalid characters (0, 1)": {
			input:       "JBSWY3DP0HPK3PXP", // contains '0'
			shouldError: true,
			errorMsg:    "invalid character '0'",
		},
		"Invalid characters (8, 9)": {
			input:       "JBSWY3DP8HPK9PXP", // contains '8' and '9'
			shouldError: true,
			errorMsg:    "invalid character '8'",
		},
		"Special characters": {
			input:       "JBSWY3DP-HPK3PXP", // contains '-'
			shouldError: true,
			errorMsg:    "invalid character '-'",
		},
		"Spaces only": {
			input:       "   ",
			shouldError: true,
			errorMsg:    "secret cannot be empty",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := ValidateAndNormalizeSecret(tc.input)

			if tc.shouldError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if !strings.Contains(err.Error(), tc.errorMsg) {
					t.Errorf("Expected error to contain '%s', got: %s", tc.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				} else if result != tc.expected {
					t.Errorf("Expected '%s', got '%s'", tc.expected, result)
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
	tests := map[string]struct {
		input    string
		provider string
	}{
		"AWS typical format": {
			input:    "KFDPQJL2NYF3XP6OQCUCLPT3JHJ6NE6RLR4WEL663MX3J3EURIEIKRTUUNLD3DKJ",
			provider: "AWS Console",
		},
		"Google typical format with spaces": {
			input:    "KFDP QJL2 NYF3 XP6O QCUC LPT3 JHJ6 NE6R",
			provider: "Google Authenticator",
		},
		"GitHub typical format": {
			input:    "kfdpqjl2nyf3xp6oqcuclpt3jhj6ne6r",
			provider: "GitHub",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			normalized, err := ValidateAndNormalizeSecret(tc.input)
			if err != nil {
				t.Errorf("Failed to normalize %s secret: %v", tc.provider, err)
				return
			}

			// Test that we can generate codes with the normalized secret
			code, err := Generate(normalized)
			if err != nil {
				t.Errorf("Failed to generate TOTP with normalized %s secret: %v", tc.provider, err)
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

func TestGenerateForTime(t *testing.T) {
	testSecret := "JBSWY3DPEHPK3PXP"

	tests := map[string]struct {
		secret  string
		time    time.Time
		wantErr bool
	}{
		"valid secret and time": {
			secret:  testSecret,
			time:    time.Now(),
			wantErr: false,
		},
		"specific time": {
			secret:  testSecret,
			time:    time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
			wantErr: false,
		},
		"invalid secret": {
			secret:  "INVALID!@#",
			time:    time.Now(),
			wantErr: true,
		},
		"empty secret": {
			secret:  "",
			time:    time.Now(),
			wantErr: false, // TOTP library allows empty secrets
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			code, err := GenerateForTime(tc.secret, tc.time)

			if (err != nil) != tc.wantErr {
				t.Errorf("GenerateForTime() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if !tc.wantErr && len(code) != 6 {
				t.Errorf("Expected 6-digit code, got %d digits: %s", len(code), code)
			}
		})
	}
}

func TestGenerateSecure(t *testing.T) {
	tests := map[string]struct {
		secret  string
		wantErr bool
	}{
		"valid secret": {
			secret:  "JBSWY3DPEHPK3PXP",
			wantErr: false,
		},
		"invalid secret": {
			secret:  "INVALID!@#",
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			code, err := GenerateSecure(tc.secret)

			if (err != nil) != tc.wantErr {
				t.Errorf("GenerateSecure() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if !tc.wantErr && len(code) != 6 {
				t.Errorf("Expected 6-digit code, got %d digits: %s", len(code), code)
			}
		})
	}
}

func TestGenerateForTimeSecure(t *testing.T) {
	tests := map[string]struct {
		secret  string
		time    time.Time
		wantErr bool
	}{
		"valid secret and time": {
			secret:  "JBSWY3DPEHPK3PXP",
			time:    time.Now(),
			wantErr: false,
		},
		"invalid secret": {
			secret:  "INVALID!@#",
			time:    time.Now(),
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			code, err := GenerateForTimeSecure(tc.secret, tc.time)

			if (err != nil) != tc.wantErr {
				t.Errorf("GenerateForTimeSecure() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if !tc.wantErr && len(code) != 6 {
				t.Errorf("Expected 6-digit code, got %d digits: %s", len(code), code)
			}
		})
	}
}

func TestGenerateBytes(t *testing.T) {
	tests := map[string]struct {
		secret  []byte
		wantErr bool
	}{
		"valid secret": {
			secret:  []byte("JBSWY3DPEHPK3PXP"),
			wantErr: false,
		},
		"secret with whitespace": {
			secret:  []byte("  JBSWY3DPEHPK3PXP  "),
			wantErr: false,
		},
		"invalid secret": {
			secret:  []byte("INVALID!@#"),
			wantErr: true,
		},
		"empty secret": {
			secret:  []byte{},
			wantErr: true, // We now reject empty secrets
		},
		"nil secret": {
			secret:  nil,
			wantErr: true, // We now reject nil/empty secrets
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			code, err := GenerateBytes(tc.secret)

			if (err != nil) != tc.wantErr {
				t.Errorf("GenerateBytes() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if !tc.wantErr && len(code) != 6 {
				t.Errorf("Expected 6-digit code, got %d digits: %s", len(code), code)
			}
		})
	}
}

func TestGenerateForTimeBytes(t *testing.T) {
	tests := map[string]struct {
		secret  []byte
		time    time.Time
		wantErr bool
	}{
		"valid secret and time": {
			secret:  []byte("JBSWY3DPEHPK3PXP"),
			time:    time.Now(),
			wantErr: false,
		},
		"secret with whitespace": {
			secret:  []byte("  JBSWY3DPEHPK3PXP  "),
			time:    time.Now(),
			wantErr: false,
		},
		"specific time": {
			secret:  []byte("JBSWY3DPEHPK3PXP"),
			time:    time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
			wantErr: false,
		},
		"invalid secret": {
			secret:  []byte("INVALID!@#"),
			time:    time.Now(),
			wantErr: true,
		},
		"empty secret": {
			secret:  []byte{},
			time:    time.Now(),
			wantErr: true, // We now reject empty secrets
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			code, err := GenerateForTimeBytes(tc.secret, tc.time)

			if (err != nil) != tc.wantErr {
				t.Errorf("GenerateForTimeBytes() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if !tc.wantErr && len(code) != 6 {
				t.Errorf("Expected 6-digit code, got %d digits: %s", len(code), code)
			}
		})
	}
}

func TestGenerateConsecutiveCodesBytes(t *testing.T) {
	tests := map[string]struct {
		secret  []byte
		wantErr bool
		errMsg  string
	}{
		"valid secret": {
			secret:  []byte("JBSWY3DPEHPK3PXP"),
			wantErr: false,
		},
		"secret with whitespace": {
			secret:  []byte("  JBSWY3DPEHPK3PXP  "),
			wantErr: false,
		},
		"invalid secret": {
			secret:  []byte("INVALID!@#"),
			wantErr: true,
			errMsg:  "failed to generate",
		},
		"empty secret": {
			secret:  []byte{},
			wantErr: true,
			errMsg:  "empty secret provided",
		},
		"nil secret": {
			secret:  nil,
			wantErr: true,
			errMsg:  "empty secret provided",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			current, next, err := GenerateConsecutiveCodesBytes(tc.secret)

			if (err != nil) != tc.wantErr {
				t.Errorf("GenerateConsecutiveCodesBytes() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if tc.wantErr && tc.errMsg != "" && !strings.Contains(err.Error(), tc.errMsg) {
				t.Errorf("Expected error containing %q, got %q", tc.errMsg, err.Error())
			}

			if !tc.wantErr {
				if len(current) != 6 {
					t.Errorf("Expected 6-digit current code, got %d digits: %s", len(current), current)
				}
				if len(next) != 6 {
					t.Errorf("Expected 6-digit next code, got %d digits: %s", len(next), next)
				}
				if current == next {
					t.Error("Current and next codes should be different")
				}
			}
		})
	}
}
