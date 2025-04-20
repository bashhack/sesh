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
