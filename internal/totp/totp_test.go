package totp

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
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
			secret:     "JBSWY3DPEHPK3PXP",
			wantErrMsg: "",
		},
		"Invalid Base32 secret": {
			secret:     "NOT-VALID-BASE32!@#",
			wantErrMsg: "failed to generate current TOTP",
		},
		"Empty secret": {
			secret:     "",
			wantErrMsg: "",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if tc.wantErrMsg != "" && testing.Short() {
				t.Skip("Skipping error case in short mode")
			}

			current, next, err := GenerateConsecutiveCodes(tc.secret)

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

			if err != nil {
				t.Errorf("GenerateConsecutiveCodes() unexpected error = %v", err)
				return
			}

			if len(current) != 6 || len(next) != 6 {
				t.Errorf("GenerateConsecutiveCodes() code lengths = %d and %d, want both 6", len(current), len(next))
			}
		})
	}
}

func TestGenerateConsecutiveCodesForTime(t *testing.T) {
	tests := map[string]struct {
		baseTime time.Time
		secret   string
		wantErr  bool
	}{
		"2026-01-01 midnight UTC": {
			secret:   "JBSWY3DPEHPK3PXP",
			baseTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		"2026-06-15 noon UTC": {
			secret:   "JBSWY3DPEHPK3PXP",
			baseTime: time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC),
		},
		"invalid secret": {
			secret:   "NOT-VALID-BASE32!@#",
			baseTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			wantErr:  true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			current, next, err := GenerateConsecutiveCodesForTime(tc.secret, tc.baseTime)

			if tc.wantErr {
				if err == nil {
					t.Error("GenerateConsecutiveCodesForTime() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("GenerateConsecutiveCodesForTime() unexpected error = %v", err)
				return
			}

			wantCurrent, err := GenerateForTime(tc.secret, tc.baseTime)
			if err != nil {
				t.Fatalf("GenerateForTime (current) failed: %v", err)
			}
			wantNext, err := GenerateForTime(tc.secret, tc.baseTime.Add(30*time.Second))
			if err != nil {
				t.Fatalf("GenerateForTime (next) failed: %v", err)
			}

			if current != wantCurrent {
				t.Errorf("GenerateConsecutiveCodesForTime() current = %q, want %q", current, wantCurrent)
			}
			if next != wantNext {
				t.Errorf("GenerateConsecutiveCodesForTime() next = %q, want %q", next, wantNext)
			}
		})
	}
}

func TestValidateAndNormalizeSecret(t *testing.T) {
	tests := map[string]struct {
		input       string
		expected    string
		errorMsg    string
		shouldError bool
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
		time    time.Time
		secret  string
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
		time    time.Time
		secret  string
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
		time    time.Time
		secret  []byte
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
		errMsg  string
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
			}
		})
	}
}

func TestGenerateConsecutiveCodesForTimeBytes(t *testing.T) {
	tests := map[string]struct {
		baseTime time.Time
		errMsg   string
		secret   []byte
		wantErr  bool
	}{
		"valid secret": {
			secret:   []byte("JBSWY3DPEHPK3PXP"),
			baseTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		"secret with whitespace": {
			secret:   []byte("  JBSWY3DPEHPK3PXP  "),
			baseTime: time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC),
		},
		"empty secret": {
			secret:   []byte{},
			baseTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			wantErr:  true,
			errMsg:   "empty secret provided",
		},
		"nil secret": {
			secret:   nil,
			baseTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			wantErr:  true,
			errMsg:   "empty secret provided",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			current, next, err := GenerateConsecutiveCodesForTimeBytes(tc.secret, tc.baseTime)

			if (err != nil) != tc.wantErr {
				t.Errorf("GenerateConsecutiveCodesForTimeBytes() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if tc.wantErr && tc.errMsg != "" && !strings.Contains(err.Error(), tc.errMsg) {
				t.Errorf("Expected error containing %q, got %q", tc.errMsg, err.Error())
			}

			if !tc.wantErr {
				wantCurrent, err := GenerateForTimeBytes(tc.secret, tc.baseTime)
				if err != nil {
					t.Fatalf("GenerateForTimeBytes (current) failed: %v", err)
				}
				wantNext, err := GenerateForTimeBytes(tc.secret, tc.baseTime.Add(30*time.Second))
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
		})
	}
}

func TestAlgorithmFromName(t *testing.T) {
	tests := map[string]otp.Algorithm{
		"SHA1":       otp.AlgorithmSHA1,
		"sha1":       otp.AlgorithmSHA1, // case-insensitive
		"SHA256":     otp.AlgorithmSHA256,
		"sha256":     otp.AlgorithmSHA256,
		"SHA512":     otp.AlgorithmSHA512,
		"":           otp.AlgorithmSHA1, // default
		"bogus-algo": otp.AlgorithmSHA1, // unknown → default
	}
	for name, want := range tests {
		t.Run(name, func(t *testing.T) {
			if got := algorithmFromName(name); got != want {
				t.Errorf("algorithmFromName(%q) = %v, want %v", name, got, want)
			}
		})
	}
}

func TestParams_IsDefault(t *testing.T) {
	tests := map[string]struct {
		p    Params
		want bool
	}{
		"zero":                {p: Params{}, want: true},
		"issuer-only":         {p: Params{Issuer: "Example"}, want: true}, // IsDefault ignores issuer
		"digits set":          {p: Params{Digits: 6}, want: false},
		"period set":          {p: Params{Period: 30}, want: false},
		"algorithm set":       {p: Params{Algorithm: "SHA256"}, want: false},
		"all non-default set": {p: Params{Algorithm: "SHA1", Digits: 6, Period: 30}, want: false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := tc.p.IsDefault(); got != tc.want {
				t.Errorf("IsDefault() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParams_MarshalDescription(t *testing.T) {
	tests := map[string]struct {
		wantSub string // expect substring in JSON output (or empty)
		p       Params
	}{
		"all-default produces empty": {
			p:       Params{},
			wantSub: "",
		},
		"issuer alone is serialized": {
			// IsDefault returns true for issuer-only, but MarshalDescription
			// still emits JSON when issuer is set, so the issuer is preserved.
			p:       Params{Issuer: "Example"},
			wantSub: `"issuer":"Example"`,
		},
		"non-default params are serialized": {
			p:       Params{Algorithm: "SHA256", Digits: 8, Period: 60},
			wantSub: `"algorithm":"SHA256"`,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := tc.p.MarshalDescription()
			if tc.wantSub == "" {
				if got != "" {
					t.Errorf("MarshalDescription() = %q, want empty", got)
				}
				return
			}
			if !strings.Contains(got, tc.wantSub) {
				t.Errorf("MarshalDescription() = %q, want contains %q", got, tc.wantSub)
			}
		})
	}
}

func TestParseParams(t *testing.T) {
	tests := map[string]struct {
		desc string
		want Params
	}{
		"empty string": {
			desc: "",
			want: Params{},
		},
		"invalid JSON": {
			desc: "not{json",
			want: Params{},
		},
		"valid params": {
			desc: `{"issuer":"Example","algorithm":"SHA256","digits":8,"period":60}`,
			want: Params{Issuer: "Example", Algorithm: "SHA256", Digits: 8, Period: 60},
		},
		"partial params": {
			desc: `{"digits":8}`,
			want: Params{Digits: 8},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := ParseParams(tc.desc)
			if got != tc.want {
				t.Errorf("ParseParams(%q) = %+v, want %+v", tc.desc, got, tc.want)
			}
		})
	}
}

func TestGenerateConsecutiveCodesBytesWithParams(t *testing.T) {
	secret := []byte("JBSWY3DPEHPK3PXP")

	t.Run("default params falls through to standard path", func(t *testing.T) {
		cur, next, err := GenerateConsecutiveCodesBytesWithParams(secret, Params{})
		if err != nil {
			t.Fatal(err)
		}
		if len(cur) != 6 || len(next) != 6 {
			t.Errorf("default params should produce 6-digit codes, got cur=%q next=%q", cur, next)
		}
	})

	t.Run("8-digit params produces 8-digit codes", func(t *testing.T) {
		cur, next, err := GenerateConsecutiveCodesBytesWithParams(secret, Params{Digits: 8, Period: 30})
		if err != nil {
			t.Fatal(err)
		}
		if len(cur) != 8 || len(next) != 8 {
			t.Errorf("expected 8-digit codes, got cur=%q next=%q", cur, next)
		}
	})

	t.Run("empty secret with non-default params returns error", func(t *testing.T) {
		_, _, err := GenerateConsecutiveCodesBytesWithParams(nil, Params{Digits: 8})
		if err == nil {
			t.Fatal("expected error for empty secret")
		}
	})

	t.Run("whitespace-only secret returns error", func(t *testing.T) {
		_, _, err := GenerateConsecutiveCodesBytesWithParams([]byte("   \t\n"), Params{Digits: 8})
		if err == nil {
			t.Fatal("expected error for whitespace-only secret")
		}
	})

	t.Run("period above cap is rejected", func(t *testing.T) {
		// Without the bound, Period * time.Second overflows int64 and
		// now.Add(period) lands in the past — producing a "next" code
		// that doesn't correspond to any future window.
		_, _, err := GenerateConsecutiveCodesBytesWithParams(secret, Params{Digits: 8, Period: MaxTOTPPeriodSeconds + 1})
		if err == nil {
			t.Fatal("expected error for period above cap")
		}
	})

	t.Run("period at cap is accepted", func(t *testing.T) {
		_, _, err := GenerateConsecutiveCodesBytesWithParams(secret, Params{Digits: 8, Period: MaxTOTPPeriodSeconds})
		if err != nil {
			t.Fatalf("period at cap should be accepted: %v", err)
		}
	})
}

func TestValidateOptsFromParams(t *testing.T) {
	tests := map[string]struct {
		params     Params
		wantDigits otp.Digits
		wantPeriod uint
		wantAlgo   otp.Algorithm
	}{
		"zero params defaults to SHA1/6/30": {
			params:     Params{},
			wantDigits: otp.DigitsSix,
			wantPeriod: 30,
			wantAlgo:   otp.AlgorithmSHA1,
		},
		"digits=6 passes through": {
			params:     Params{Digits: 6},
			wantDigits: otp.DigitsSix,
			wantPeriod: 30,
			wantAlgo:   otp.AlgorithmSHA1,
		},
		"digits=7 passes through (RFC 4226 allowed)": {
			params:     Params{Digits: 7},
			wantDigits: otp.Digits(7),
			wantPeriod: 30,
			wantAlgo:   otp.AlgorithmSHA1,
		},
		"digits=8 passes through": {
			params:     Params{Digits: 8},
			wantDigits: otp.DigitsEight,
			wantPeriod: 30,
			wantAlgo:   otp.AlgorithmSHA1,
		},
		"digits=5 (invalid) falls back to 6": {
			// Guards the behavior we locked in after the review: invalid
			// or out-of-range values should NOT silently upgrade.
			params:     Params{Digits: 5},
			wantDigits: otp.DigitsSix,
			wantPeriod: 30,
			wantAlgo:   otp.AlgorithmSHA1,
		},
		"digits=9 (invalid) falls back to 6": {
			params:     Params{Digits: 9},
			wantDigits: otp.DigitsSix,
			wantPeriod: 30,
			wantAlgo:   otp.AlgorithmSHA1,
		},
		"custom period": {
			params:     Params{Period: 60},
			wantDigits: otp.DigitsSix,
			wantPeriod: 60,
			wantAlgo:   otp.AlgorithmSHA1,
		},
		"zero period falls back to 30": {
			params:     Params{Period: 0},
			wantDigits: otp.DigitsSix,
			wantPeriod: 30,
			wantAlgo:   otp.AlgorithmSHA1,
		},
		"SHA256 algorithm": {
			params:     Params{Algorithm: "SHA256"},
			wantDigits: otp.DigitsSix,
			wantPeriod: 30,
			wantAlgo:   otp.AlgorithmSHA256,
		},
		"full params": {
			params:     Params{Algorithm: "SHA512", Digits: 8, Period: 60},
			wantDigits: otp.DigitsEight,
			wantPeriod: 60,
			wantAlgo:   otp.AlgorithmSHA512,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			opts := validateOptsFromParams(tc.params)
			if opts.Digits != tc.wantDigits {
				t.Errorf("Digits = %v, want %v", opts.Digits, tc.wantDigits)
			}
			if opts.Period != tc.wantPeriod {
				t.Errorf("Period = %v, want %v", opts.Period, tc.wantPeriod)
			}
			if opts.Algorithm != tc.wantAlgo {
				t.Errorf("Algorithm = %v, want %v", opts.Algorithm, tc.wantAlgo)
			}
		})
	}
}
