package password

import (
	"strings"
	"testing"
)

func TestGeneratePassword(t *testing.T) {
	tests := map[string]struct {
		opts    GenerateOptions
		wantLen int
		wantErr bool
	}{
		"defaults": {
			opts:    DefaultGenerateOptions(),
			wantLen: 24,
		},
		"short password": {
			opts:    GenerateOptions{Length: 8, Uppercase: true, Lowercase: true, Digits: true, Symbols: true},
			wantLen: 8,
		},
		"long password": {
			opts:    GenerateOptions{Length: 128, Uppercase: true, Lowercase: true, Digits: true, Symbols: true},
			wantLen: 128,
		},
		"no symbols": {
			opts:    GenerateOptions{Length: 16, Uppercase: true, Lowercase: true, Digits: true, Symbols: false},
			wantLen: 16,
		},
		"digits only": {
			opts:    GenerateOptions{Length: 6, Digits: true},
			wantLen: 6,
		},
		"minimum viable": {
			opts:    GenerateOptions{Length: 4, Uppercase: true, Lowercase: true, Digits: true, Symbols: true},
			wantLen: 4,
		},
		"zero length": {
			opts:    GenerateOptions{Length: 0, Lowercase: true},
			wantErr: true,
		},
		"too short for required sets": {
			opts:    GenerateOptions{Length: 2, Uppercase: true, Lowercase: true, Digits: true, Symbols: true},
			wantErr: true,
		},
		"no character sets": {
			opts:    GenerateOptions{Length: 16},
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			pw, err := GeneratePassword(tc.opts)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(pw) != tc.wantLen {
				t.Errorf("expected length %d, got %d", tc.wantLen, len(pw))
			}
		})
	}
}

func TestGeneratePasswordCharacterSets(t *testing.T) {
	tests := map[string]struct {
		mustHave string
		mustNot  string
		opts     GenerateOptions
	}{
		"no symbols excluded": {
			opts:    GenerateOptions{Length: 100, Uppercase: true, Lowercase: true, Digits: true, Symbols: false},
			mustNot: symbolChars,
		},
		"digits only": {
			opts:    GenerateOptions{Length: 100, Digits: true},
			mustNot: lowerChars + upperChars + symbolChars,
		},
		"lowercase only": {
			opts:    GenerateOptions{Length: 100, Lowercase: true},
			mustNot: upperChars + digitChars + symbolChars,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			pw, err := GeneratePassword(tc.opts)
			if err != nil {
				t.Fatal(err)
			}

			if tc.mustNot != "" {
				for _, c := range pw {
					if strings.ContainsRune(tc.mustNot, c) {
						t.Errorf("password contains excluded character %q", string(c))
						break
					}
				}
			}
		})
	}
}

func TestGeneratePasswordUniqueness(t *testing.T) {
	opts := DefaultGenerateOptions()
	seen := make(map[string]bool)

	for i := range 100 {
		pw, err := GeneratePassword(opts)
		if err != nil {
			t.Fatal(err)
		}
		if seen[pw] {
			t.Fatalf("duplicate password generated on iteration %d", i)
		}
		seen[pw] = true
	}
}

func TestGeneratePasswordGuaranteedCharSets(t *testing.T) {
	opts := GenerateOptions{Length: 4, Uppercase: true, Lowercase: true, Digits: true, Symbols: true}

	// With length=4 and 4 required sets, every set must appear.
	// Run multiple times to catch probabilistic failures.
	for i := range 50 {
		pw, err := GeneratePassword(opts)
		if err != nil {
			t.Fatal(err)
		}
		hasLower := strings.ContainsAny(pw, lowerChars)
		hasUpper := strings.ContainsAny(pw, upperChars)
		hasDigit := strings.ContainsAny(pw, digitChars)
		hasSymbol := strings.ContainsAny(pw, symbolChars)

		if !hasLower || !hasUpper || !hasDigit || !hasSymbol {
			t.Fatalf("iteration %d: password %q missing required character set (lower=%v upper=%v digit=%v symbol=%v)",
				i, pw, hasLower, hasUpper, hasDigit, hasSymbol)
		}
	}
}
