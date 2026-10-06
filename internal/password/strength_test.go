package password

import (
	"testing"
	"time"
)

func TestIsWeak(t *testing.T) {
	for _, tt := range []struct {
		pw    string
		hints []string
		want  bool
	}{
		{"password1", nil, true},
		{"Summer2024!", nil, true},
		{"Tr0ub4dor&3", nil, false},
		{"correct horse battery staple", nil, false},
		// Strong alone, weak once it's built from the entry's own names.
		{"mycorpportal2026", nil, false},
		{"mycorpportal2026", []string{"mycorpportal"}, true},
		{"alicejohnson88", []string{"github", "alicejohnson"}, true},
		// A name of several words counts word by word and run together.
		{"mybank2024", nil, false},
		{"mybank2024", []string{"My Bank"}, true},
	} {
		if got := IsWeak([]byte(tt.pw), tt.hints...); got != tt.want {
			t.Errorf("IsWeak(%q, %q) = %v, want %v", tt.pw, tt.hints, got, tt.want)
		}
	}
}

// The warning for a weak password suggests generating one, so a generated
// password at the default settings must not count as weak.
func TestGeneratedPasswordsArentWeak(t *testing.T) {
	for _, symbols := range []bool{true, false} {
		opts := DefaultGenerateOptions()
		opts.Symbols = symbols
		for range 200 {
			pw, err := GeneratePassword(opts)
			if err != nil {
				t.Fatal(err)
			}
			if IsWeak(pw) {
				t.Fatalf("generated %q (symbols %v) counts as weak", pw, symbols)
			}
		}
	}
}

// zxcvbn slows down sharply with length; a long password, generated or
// pasted, must still be rated at once.
func TestIsWeak_LongPasswordsAreQuick(t *testing.T) {
	opts := DefaultGenerateOptions()
	opts.Length = 2048
	pw, err := GeneratePassword(opts)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan bool, 1)
	go func() { done <- IsWeak(pw) }()
	select {
	case weak := <-done:
		if weak {
			t.Error("a 2048-character random password counts as weak")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("rating a 2048-character password took over 2s")
	}
}
