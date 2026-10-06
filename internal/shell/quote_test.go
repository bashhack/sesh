package shell

import "testing"

func TestQuote(t *testing.T) {
	for in, want := range map[string]string{
		"github":            "github",
		"alice@example.com": "alice@example.com",
		"My Bank":           "'My Bank'",
		"Bob's Bank":        `'Bob'\''s Bank'`,
		"$HOME":             "'$HOME'",
		"`id`":              "'`id`'",
		"":                  "''",
	} {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %s, want %s", in, got, want)
		}
	}
}
