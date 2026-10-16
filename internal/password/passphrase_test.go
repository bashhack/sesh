package password

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"unicode"
)

// The embedded list is the EFF's, unchanged: 7776 different words.
func TestWordlist(t *testing.T) {
	sum := sha256.Sum256([]byte(effLargeWordlist))
	if got := hex.EncodeToString(sum[:]); got != "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e" {
		t.Errorf("sha256 = %s", got)
	}
	seen := map[string]bool{}
	for _, w := range wordlist {
		if w == "" || len(w) > longestWord || seen[w] || strings.IndexFunc(w, func(r rune) bool { return !unicode.IsLower(r) && r != '-' }) >= 0 {
			t.Errorf("word %q", w)
		}
		seen[w] = true
	}
	if len(wordlist) != 7776 || wordlist[0] != "abacus" || wordlist[len(wordlist)-1] != "zoom" {
		t.Errorf("%d words, %q to %q", len(wordlist), wordlist[0], wordlist[len(wordlist)-1])
	}
}

func TestGeneratePassphrase(t *testing.T) {
	inList := map[string]bool{}
	for _, w := range wordlist {
		inList[w] = true
	}
	// Separators no word has, so the words split back out.
	for _, o := range []PassphraseOptions{{Words: 6, Separator: " "}, {Words: 3, Separator: "."}, {Words: 20, Separator: "_", Capitalize: true}} {
		pw, err := GeneratePassphrase(o)
		if err != nil {
			t.Fatal(err)
		}
		got := strings.Split(string(pw), o.Separator)
		if len(got) != o.Words {
			t.Errorf("%+v: %q has %d words", o, pw, len(got))
		}
		for _, w := range got {
			if o.Capitalize {
				if w == "" || !unicode.IsUpper(rune(w[0])) {
					t.Errorf("%+v: %q isn't capitalized", o, w)
				}
				w = strings.ToLower(w[:1]) + w[1:]
			}
			if !inList[w] {
				t.Errorf("%+v: %q isn't a listed word", o, w)
			}
		}
	}
	a, err := GeneratePassphrase(DefaultPassphraseOptions())
	if err != nil {
		t.Fatal(err)
	}
	b, err := GeneratePassphrase(DefaultPassphraseOptions())
	if err != nil {
		t.Fatal(err)
	}
	if string(a) == string(b) || strings.Count(string(a), "-") < 5 {
		t.Errorf("by default: %q and %q", a, b)
	}
}

func TestGeneratePassphrase_Refused(t *testing.T) {
	for o, wantSub := range map[PassphraseOptions]string{
		{Words: 2, Separator: "-"}:         "3 to 20 words, not 2",
		{Words: 21, Separator: "-"}:        "not 21",
		{Words: 6, Separator: "123456789"}: "longer than 8",
		{Words: 6, Separator: "\t"}:        "control character",
	} {
		if _, err := GeneratePassphrase(o); err == nil || !strings.Contains(err.Error(), wantSub) {
			t.Errorf("%+v: %v, want %q", o, err, wantSub)
		}
	}
}
