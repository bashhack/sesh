package recovery

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"
)

// fixedKey is a key with known bytes, so the tests are repeatable.
func fixedKey() Key {
	var k Key
	for i := range k.secret {
		k.secret[i] = byte(i*37 + 11)
	}
	return k
}

func TestKey_StringAndParse(t *testing.T) {
	k, err := New()
	if err != nil {
		t.Fatal(err)
	}
	s := k.String()
	if !regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){6}$`).MatchString(s) {
		t.Fatalf("String() = %q, want 7 groups of 4 Crockford base32 characters", s)
	}
	for _, typed := range []string{
		s,
		strings.ToLower(s),
		strings.ReplaceAll(s, "-", ""),
		strings.ReplaceAll(s, "-", " ") + "\n",
	} {
		got, err := Parse(typed)
		if err != nil || got != k {
			t.Errorf("Parse(%q) = %v, %v; want the same key", typed, got, err)
		}
	}
}

func TestKey_RoundTripsManyKeys(t *testing.T) {
	for range 1000 {
		k, err := New()
		if err != nil {
			t.Fatal(err)
		}
		if got, err := Parse(k.String()); err != nil || got != k {
			t.Fatalf("Parse(%q) = %v, %v", k.String(), got, err)
		}
	}
}

func TestParse_HandwritingLookalikes(t *testing.T) {
	k := fixedKey()
	s := k.String()
	// Crockford base32 reads I and L as 1, and O as 0.
	mangled := strings.NewReplacer("1", "l", "0", "O").Replace(s)
	if got, err := Parse(mangled); err != nil || got != k {
		t.Errorf("Parse(%q) = %v, %v; want %q", mangled, got, err, s)
	}
}

func TestParse_Refuses(t *testing.T) {
	s := fixedKey().String()
	typo := []byte(s)
	if typo[5] == 'A' {
		typo[5] = 'B'
	} else {
		typo[5] = 'A'
	}
	for name, tt := range map[string]struct{ in, wantSub string }{
		"too short":       {s[:20], "a recovery key has 28 characters (7 groups of 4); got 16"},
		"too long":        {s + "-ABCD", "a recovery key has 28 characters (7 groups of 4); got 32"},
		"not in alphabet": {"U" + s[1:], `"U" can't appear in a recovery key`},
		"a typo":          {string(typo), "that's not a valid recovery key: a character is wrong"},
		"first character": {"Z" + s[1:], "that's not a valid recovery key: a character is wrong"},
		"empty":           {"", "a recovery key has 28 characters (7 groups of 4); got 0"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(tt.in)
			if err == nil || !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("Parse(%q) err = %v, want %q", tt.in, err, tt.wantSub)
			}
			if !errors.Is(err, ErrInvalidKey) {
				t.Errorf("err = %v, want it to wrap ErrInvalidKey", err)
			}
		})
	}
}

func TestKey_PublicKeyIsDeterministic(t *testing.T) {
	a, err := fixedKey().PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := fixedKey().PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) || len(a) != 65 || a[0] != 4 {
		t.Errorf("public keys %x and %x; want the same uncompressed P-256 key", a, b)
	}
	other, err := New()
	if err != nil {
		t.Fatal(err)
	}
	c, err := other.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, c) {
		t.Error("two keys share a public key")
	}
}

func TestWrapUnwrap(t *testing.T) {
	k := fixedKey()
	pub, err := k.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{0x42}, 32)
	w, err := Wrap(pub, secret, []byte("vault id"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := k.Unwrap(w, []byte("vault id"))
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("Unwrap = %x, %v", got, err)
	}
	other, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Unwrap(w, []byte("vault id")); !errors.Is(err, ErrWrongKey) {
		t.Errorf("another key: err = %v, want ErrWrongKey", err)
	}
	if _, err := k.Unwrap(w, []byte("another vault")); !errors.Is(err, ErrWrongKey) {
		t.Errorf("another vault: err = %v, want ErrWrongKey", err)
	}
}
