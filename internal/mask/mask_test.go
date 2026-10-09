package mask

import (
	"bytes"
	"strings"
	"testing"
)

// write sends chunks through a Writer masking secrets and returns what
// came out.
func write(t *testing.T, secrets []string, chunks ...string) string {
	t.Helper()
	var out bytes.Buffer
	var bs [][]byte
	for _, s := range secrets {
		bs = append(bs, []byte(s))
	}
	w := NewWriter(&out, bs)
	for _, c := range chunks {
		if n, err := w.Write([]byte(c)); err != nil || n != len(c) {
			t.Fatalf("Write(%q) = %d, %v", c, n, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestWriter(t *testing.T) {
	const c = Concealed
	for name, tc := range map[string]struct {
		want    string
		secrets []string
		chunks  []string
	}{
		"in one write":            {"pw=" + c + "\n", []string{"hunter2"}, []string{"pw=hunter2\n"}},
		"split across writes":     {"pw=" + c + " ok\n", []string{"hunter2"}, []string{"pw=hun", "ter", "2 ok\n"}},
		"every byte its own":      {"x" + c + "y" + c, []string{"abc"}, strings.Split("xabcyabc", "")},
		"twice":                   {c + " " + c, []string{"sk-1"}, []string{"sk-1 sk-1"}},
		"longest first":           {"a " + c + " b " + c, []string{"pass", "password"}, []string{"a password b pass"}},
		"a prefix at the end":     {"hunt", []string{"hunter2"}, []string{"hunt"}},
		"nothing like a secret":   {"plain output\n", []string{"hunter2"}, []string{"plain output\n"}},
		"no secrets":              {"anything", nil, []string{"anything"}},
		"overlapping start":       {"a" + c, []string{"aab"}, []string{"aaab"}},
		"short values are passed": {"ab " + c, []string{"ab", "xyz"}, []string{"ab xyz"}},
	} {
		if got := write(t, tc.secrets, tc.chunks...); got != tc.want {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
}

// Output that can't start a secret goes out at once, not held back until
// the end; only what could be a secret's start waits.
func TestWriter_HoldsBackOnlyAPossibleStart(t *testing.T) {
	var out bytes.Buffer
	w := NewWriter(&out, [][]byte{[]byte("hunter2")})
	if _, err := w.Write([]byte("Password: ")); err != nil {
		t.Fatal(err)
	}
	if out.String() != "Password: " {
		t.Errorf("after a prompt: %q, want it written at once", out.String())
	}
	if _, err := w.Write([]byte("ok hun")); err != nil {
		t.Fatal(err)
	}
	if out.String() != "Password: ok " {
		t.Errorf("held back: %q", out.String())
	}
}
