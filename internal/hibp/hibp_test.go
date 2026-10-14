package hibp

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // the download's keys
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// sha1Hex is password's SHA-1 in upper-case hex, as the download keys it.
func sha1Hex(password string) string {
	sum := sha1.Sum([]byte(password)) //nolint:gosec // the download's keys
	return hexUpper(sum[:])
}

// singleFile writes a one-file download of lines (hash:count), sorted, with
// eol after each but the last, a byte order mark before each range's first
// line when marks, and returns its path.
func singleFile(t *testing.T, lines []string, eol string, marks bool) string {
	t.Helper()
	slices.Sort(lines)
	var b bytes.Buffer
	prev := ""
	for i, l := range lines {
		if marks && l[:prefixLen] != prev {
			b.Write(bom)
		}
		prev = l[:prefixLen]
		b.WriteString(l)
		if i < len(lines)-1 {
			b.WriteString(eol)
		}
	}
	path := filepath.Join(t.TempDir(), "pwnedpasswords.txt")
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// randomLines are n made-up hashes with counts, none of them want.
func randomLines(n int, want ...string) []string {
	r := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // test data
	out := make([]string, 0, n)
	for len(out) < n {
		var h [20]byte
		for i := range h {
			h[i] = byte(r.IntN(256))
		}
		s := hexUpper(h[:])
		if !slices.Contains(want, s) {
			out = append(out, fmt.Sprintf("%s:%d", s, r.IntN(1000)+1))
		}
	}
	return out
}

// The one file is searched by halving, whatever its line ends and marks.
func TestSingleFile(t *testing.T) {
	pw, hunter := sha1Hex("password"), sha1Hex("hunter2")
	lines := append(randomLines(20000, pw, hunter), pw+":9659365", hunter+":42")
	for _, c := range []struct {
		name, eol string
		marks     bool
	}{{"LF", "\n", false}, {"CRLF", "\r\n", false}, {"LF with marks", "\n", true}, {"CRLF with marks", "\r\n", true}} {
		t.Run(c.name, func(t *testing.T) {
			p, err := Open(singleFile(t, slices.Clone(lines), c.eol, c.marks))
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close() //nolint:errcheck // test
			for word, want := range map[string]int{"password": 9659365, "hunter2": 42, "not in it at all": 0} {
				if n, err := p.Count([]byte(word)); err != nil || n != want {
					t.Errorf("Count(%q) = %d, %v; want %d", word, n, err, want)
				}
			}
			sorted := slices.Clone(lines)
			slices.Sort(sorted)
			for _, l := range []string{sorted[0], sorted[len(sorted)-1], sorted[len(sorted)/3]} {
				h, n, _ := strings.Cut(l, ":")
				if got, err := p.countHash([]byte(h)); err != nil || fmt.Sprint(got) != n {
					t.Errorf("the line %s: %d, %v", l, got, err)
				}
			}
		})
	}
}

// A folder of ranges, as the downloader makes by default, from a range as Have I Been Pwned sends it.
func TestFolder(t *testing.T) {
	real, err := os.ReadFile(filepath.Join("testdata", "00000.txt"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "00000.txt"), real, 0o600); err != nil {
		t.Fatal(err)
	}
	pw := sha1Hex("password")
	if err := os.WriteFile(filepath.Join(dir, pw[:prefixLen]+".txt"), []byte("0000000000000000000000000000000000A:3\r\n"+pw[prefixLen:]+":9659365"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close() //nolint:errcheck // test
	if n, err := p.Count([]byte("password")); err != nil || n != 9659365 {
		t.Errorf("Count(password) = %d, %v", n, err)
	}
	for hash, want := range map[string]int{
		"00000" + "0005AD76BD555C1D6D771DE417A4B87E4B4": 58, // the real range's first line
		"00000" + strings.Repeat("F", 35):               0,
	} {
		if n, err := p.countHash([]byte(hash)); err != nil || n != want {
			t.Errorf("countHash(%s) = %d, %v; want %d", hash, n, err, want)
		}
	}
	if n, err := p.countHash([]byte("00000" + "FFF5C4A486B528DD84D1F1D3F41A06E9256")); err != nil || n != 4 {
		t.Errorf("the real range's last line, with no line end: %d, %v", n, err)
	}
	if _, err := p.Count([]byte("hunter2")); err == nil || !strings.Contains(err.Error(), "missing a range") {
		t.Errorf("a range not downloaded: %v", err)
	}
}

// Something other than the SHA-1 download is refused when opened.
func TestOpenRefuses(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"ntlm.txt":    "00000011059407D743D40689940F858C:3\n",
		"words.txt":   "password\nhunter2\n",
		"empty.txt":   "",
		"counted.txt": sha1Hex("x") + ":lots\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Open(path)
		want := "not a Pwned Passwords download"
		if name == "ntlm.txt" {
			want = "NTLM download"
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v; want %q", name, err, want)
		}
	}
	if _, err := Open(t.TempDir()); err == nil || !strings.Contains(err.Error(), "isn't a Pwned Passwords download folder") {
		t.Errorf("an empty folder: %v", err)
	}
}
