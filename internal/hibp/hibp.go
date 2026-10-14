// Package hibp looks passwords up in a downloaded copy of Have I Been
// Pwned's Pwned Passwords, so nothing about them leaves the machine.
//
// The download is made with Have I Been Pwned's PwnedPasswordsDownloader,
// as one file (--single) or a folder of one file per range. Either is
// SHA-1 hashes in upper-case hex, each followed by ":" and how many times
// it was seen in breaches. The one file's lines are the whole 40-character
// hash, sorted; a range file's are the 35 characters after its name.
package hibp

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // Pwned Passwords is keyed by SHA-1; it's a lookup, not a protection
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

// hashLen is a SHA-1 hash's length in hex; ntlmLen an NTLM hash's, which
// the downloader's --ntlm gives instead.
const (
	hashLen   = 40
	ntlmLen   = 32
	prefixLen = 5
)

// maxLine is the longest line read: a hash, ":", a count, a line end, and
// a byte order mark before it.
const maxLine = 3 + hashLen + 1 + 20 + 2

// bom is the UTF-8 byte order mark the downloader may write at the start
// of a range.
var bom = []byte{0xEF, 0xBB, 0xBF}

// ErrNTLM is the download made with --ntlm, of NTLM hashes, which sesh
// doesn't look passwords up in.
var ErrNTLM = errors.New("that's the NTLM download (made with --ntlm); sesh needs the SHA-1 one, made without it")

// Passwords is a Pwned Passwords download, open for looking up.
type Passwords struct {
	f    *os.File // the one file, nil for a folder
	dir  string   // the folder of range files, "" for one file
	size int64
}

// Open opens the download at path: the one file, or the folder of range
// files. It checks the first line, so a file of something else, or the
// NTLM download, is refused here rather than giving wrong answers.
func Open(path string) (*Passwords, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("the Pwned Passwords download: %w", err)
	}
	if info.IsDir() {
		p := &Passwords{dir: path}
		first, err := os.ReadFile(filepath.Join(path, "00000.txt")) //nolint:gosec // a file the user named
		if err != nil {
			return nil, fmt.Errorf("%s isn't a Pwned Passwords download folder: %w", path, err)
		}
		if err := checkFirst(first, hashLen-prefixLen, ntlmLen-prefixLen); err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(path, "00000.txt"), err)
		}
		return p, nil
	}
	f, err := os.Open(path) //nolint:gosec // a file the user named
	if err != nil {
		return nil, fmt.Errorf("the Pwned Passwords download: %w", err)
	}
	head := make([]byte, maxLine)
	n, err := f.ReadAt(head, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		f.Close() //nolint:errcheck,gosec // already failing
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if err := checkFirst(head[:n], hashLen, ntlmLen); err != nil {
		f.Close() //nolint:errcheck,gosec // already failing
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &Passwords{f: f, size: info.Size()}, nil
}

// checkFirst checks data's first line is a hash of want characters and a
// count; one of ntlm characters is the NTLM download.
func checkFirst(data []byte, want, ntlm int) error {
	line, _, _ := bytes.Cut(data, []byte("\n"))
	hash, _, err := parseLine(line)
	switch {
	case err == nil && len(hash) == want:
		return nil
	case err == nil && len(hash) == ntlm:
		return ErrNTLM
	}
	return errors.New("not a Pwned Passwords download: its first line isn't a hash and a count")
}

// Close closes the download.
func (p *Passwords) Close() error {
	if p.f == nil {
		return nil
	}
	return p.f.Close()
}

// Count is how many times password was seen in breaches: 0 for never.
func (p *Passwords) Count(password []byte) (int, error) {
	sum := sha1.Sum(password) //nolint:gosec // see the import
	return p.countHash([]byte(hexUpper(sum[:])))
}

// countHash is how many times the password whose SHA-1 is hash (upper-case
// hex) was seen.
func (p *Passwords) countHash(hash []byte) (int, error) {
	if p.f == nil {
		return p.countInRange(hash)
	}
	return p.countInFile(hash)
}

func hexUpper(b []byte) string {
	return string(bytes.ToUpper([]byte(hex.EncodeToString(b))))
}

// countInRange looks hash up in its range's file.
func (p *Passwords) countInRange(hash []byte) (int, error) {
	name := filepath.Join(p.dir, string(hash[:prefixLen])+".txt")
	data, err := os.ReadFile(name) //nolint:gosec // in the folder the user named
	if err != nil {
		return 0, fmt.Errorf("the Pwned Passwords download is missing a range: %w", err)
	}
	want := hash[prefixLen:]
	for line := range bytes.SplitSeq(data, []byte("\n")) {
		h, n, err := parseLine(line)
		if err != nil {
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			return 0, fmt.Errorf("%s: %w", name, err)
		}
		if bytes.EqualFold(h, want) {
			return n, nil
		}
	}
	return 0, nil
}

// countInFile looks hash up in the one file, sorted by hash, by halving
// the part of it the hash's line can be in, then reading that part.
func (p *Passwords) countInFile(hash []byte) (int, error) {
	lo, hi := int64(0), p.size // the line, if there, starts in [lo, hi); lo starts a line
	for hi-lo > 4096 {
		mid := lo + (hi-lo)/2
		start, err := p.lineStart(mid)
		if err != nil {
			return 0, err
		}
		if start >= hi {
			hi = mid
			continue
		}
		line, next, err := p.lineAt(start)
		if err != nil {
			return 0, err
		}
		h, n, err := parseLine(line)
		if err != nil {
			return 0, fmt.Errorf("the Pwned Passwords download, at byte %d: %w", start, err)
		}
		switch c := bytes.Compare(bytes.ToUpper(h), hash); {
		case c == 0:
			return n, nil
		case c < 0:
			lo = next
		default:
			hi = start
		}
	}
	for at := lo; at < hi; {
		line, next, err := p.lineAt(at)
		if err != nil {
			return 0, err
		}
		h, n, err := parseLine(line)
		if err != nil {
			if len(bytes.TrimSpace(line)) > 0 {
				return 0, fmt.Errorf("the Pwned Passwords download, at byte %d: %w", at, err)
			}
		} else if bytes.EqualFold(h, hash) {
			return n, nil
		}
		at = next
	}
	return 0, nil
}

// lineStart is where the first line starting at or after at starts: at
// itself, after a line end; or p.size when none does.
func (p *Passwords) lineStart(at int64) (int64, error) {
	if at == 0 {
		return 0, nil
	}
	buf := make([]byte, maxLine)
	n, err := p.f.ReadAt(buf, at-1)
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, fmt.Errorf("read the Pwned Passwords download: %w", err)
	}
	i := bytes.IndexByte(buf[:n], '\n')
	if i < 0 {
		if at-1+int64(n) >= p.size {
			return p.size, nil
		}
		return 0, fmt.Errorf("the Pwned Passwords download, at byte %d: a line longer than a hash and a count", at)
	}
	return at + int64(i), nil
}

// lineAt is the line starting at start, without its end, and where the
// next starts.
func (p *Passwords) lineAt(start int64) (line []byte, next int64, err error) {
	buf := make([]byte, maxLine)
	n, err := p.f.ReadAt(buf, start)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, 0, fmt.Errorf("read the Pwned Passwords download: %w", err)
	}
	buf = buf[:n]
	if i := bytes.IndexByte(buf, '\n'); i >= 0 {
		return buf[:i], start + int64(i) + 1, nil
	}
	if start+int64(n) >= p.size {
		return buf, p.size, nil // the last line, with no end
	}
	return nil, 0, fmt.Errorf("the Pwned Passwords download, at byte %d: a line longer than a hash and a count", start)
}

// parseLine reads a line's hash and count: hex, ":", a whole number, with
// a byte order mark before it or a carriage return after it ignored.
func parseLine(line []byte) (hash []byte, count int, err error) {
	line = bytes.TrimPrefix(line, bom)
	line = bytes.TrimSuffix(line, []byte("\r"))
	h, c, ok := bytes.Cut(line, []byte(":"))
	if !ok || len(h) == 0 {
		return nil, 0, errors.New("not a hash and a count")
	}
	for _, b := range h {
		if !isHex(b) {
			return nil, 0, errors.New("not a hash and a count")
		}
	}
	n, err := strconv.Atoi(string(c))
	if err != nil || n < 0 {
		return nil, 0, errors.New("not a hash and a count")
	}
	return h, n, nil
}

func isHex(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'A' && b <= 'F' || b >= 'a' && b <= 'f'
}
