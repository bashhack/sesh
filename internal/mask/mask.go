// Package mask hides secret values in a stream of output, as sesh run does
// with a command's stdout and stderr.
package mask

import (
	"bytes"
	"io"
	"slices"
	"sync"

	"github.com/bashhack/sesh/internal/secure"
)

// Concealed is what a secret is replaced with.
const Concealed = "<concealed by sesh>"

// MinLength is the shortest value masked: a shorter one would be replaced
// wherever its letters happen to appear.
const MinLength = 3

// Writer writes to w with every secret replaced by Concealed. A secret
// split across writes is still found: the end of a write that could be
// the start of a secret is held back until the next write, or Close, says
// whether it is. Nothing else is held back, so a prompt shows at once.
type Writer struct {
	w       io.Writer
	secrets [][]byte
	held    []byte
	mu      sync.Mutex
}

// NewWriter returns a Writer to w masking secrets (those at least
// MinLength long). It keeps its own copies, which Close zeroes.
func NewWriter(w io.Writer, secrets [][]byte) *Writer {
	m := &Writer{w: w}
	for _, s := range secrets {
		if len(s) >= MinLength {
			m.secrets = append(m.secrets, bytes.Clone(s))
		}
	}
	// Longest first, so a secret containing another is replaced whole.
	slices.SortFunc(m.secrets, func(a, b []byte) int { return len(b) - len(a) })
	return m
}

// Write implements io.Writer: it reports all of p written once what can
// be is passed on.
func (m *Writer) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	buf := slices.Concat(m.held, p)
	secure.SecureZeroBytes(m.held)
	out, rest := m.mask(buf, false)
	m.held = bytes.Clone(rest)
	secure.SecureZeroBytes(buf)
	if _, err := m.w.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close writes what's held back, masked, and zeroes the Writer's copies of
// the secrets.
func (m *Writer) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	out, _ := m.mask(m.held, true)
	secure.SecureZeroBytes(m.held)
	m.held = nil
	for _, s := range m.secrets {
		secure.SecureZeroBytes(s)
	}
	m.secrets = nil
	_, err := m.w.Write(out)
	return err
}

// mask replaces each secret in buf, earliest first. Unless final, it
// returns separately the end of buf that could start a secret.
func (m *Writer) mask(buf []byte, final bool) (out, rest []byte) {
	for {
		at, n := -1, 0
		for _, s := range m.secrets {
			if i := bytes.Index(buf, s); i >= 0 && (at < 0 || i < at) {
				at, n = i, len(s)
			}
		}
		if at < 0 {
			break
		}
		out = append(out, buf[:at]...)
		out = append(out, Concealed...)
		buf = buf[at+n:]
	}
	if final {
		return append(out, buf...), nil
	}
	k := 0
	for _, s := range m.secrets {
		for j := min(len(s)-1, len(buf)); j > k; j-- {
			if bytes.Equal(buf[len(buf)-j:], s[:j]) {
				k = j
				break
			}
		}
	}
	return append(out, buf[:len(buf)-k]...), buf[len(buf)-k:]
}
