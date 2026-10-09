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
	longest int
	// known is how much of held is part of a secret already concealed,
	// which the next match must cover too.
	known int
	mu    sync.Mutex
}

// NewWriter returns a Writer to w masking secrets (those at least
// MinLength long). It keeps its own copies, which Close zeroes.
func NewWriter(w io.Writer, secrets [][]byte) *Writer {
	m := &Writer{w: w}
	for _, s := range secrets {
		// Spaces and line breaks around a value are matched as output, not
		// as the secret, so a prompt or line ending in one isn't held back.
		if s = bytes.TrimSpace(s); len(s) >= MinLength {
			m.secrets = append(m.secrets, bytes.Clone(s))
			m.longest = max(m.longest, len(s))
		}
	}
	return m
}

// Write implements io.Writer: it reports all of p written once what can
// be is passed on.
func (m *Writer) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	buf := slices.Concat(m.held, p)
	secure.SecureZeroBytes(m.held)
	out, rest, known := m.mask(buf, false)
	m.held, m.known = bytes.Clone(rest), known
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
	out, _, _ := m.mask(m.held, true)
	secure.SecureZeroBytes(m.held)
	m.held = nil
	for _, s := range m.secrets {
		secure.SecureZeroBytes(s)
	}
	m.secrets = nil
	_, err := m.w.Write(out)
	return err
}

// mask replaces each secret in buf; secrets that overlap, or one inside
// another, become one Concealed. Unless final, it returns separately the
// end of buf that could start a secret, and a match reaching into that
// end, which more output could lengthen: from its start, or, when that's
// further back than the longest secret, from there, the match before it
// already concealed. So no more than a secret's length is held back, and
// a long run of a secret can show as several Concealed.
func (m *Writer) mask(buf []byte, final bool) (out, rest []byte, known int) {
	limit := len(buf)
	if !final {
		limit -= m.possibleStart(buf)
	}
	type span struct{ start, end int }
	var spans []span
	if m.known > 0 {
		spans = append(spans, span{0, min(m.known, len(buf))})
	}
	for _, s := range m.secrets {
		for i := 0; ; {
			j := bytes.Index(buf[i:], s)
			if j < 0 {
				break
			}
			spans = append(spans, span{i + j, i + j + len(s)})
			i += j + 1
		}
	}
	slices.SortFunc(spans, func(a, b span) int { return a.start - b.start })
	var merged []span
	for _, sp := range spans {
		if n := len(merged); n > 0 && sp.start < merged[n-1].end {
			merged[n-1].end = max(merged[n-1].end, sp.end)
			continue
		}
		merged = append(merged, sp)
	}
	pos := 0
	for _, sp := range merged {
		if sp.end > limit {
			from := max(sp.start, len(buf)-(m.longest-1))
			if from > sp.start {
				out = append(out, buf[pos:sp.start]...)
				out = append(out, Concealed...)
				pos = from
				known = sp.end - from
			}
			limit = min(limit, from)
			break
		}
		out = append(out, buf[pos:sp.start]...)
		out = append(out, Concealed...)
		pos = sp.end
	}
	if pos < limit {
		out = append(out, buf[pos:limit]...)
	}
	return out, buf[max(pos, limit):], known
}

// possibleStart is how long the end of buf is that could be the start of
// a secret.
func (m *Writer) possibleStart(buf []byte) int {
	k := 0
	for _, s := range m.secrets {
		for j := min(len(s)-1, len(buf)); j > k; j-- {
			if bytes.Equal(buf[len(buf)-j:], s[:j]) {
				k = j
				break
			}
		}
	}
	return k
}
