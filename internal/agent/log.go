package agent

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// oneLine escapes line breaks, so a value with a newline in it (a socket
// path, an error) can't start a log line that has no timestamp.
var oneLine = strings.NewReplacer("\r", `\r`, "\n", `\n`)

// agentLog writes the daemon's log lines. Each line starts with an RFC 3339
// timestamp, because the log file is appended to across runs. Lines name
// events only: never a password, key, plaintext, or full unlock id.
type agentLog struct {
	w   io.Writer
	now func() time.Time
	mu  sync.Mutex
}

// printf writes one timestamped line. A nil log writes to stderr, so a
// keystore built without a Server still reports its events.
func (l *agentLog) printf(format string, args ...any) {
	if l == nil {
		fmt.Fprintf(os.Stderr, "%s %s\n", time.Now().Format(time.RFC3339), oneLine.Replace(fmt.Sprintf(format, args...))) //nolint:errcheck // best-effort log line
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "%s %s\n", l.now().Format(time.RFC3339), oneLine.Replace(fmt.Sprintf(format, args...))) //nolint:errcheck // best-effort log line
}

// TimestampLines returns a writer that starts every line written to w with
// a timestamp, as agentLog does. The daemon wraps its stderr in one so that
// what it writes outside the Server (a flag error, a failed start) matches
// the rest of the agent log.
func TimestampLines(w io.Writer) io.Writer {
	return &stampWriter{w: w, now: time.Now}
}

type stampWriter struct {
	w   io.Writer
	now func() time.Time
	mu  sync.Mutex
	// midLine is set when the last write ended without a newline.
	midLine bool
}

func (s *stampWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var buf []byte
	for rest := p; len(rest) > 0; {
		if !s.midLine {
			buf = append(buf, s.now().Format(time.RFC3339)+" "...)
		}
		line := rest
		if i := strings.IndexByte(string(rest), '\n'); i >= 0 {
			line = rest[:i+1]
		}
		buf = append(buf, line...)
		s.midLine = line[len(line)-1] != '\n'
		rest = rest[len(line):]
	}
	if _, err := s.w.Write(buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

// closeOrLog closes c and logs a failure as a warning.
func (l *agentLog) closeOrLog(c io.Closer, what string) {
	if err := c.Close(); err != nil {
		l.printf("warning: close %s: %v", what, err)
	}
}
