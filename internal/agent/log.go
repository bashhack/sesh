package agent

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

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
		fmt.Fprintf(os.Stderr, "%s %s\n", time.Now().Format(time.RFC3339), fmt.Sprintf(format, args...)) //nolint:errcheck // best-effort log line
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "%s %s\n", l.now().Format(time.RFC3339), fmt.Sprintf(format, args...)) //nolint:errcheck // best-effort log line
}

// closeOrLog closes c and logs a failure as a warning.
func (l *agentLog) closeOrLog(c io.Closer, what string) {
	if err := c.Close(); err != nil {
		l.printf("warning: close %s: %v", what, err)
	}
}
