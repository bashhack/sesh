package agent

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// logBuffer is a bytes.Buffer safe to read while the server writes to it.
type logBuffer struct {
	buf bytes.Buffer
	mu  sync.Mutex
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitForLog polls until the log contains want, failing after two seconds.
func waitForLog(t *testing.T, log *logBuffer, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(log.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("log never contained %q; log:\n%s", want, log.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

var timestampedLine = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2}) \S`)

func TestAgentLog_TimestampsEveryLine(t *testing.T) {
	var out bytes.Buffer
	l := &agentLog{w: &out, now: func() time.Time { return time.Date(2026, 10, 2, 13, 4, 5, 0, time.UTC) }}
	l.printf("locked after %s", "idle timeout")
	if got, want := out.String(), "2026-10-02T13:04:05Z locked after idle timeout\n"; got != want {
		t.Errorf("line = %q, want %q", got, want)
	}
}

func TestServer_LogsLifecycleEvents(t *testing.T) {
	sockPath := tempSocketPath(t)
	var log logBuffer
	_, done := serve(t, sockPath, withLogOutput(&log))

	params := lightParams()
	salt, verify := sealVerify(t, "correct-horse", params)
	conn := dialClient(t, sockPath)
	if err := Unlock(conn, []byte("wrong-horse"), salt, verify, params); err == nil {
		t.Fatal("unlock with the wrong password succeeded")
	}
	if err := Unlock(conn, []byte("correct-horse"), salt, verify, params); err != nil {
		t.Fatal(err)
	}
	if err := Lock(conn); err != nil {
		t.Fatal(err)
	}
	if err := Stop(conn); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}

	got := log.String()
	rest := got
	for _, want := range []string{
		"listening at " + sockPath,
		"unlock refused: wrong password",
		"unlocked",
		"locked (lock request)",
		"stopping (stop request)",
		"stopped",
	} {
		i := strings.Index(rest, want)
		if i < 0 {
			t.Fatalf("log missing %q after the earlier events; log:\n%s", want, got)
		}
		rest = rest[i+len(want):]
	}
	for line := range strings.SplitSeq(strings.TrimSpace(got), "\n") {
		if !timestampedLine.MatchString(line) {
			t.Errorf("line without a timestamp: %q", line)
		}
	}
	if strings.Contains(got, "horse") || strings.Contains(got, UnlockID(verify)) {
		t.Errorf("log leaks the password or the unlock id:\n%s", got)
	}
}

func TestServer_LogsAutoLock(t *testing.T) {
	sockPath := tempSocketPath(t)
	var log logBuffer
	clk := newFakeClock()
	serve(t, sockPath, withLogOutput(&log), withClock(clk), WithIdleTimeout(time.Minute))
	unlockClient(t, sockPath)

	clk.advance(time.Minute)
	waitForLog(t, &log, "locked after idle timeout")
}

func TestServer_LogsRefusedConnections(t *testing.T) {
	t.Run("other user", func(t *testing.T) {
		sockPath := tempSocketPath(t)
		var log logBuffer
		serve(t, sockPath, withLogOutput(&log))
		otherUser(t)
		if conn, err := dialAndHandshake(sockPath); err == nil {
			mustClose(t, conn.uc)
			t.Fatal("handshake succeeded across users")
		}
		waitForLog(t, &log, "refused connection: peer UID")
	})
	t.Run("protocol version", func(t *testing.T) {
		sockPath := tempSocketPath(t)
		var log logBuffer
		serve(t, sockPath, withLogOutput(&log))
		raw, err := net.DialTimeout("unix", sockPath, dialTimeout)
		if err != nil {
			t.Fatal(err)
		}
		defer mustClose(t, raw)
		if err := writeJSON(raw, HelloRequest{Type: TypeHello, Version: 99}); err != nil {
			t.Fatal(err)
		}
		waitForLog(t, &log, "refused client speaking protocol version 99")
	})
}

func TestRotateLog(t *testing.T) {
	for _, tc := range []struct {
		name        string
		size        int
		wantRotated bool
	}{
		{"at the limit", maxAgentLogSize, false},
		{"over the limit", maxAgentLogSize + 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agent.log")
			if err := os.WriteFile(path, bytes.Repeat([]byte("x"), tc.size), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path+".1", []byte("older"), 0o600); err != nil {
				t.Fatal(err)
			}
			rotateLog(path)
			_, err := os.Stat(path)
			if rotated := os.IsNotExist(err); rotated != tc.wantRotated {
				t.Fatalf("rotated = %v, want %v (stat err %v)", rotated, tc.wantRotated, err)
			}
			prev, err := os.ReadFile(path + ".1")
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantRotated && len(prev) != tc.size {
				t.Errorf("agent.log.1 has %d bytes, want the rotated %d", len(prev), tc.size)
			}
			if !tc.wantRotated && string(prev) != "older" {
				t.Errorf("agent.log.1 changed without a rotation: %q", prev)
			}
		})
	}
}
