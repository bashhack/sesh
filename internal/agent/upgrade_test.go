package agent

import (
	"bufio"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/testutil"
)

// fakeOwnBuild makes this process report build b, as a newer sesh would.
func fakeOwnBuild(t *testing.T, b string) {
	t.Helper()
	orig := thisBuild
	thisBuild = func() string { return b }
	t.Cleanup(func() { thisBuild = orig })
}

// waitRun fails unless Run has returned nil within two seconds.
func waitRun(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent still running")
	}
}

func TestOtherBuild(t *testing.T) {
	tests := map[string]struct {
		mine, agent string
		want        bool
	}{
		"same build":            {"aaa", "aaa", false},
		"different build":       {"aaa", "bbb", true},
		"agent predates builds": {"aaa", "", true},
		"own build unreadable":  {"", "bbb", false},
		"neither knows a build": {"", "", false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			fakeOwnBuild(t, tt.mine)
			if got := otherBuild(tt.agent); got != tt.want {
				t.Errorf("otherBuild(%q) with own build %q = %v, want %v", tt.agent, tt.mine, got, tt.want)
			}
		})
	}
}

func TestServer_HelloReportsBuild(t *testing.T) {
	sockPath := tempSocketPath(t)
	serve(t, sockPath)
	conn := dialClient(t, sockPath)
	defer mustClose(t, conn)
	if conn.agentBuild == "" || conn.agentBuild != Build() {
		t.Errorf("hello_ack build = %q, want this test binary's %q", conn.agentBuild, Build())
	}
}

func TestEnsureAgent_ReplacesAgentFromAnotherBuild(t *testing.T) {
	sockPath := useTempSocketEnv(t)
	useTestSpawn(t)
	defer cleanupAgent(t, sockPath)
	var log logBuffer
	_, done := serve(t, sockPath, withLogOutput(&log))
	fakeOwnBuild(t, "newer-build")

	restore := testutil.RedirectStderr(t)
	conn, err := EnsureAgent()
	out := restore()
	if err != nil {
		t.Fatalf("EnsureAgent: %v", err)
	}
	defer mustClose(t, conn)

	waitRun(t, done)
	if !strings.Contains(log.String(), "stopping (stop request)") {
		t.Errorf("old agent log missing the stop:\n%s", log.String())
	}
	if conn.agentPID == os.Getpid() {
		t.Error("EnsureAgent returned the old in-process agent")
	}
	if !strings.Contains(out, "Restarted the sesh agent") {
		t.Errorf("stderr = %q, want the restart notice", out)
	}
}

func TestDialCurrent_ReportsAgentThatWontStop(t *testing.T) {
	fakeOwnBuild(t, "newer-build")
	sockPath := startFakeAgent(t, func(t *testing.T, rw *bufio.ReadWriter) {
		consumeClientHello(t, rw)
		reply(t, rw, HelloResponse{Type: TypeHelloAck, Version: ProtocolVersion, AgentPID: 4242, AgentBuild: "older-build"})
		if err := rw.Flush(); err != nil {
			t.Logf("fake agent flush hello_ack: %v", err)
			return
		}
		if _, _, err := readEnvelope(rw.Reader); err != nil {
			t.Logf("fake agent read stop: %v", err)
			return
		}
		reply(t, rw, ErrorResponse{Type: TypeError, Version: ProtocolVersion, Code: ErrCodeInternal, Message: "shutdown incomplete"})
	})
	_, err := dialCurrent(sockPath)
	if err == nil || errors.Is(err, errAgentReplaced) || !strings.Contains(err.Error(), "kill 4242") {
		t.Fatalf("err = %v, want a stop failure naming kill 4242", err)
	}
}

func TestServer_ExitOnAutoLock(t *testing.T) {
	tests := map[string]struct {
		wantLog string
		opts    []Option
		advance time.Duration
		unlock  bool
	}{
		"idle timeout":   {"stopping (locked after idle timeout)", []Option{WithIdleTimeout(time.Minute), WithMaxLifetime(0)}, time.Minute, true},
		"max lifetime":   {"stopping (locked after max lifetime)", []Option{WithIdleTimeout(0), WithMaxLifetime(time.Hour)}, time.Hour, true},
		"never unlocked": {"stopping (not unlocked within the idle timeout)", []Option{WithIdleTimeout(time.Minute)}, time.Minute, false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			sockPath := tempSocketPath(t)
			var log logBuffer
			clk := newFakeClock()
			opts := append([]Option{withLogOutput(&log), withClock(clk), WithExitOnAutoLock()}, tt.opts...)
			_, done := serve(t, sockPath, opts...)
			// A completed exchange proves Run is serving, so its timers exist.
			var conn *Conn
			if tt.unlock {
				conn, _ = unlockClient(t, sockPath)
			} else {
				conn = dialClient(t, sockPath)
			}
			defer mustClose(t, conn)

			clk.advance(tt.advance)
			waitRun(t, done)
			if _, err := os.Stat(sockPath); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("socket still present after exit: %v", err)
			}
			if !strings.Contains(log.String(), tt.wantLog) {
				t.Errorf("log missing %q:\n%s", tt.wantLog, log.String())
			}
		})
	}
}

func TestServer_KeepsRunningWhenLockedOnRequest(t *testing.T) {
	sockPath := tempSocketPath(t)
	clk := newFakeClock()
	_, done := serve(t, sockPath, withClock(clk), WithExitOnAutoLock(), WithIdleTimeout(time.Minute))
	conn, _ := unlockClient(t, sockPath)
	defer mustClose(t, conn)
	if err := Lock(conn); err != nil {
		t.Fatal(err)
	}

	clk.advance(10 * time.Minute)
	select {
	case <-done:
		t.Fatal("agent locked on request exited")
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := Status(conn); err != nil {
		t.Fatalf("status after lock: %v", err)
	}
}

func TestServer_StaysRunningAfterAutoLockByDefault(t *testing.T) {
	sockPath := tempSocketPath(t)
	clk := newFakeClock()
	_, done := serve(t, sockPath, withClock(clk), WithIdleTimeout(time.Minute))
	conn, _ := unlockClient(t, sockPath)
	defer mustClose(t, conn)

	clk.advance(time.Minute)
	select {
	case <-done:
		t.Fatal("agent without WithExitOnAutoLock exited")
	case <-time.After(100 * time.Millisecond):
	}
	st, err := Status(conn)
	if err != nil || st.Unlocked {
		t.Fatalf("status = %+v, %v; want running and locked", st, err)
	}
}
