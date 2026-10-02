package agent

import (
	"bufio"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/database"
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
	// The fake serves one connection; the re-dial after the failed stop
	// should give up quickly.
	origHello := helloTimeout
	helloTimeout = 100 * time.Millisecond
	t.Cleanup(func() { helloTimeout = origHello })
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

// blockDerive makes the next key derivations wait for release, and closes
// started when the first one begins.
func blockDerive(t *testing.T) (started <-chan struct{}, release chan<- struct{}) {
	t.Helper()
	s, r := make(chan struct{}), make(chan struct{})
	var once sync.Once
	orig := deriveKey
	deriveKey = func(pw, salt []byte, p database.Argon2idParams) []byte {
		once.Do(func() { close(s) })
		<-r
		return orig(pw, salt, p)
	}
	t.Cleanup(func() { deriveKey = orig })
	return s, r
}

func TestServer_NeverUnlockedExitWaitsForUnlockInProgress(t *testing.T) {
	for _, tt := range []struct {
		name     string
		password string
	}{
		{"unlock succeeds", "correct-horse"},
		{"unlock fails", "wrong-horse"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sockPath := tempSocketPath(t)
			clk := newFakeClock()
			_, done := serve(t, sockPath, withClock(clk), WithExitOnAutoLock(), WithIdleTimeout(time.Minute), WithMaxLifetime(0))
			params := lightParams()
			salt, verify := sealVerify(t, "correct-horse", params)
			started, release := blockDerive(t)
			conn := dialClient(t, sockPath)
			defer mustClose(t, conn)

			unlocked := make(chan error, 1)
			go func() { unlocked <- Unlock(conn, []byte(tt.password), salt, verify, params) }()
			<-started
			clk.advance(time.Minute) // the startup deadline passes mid-derivation
			close(release)
			err := <-unlocked
			if tt.password == "correct-horse" && err != nil {
				t.Fatalf("unlock that began before the deadline failed: %v", err)
			}
			select {
			case <-done:
				t.Fatal("agent exited while an unlock was in progress")
			default:
			}

			if tt.password == "correct-horse" {
				return
			}
			// Still never unlocked: it exits one idle timeout after the
			// deadline it waited past, not sooner.
			clk.advance(30 * time.Second)
			select {
			case <-done:
				t.Fatal("agent exited before the extra idle timeout")
			default:
			}
			clk.advance(30 * time.Second)
			waitRun(t, done)
		})
	}
}

// startVanishingAgent serves one hello_ack from an "older-build" agent,
// then, when the stop request arrives, removes its socket and drops the
// connection without replying: an agent that exited between a client's
// dial and its stop. If successor is set, it runs after the socket is
// gone and before the connection drops.
func startVanishingAgent(t *testing.T, sockPath string, successor func()) {
	t.Helper()
	lis, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := lis.Accept()
		if err != nil {
			return
		}
		rw := bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))
		consumeClientHello(t, rw)
		reply(t, rw, HelloResponse{Type: TypeHelloAck, Version: ProtocolVersion, AgentPID: 4242, AgentBuild: "older-build"})
		if err := rw.Flush(); err != nil {
			t.Logf("fake agent flush: %v", err)
		}
		if _, _, err := readEnvelope(rw.Reader); err != nil {
			t.Logf("fake agent read stop: %v", err)
		}
		if err := lis.Close(); err != nil {
			t.Logf("fake agent close listener: %v", err)
		}
		if successor != nil {
			successor()
		}
		if err := c.Close(); err != nil {
			t.Logf("fake agent close conn: %v", err)
		}
	}()
}

func TestDialCurrent_AgentGoneBeforeStop(t *testing.T) {
	t.Run("nothing replaced it", func(t *testing.T) {
		fakeOwnBuild(t, "newer-build")
		sockPath := tempSocketPath(t)
		startVanishingAgent(t, sockPath, nil)
		if _, err := dialCurrent(sockPath); !errors.Is(err, errAgentReplaced) {
			t.Fatalf("err = %v, want errAgentReplaced so the caller spawns", err)
		}
	})
	t.Run("a current agent replaced it", func(t *testing.T) {
		sockPath := tempSocketPath(t)
		startVanishingAgent(t, sockPath, func() { serve(t, sockPath) })
		fakeOwnBuild(t, Build())
		conn, err := dialCurrent(sockPath)
		if err != nil {
			t.Fatalf("dialCurrent: %v, want the replacement agent", err)
		}
		defer mustClose(t, conn)
		if conn.agentBuild != Build() {
			t.Errorf("connected to build %q, want the current %q", conn.agentBuild, Build())
		}
	})
}
