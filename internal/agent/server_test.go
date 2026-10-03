package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// tempSocketPath returns a short path suitable for binding a Unix socket.
// macOS caps socket paths at 104 chars and t.TempDir() lives under
// /var/folders/.../TestName.../NNN which by itself can exceed the limit
// once the test name is long. Using /tmp directly keeps us under it.
func tempSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "sa")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() {
		if rerr := os.RemoveAll(dir); rerr != nil {
			t.Errorf("RemoveAll(%s): %v", dir, rerr)
		}
	})
	return filepath.Join(dir, "s")
}

// mustClose closes c, failing the test if Close returns an error. Used
// in place of `defer func() { _ = c.Close() }()` so errcheck stays
// happy without nolint.
func mustClose(t *testing.T, c io.Closer) {
	t.Helper()
	if err := c.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

// dialAndShake is a test helper that dials the agent socket and runs the
// hello handshake. Mirrors what a real CLI client does on connect.
func dialAndShake(t *testing.T, sockPath string) *net.UnixConn {
	t.Helper()
	return dialClient(t, sockPath).uc
}

// dialClient dials and handshakes, returning the client connection used
// by Unlock, Encrypt, Decrypt, and Status.
func dialClient(t *testing.T, sockPath string) *Conn {
	t.Helper()
	conn, err := dialAndHandshake(sockPath)
	if err != nil {
		t.Fatalf("dialAndHandshake: %v", err)
	}
	return conn
}

// runServer starts a server on its own goroutine and returns a stop
// function. The caller defers stop() to shut it down.
func runServer(t *testing.T, sockPath string) func() {
	t.Helper()
	srv, err := Listen(sockPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		if err := srv.Run(ctx); err != nil {
			t.Errorf("server Run: %v", err)
		}
		close(done)
	}()
	return func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Errorf("server Run did not exit within 2s after cancel")
		}
	}
}

func TestServer_SocketPathGetter(t *testing.T) {
	sockPath := tempSocketPath(t)
	srv, err := Listen(sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer mustClose(t, srv)
	if got := srv.SocketPath(); got != sockPath {
		t.Errorf("SocketPath() = %q, want %q", got, sockPath)
	}
}

func TestServer_HelloHandshake(t *testing.T) {
	sockPath := tempSocketPath(t)
	stop := runServer(t, sockPath)
	defer stop()

	conn := dialAndShake(t, sockPath)
	defer mustClose(t, conn)
}

func TestServer_HelloAckIncludesAgentPID(t *testing.T) {
	sockPath := tempSocketPath(t)
	stop := runServer(t, sockPath)
	defer stop()

	raw, err := net.DialTimeout("unix", sockPath, dialTimeout)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn := raw.(*net.UnixConn)
	defer mustClose(t, conn)

	if err := writeJSON(conn, HelloRequest{Type: TypeHello, Version: ProtocolVersion}); err != nil {
		t.Fatal(err)
	}

	r := bufio.NewReader(conn)
	_, raw2, err := readEnvelope(r)
	if err != nil {
		t.Fatal(err)
	}
	var ack HelloResponse
	if err := decodeMessage(raw2, &ack); err != nil {
		t.Fatal(err)
	}
	if ack.Type != TypeHelloAck {
		t.Errorf("Type = %q, want %q", ack.Type, TypeHelloAck)
	}
	if ack.AgentPID != os.Getpid() {
		t.Errorf("AgentPID = %d, want %d (server runs in test process)", ack.AgentPID, os.Getpid())
	}
}

func TestServer_PingPong(t *testing.T) {
	sockPath := tempSocketPath(t)
	stop := runServer(t, sockPath)
	defer stop()

	conn := dialAndShake(t, sockPath)
	defer mustClose(t, conn)

	if err := writeJSON(conn, PingRequest{Type: TypePing, Version: ProtocolVersion}); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(conn)
	env, _, err := readEnvelope(r)
	if err != nil {
		t.Fatal(err)
	}
	if env.Type != TypePong {
		t.Errorf("response type = %q, want %q", env.Type, TypePong)
	}
}

func TestServer_VersionMismatchRejectsHello(t *testing.T) {
	sockPath := tempSocketPath(t)
	stop := runServer(t, sockPath)
	defer stop()

	raw, err := net.DialTimeout("unix", sockPath, dialTimeout)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn := raw.(*net.UnixConn)
	defer mustClose(t, conn)

	if err := writeJSON(conn, HelloRequest{Type: TypeHello, Version: 99}); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(conn)
	_, line, err := readEnvelope(r)
	if err != nil {
		t.Fatal(err)
	}
	var got ErrorResponse
	if err := decodeMessage(line, &got); err != nil {
		t.Fatal(err)
	}
	if got.Code != ErrCodeProtocolVersionMismatch {
		t.Errorf("Code = %q, want %q (full message: %q)", got.Code, ErrCodeProtocolVersionMismatch, got.Message)
	}
	if got.AgentPID != os.Getpid() {
		t.Errorf("AgentPID = %d, want the agent's pid %d", got.AgentPID, os.Getpid())
	}
}

func TestServer_NonHelloFirstMessageRejected(t *testing.T) {
	sockPath := tempSocketPath(t)
	stop := runServer(t, sockPath)
	defer stop()

	raw, err := net.DialTimeout("unix", sockPath, dialTimeout)
	if err != nil {
		t.Fatal(err)
	}
	conn := raw.(*net.UnixConn)
	defer mustClose(t, conn)

	if err := writeJSON(conn, PingRequest{Type: TypePing, Version: ProtocolVersion}); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(conn)
	_, line, err := readEnvelope(r)
	if err != nil {
		t.Fatal(err)
	}
	var got ErrorResponse
	if err := decodeMessage(line, &got); err != nil {
		t.Fatal(err)
	}
	if got.Code != ErrCodeUnknownMessageType {
		t.Errorf("Code = %q, want %q", got.Code, ErrCodeUnknownMessageType)
	}
	if !strings.Contains(got.Message, TypeHello) {
		t.Errorf("Message %q should mention %q", got.Message, TypeHello)
	}
}

func TestServer_UnknownMessageTypeAfterHello(t *testing.T) {
	sockPath := tempSocketPath(t)
	stop := runServer(t, sockPath)
	defer stop()

	conn := dialAndShake(t, sockPath)
	defer mustClose(t, conn)

	if err := writeJSON(conn, struct {
		Type    string `json:"type"`
		Version int    `json:"version"`
	}{Type: "banana", Version: ProtocolVersion}); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(conn)
	_, line, err := readEnvelope(r)
	if err != nil {
		t.Fatal(err)
	}
	var got ErrorResponse
	if err := decodeMessage(line, &got); err != nil {
		t.Fatal(err)
	}
	if got.Code != ErrCodeUnknownMessageType {
		t.Errorf("Code = %q, want %q", got.Code, ErrCodeUnknownMessageType)
	}
}

func TestServer_TruncatedFrameAfterHello(t *testing.T) {
	sockPath := tempSocketPath(t)
	stop := runServer(t, sockPath)
	defer stop()

	conn := dialAndShake(t, sockPath)
	defer mustClose(t, conn)

	if _, err := conn.Write([]byte(`{"type":"ping"`)); err != nil {
		t.Fatal(err)
	}
	// Half-close so the server sees EOF mid-frame and can still write
	// the error response back.
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(conn)
	_, line, err := readEnvelope(r)
	if err != nil {
		t.Fatal(err)
	}
	var got ErrorResponse
	if err := decodeMessage(line, &got); err != nil {
		t.Fatal(err)
	}
	if got.Code != ErrCodeInternal {
		t.Errorf("Code = %q, want %q", got.Code, ErrCodeInternal)
	}
	if !strings.Contains(got.Message, "truncated frame") {
		t.Errorf("Message = %q, want mention of truncated frame", got.Message)
	}
}

func TestServer_ClientDisconnectMidStreamLeavesServerHealthy(t *testing.T) {
	sockPath := tempSocketPath(t)
	stop := runServer(t, sockPath)
	defer stop()

	conn := dialAndShake(t, sockPath)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	conn2 := dialAndShake(t, sockPath)
	defer mustClose(t, conn2)
}

func TestServer_RefusesIfSocketAlreadyBound(t *testing.T) {
	sockPath := tempSocketPath(t)
	stop := runServer(t, sockPath)
	defer stop()

	_, err := Listen(sockPath)
	if err == nil {
		t.Fatal("Listen on already-bound socket should fail")
	}
	if !strings.Contains(err.Error(), "already running") {
		t.Errorf("err = %v, want mention of 'already running'", err)
	}
}

// leftoverSocket leaves a Unix socket inode with nobody listening. A
// later dial fails with ECONNREFUSED, which is the only signal that the
// path is stale.
func leftoverSocket(t *testing.T, sockPath string) {
	t.Helper()
	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	lis.SetUnlinkOnClose(false)
	if err := lis.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestServer_CleansUpStaleSocketFile(t *testing.T) {
	sockPath := tempSocketPath(t)
	leftoverSocket(t, sockPath)
	if _, err := os.Stat(sockPath); err != nil {
		t.Fatalf("setup: stale socket not present: %v", err)
	}

	srv, err := Listen(sockPath)
	if err != nil {
		t.Fatalf("Listen should clean up stale file and succeed: %v", err)
	}
	defer mustClose(t, srv)
}

func TestListen_RefusesUnreadableLiveSocket(t *testing.T) {
	sockPath := tempSocketPath(t)
	stop := runServer(t, sockPath)
	defer func() {
		if err := os.Chmod(sockPath, 0o600); err != nil && !os.IsNotExist(err) {
			t.Errorf("restore socket mode: %v", err)
		}
		stop()
	}()
	if err := os.Chmod(sockPath, 0); err != nil {
		t.Fatal(err)
	}

	_, err := Listen(sockPath)
	if err == nil {
		t.Fatal("Listen replaced a live socket it could not probe")
	}
	if _, statErr := os.Stat(sockPath); statErr != nil {
		t.Fatalf("socket removed: %v", statErr)
	}
}

func TestServer_WrongVersionAfterHelloCloses(t *testing.T) {
	sockPath := tempSocketPath(t)
	stop := runServer(t, sockPath)
	defer stop()

	conn := dialAndShake(t, sockPath)
	defer mustClose(t, conn)
	if err := writeJSON(conn, PingRequest{Type: TypePing, Version: 99}); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(conn)
	_, line, err := readEnvelope(r)
	if err != nil {
		t.Fatal(err)
	}
	var got ErrorResponse
	if err := decodeMessage(line, &got); err != nil {
		t.Fatal(err)
	}
	if got.Code != ErrCodeProtocolVersionMismatch {
		t.Fatalf("Code = %q, want %q", got.Code, ErrCodeProtocolVersionMismatch)
	}
	if _, _, err := readEnvelope(r); err == nil {
		t.Fatal("connection stayed open after a version mismatch")
	}
}

func TestServer_UnlockRejectsUndecodableRequest(t *testing.T) {
	sockPath := tempSocketPath(t)
	stop := runServer(t, sockPath)
	defer stop()

	conn := dialAndShake(t, sockPath)
	defer mustClose(t, conn)
	if _, err := conn.Write([]byte("{\"type\":\"unlock\",\"version\":1,\"password\":1}\n")); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, line, err := readEnvelope(bufio.NewReader(conn))
	if err != nil {
		t.Fatal(err)
	}
	var got ErrorResponse
	if err := decodeMessage(line, &got); err != nil {
		t.Fatal(err)
	}
	if got.Code != ErrCodeBadRequest {
		t.Fatalf("Code = %q, want %q (%s)", got.Code, ErrCodeBadRequest, got.Message)
	}
}

func TestServer_CloseZeroesKey(t *testing.T) {
	sockPath := tempSocketPath(t)
	srv, err := Listen(sockPath)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- srv.Run(context.Background())
	}()

	params := lightParams()
	salt, verify := sealVerify(t, "correct-horse", params)
	conn := dialClient(t, sockPath)
	if err := Unlock(conn, []byte("correct-horse"), salt, verify, params); err != nil {
		t.Fatal(err)
	}
	mustClose(t, conn)
	if !srv.keys.snapshot().unlocked {
		t.Fatal("setup: keystore is locked")
	}
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	if srv.keys.snapshot().unlocked {
		t.Fatal("Close left the keystore unlocked")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned err = %v, want nil after Close", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after Close")
	}
}

func TestServer_ShutdownRemovesSocket(t *testing.T) {
	sockPath := tempSocketPath(t)
	stop := runServer(t, sockPath)
	if _, err := os.Stat(sockPath); err != nil {
		t.Fatalf("socket not bound after Listen: %v", err)
	}
	stop()
	if _, err := os.Stat(sockPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket file should be removed after shutdown, stat err = %v", err)
	}
}

func TestServer_DirectCloseStopsRun(t *testing.T) {
	sockPath := tempSocketPath(t)
	srv, err := Listen(sockPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- srv.Run(context.Background())
	}()

	raw, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Errorf("close dial: %v", err)
	}

	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned err = %v, want nil after Close", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit within 2s of Close")
	}

	if _, err := os.Stat(sockPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket file should be removed after Close, stat err = %v", err)
	}

	// Run.func1 is the shutdown watcher. Close unblocks Accept without a
	// signal, and the watcher still has to exit once Run returns.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !goroutineStackContains("(*Server).Run.func1") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("shutdown watcher still running after Run returned")
}

func goroutineStackContains(substr string) bool {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return strings.Contains(string(buf[:n]), substr)
}

// testSigtermMutex serializes tests that send process-level signals so
// they don't fire each other's handlers when run with t.Parallel().
var testSigtermMutex sync.Mutex

func TestServer_SIGTERMRemovesSocket(t *testing.T) {
	testSigtermMutex.Lock()
	defer testSigtermMutex.Unlock()

	sockPath := tempSocketPath(t)
	srv, err := Listen(sockPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- srv.Run(context.Background())
	}()

	time.Sleep(20 * time.Millisecond)

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned err = %v, want nil after SIGTERM", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server didn't exit within 2s of SIGTERM")
	}

	if _, err := os.Stat(sockPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket file should be removed after SIGTERM, stat err = %v", err)
	}
}

func TestServer_HandlesManyConcurrentClients(t *testing.T) {
	sockPath := tempSocketPath(t)
	stop := runServer(t, sockPath)
	defer stop()

	const N = 10
	errs := make(chan error, N)
	for range N {
		go func() {
			conn, err := dialAndHandshake(sockPath)
			if err != nil {
				errs <- err
				return
			}
			defer mustClose(t, conn)
			if werr := writeJSON(conn.uc, PingRequest{Type: TypePing, Version: ProtocolVersion}); werr != nil {
				errs <- werr
				return
			}
			env, _, rerr := readEnvelope(conn.r)
			if rerr != nil {
				errs <- rerr
				return
			}
			if env.Type != TypePong {
				errs <- fmt.Errorf("got %q, want %q", env.Type, TypePong)
				return
			}
			errs <- nil
		}()
	}
	for range N {
		if err := <-errs; err != nil {
			t.Errorf("client err: %v", err)
		}
	}
}

func TestServer_RejectsUndecodableCryptoRequests(t *testing.T) {
	sockPath := tempSocketPath(t)
	stop := runServer(t, sockPath)
	defer stop()

	for _, req := range []string{
		`{"type":"decrypt","version":1,"ciphertext":1}`,
		`{"type":"encrypt","version":1,"plaintext":1}`,
	} {
		conn := dialAndShake(t, sockPath)
		if _, err := conn.Write([]byte(req + "\n")); err != nil {
			t.Fatal(err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		_, line, err := readEnvelope(bufio.NewReader(conn))
		if err != nil {
			t.Fatal(err)
		}
		var got ErrorResponse
		if err := decodeMessage(line, &got); err != nil {
			t.Fatal(err)
		}
		if got.Code != ErrCodeBadRequest {
			t.Errorf("%s: Code = %q, want %q (%s)", req, got.Code, ErrCodeBadRequest, got.Message)
		}
		mustClose(t, conn)
	}
}
