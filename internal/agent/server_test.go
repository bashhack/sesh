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
	"strings"
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

func TestServer_CleansUpStaleSocketFile(t *testing.T) {
	sockPath := tempSocketPath(t)
	if err := os.WriteFile(sockPath, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sockPath); err != nil {
		t.Fatalf("setup: stale file not present: %v", err)
	}

	srv, err := Listen(sockPath)
	if err != nil {
		t.Fatalf("Listen should clean up stale file and succeed: %v", err)
	}
	defer mustClose(t, srv)
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

func TestServer_SIGTERMRemovesSocket(t *testing.T) {
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
			if werr := writeJSON(conn, PingRequest{Type: TypePing, Version: ProtocolVersion}); werr != nil {
				errs <- werr
				return
			}
			env, _, rerr := readEnvelope(bufio.NewReader(conn))
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
