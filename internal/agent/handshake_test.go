package agent

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeAgentBehavior is what the fake-agent helper does on its single
// connection. Behaviors get t so they can surface errors via t.Logf
// without us needing to silently discard them.
type fakeAgentBehavior func(t *testing.T, rw *bufio.ReadWriter)

// startFakeAgent spins up a listener on a fresh socket path, accepts one
// connection, and lets behavior drive the responses. Returns the socket
// path; the listener is closed on test cleanup.
func startFakeAgent(t *testing.T, behavior fakeAgentBehavior) string {
	t.Helper()
	sockPath := tempSocketPath(t)
	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mustClose(t, lis) })

	go func() {
		conn, aerr := lis.AcceptUnix()
		if aerr != nil {
			return // listener closed via t.Cleanup
		}
		defer mustClose(t, conn)
		if derr := conn.SetDeadline(time.Now().Add(2 * time.Second)); derr != nil {
			t.Logf("fake agent set deadline: %v", derr)
		}
		rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
		behavior(t, rw)
		if ferr := rw.Flush(); ferr != nil {
			t.Logf("fake agent flush: %v", ferr)
		}
	}()
	return sockPath
}

// consumeClientHello reads the first newline-terminated message from rw
// (the client's hello) and discards it. Logs but otherwise ignores any
// read error — the test cares about what the fake agent SENDS, not what
// the client said.
func consumeClientHello(t *testing.T, rw *bufio.ReadWriter) {
	t.Helper()
	if _, err := rw.ReadBytes('\n'); err != nil {
		t.Logf("fake agent consume hello: %v", err)
	}
}

// reply writes resp to rw, logging any write error.
func reply(t *testing.T, rw *bufio.ReadWriter, resp any) {
	t.Helper()
	if err := writeJSON(rw, resp); err != nil {
		t.Logf("fake agent write response: %v", err)
	}
}

func TestDialAndHandshake_AgentVersionMismatch(t *testing.T) {
	sockPath := startFakeAgent(t, func(t *testing.T, rw *bufio.ReadWriter) {
		consumeClientHello(t, rw)
		reply(t, rw, HelloResponse{Type: TypeHelloAck, Version: 99, AgentPID: 1})
	})
	_, err := dialAndHandshake(sockPath)
	if err == nil {
		t.Fatal("dialAndHandshake should fail on version mismatch")
	}
	if !strings.Contains(err.Error(), "version") {
		t.Errorf("err = %v, want version-mismatch message", err)
	}
}

func TestDialAndHandshake_AgentReturnsError(t *testing.T) {
	sockPath := startFakeAgent(t, func(t *testing.T, rw *bufio.ReadWriter) {
		consumeClientHello(t, rw)
		reply(t, rw, ErrorResponse{
			Type:    TypeError,
			Version: ProtocolVersion,
			Code:    ErrCodePeerCredMismatch,
			Message: "fake-agent peer-cred check failed",
		})
	})
	_, err := dialAndHandshake(sockPath)
	if err == nil {
		t.Fatal("dialAndHandshake should fail when agent returns error")
	}
	if !strings.Contains(err.Error(), ErrCodePeerCredMismatch) {
		t.Errorf("err = %v, want code mention", err)
	}
}

func TestDialAndHandshake_UnexpectedResponseType(t *testing.T) {
	sockPath := startFakeAgent(t, func(t *testing.T, rw *bufio.ReadWriter) {
		consumeClientHello(t, rw)
		reply(t, rw, struct {
			Type    string `json:"type"`
			Version int    `json:"version"`
		}{Type: "banana", Version: ProtocolVersion})
	})
	_, err := dialAndHandshake(sockPath)
	if err == nil {
		t.Fatal("dialAndHandshake should fail on unexpected response type")
	}
	if !strings.Contains(err.Error(), "unexpected response type") {
		t.Errorf("err = %v, want unexpected-type message", err)
	}
}

func TestDialAndHandshake_AgentClosesBeforeAck(t *testing.T) {
	sockPath := startFakeAgent(t, func(t *testing.T, rw *bufio.ReadWriter) {
		// Read the hello but never reply — connection closes when
		// the goroutine exits.
		consumeClientHello(t, rw)
	})
	_, err := dialAndHandshake(sockPath)
	if err == nil {
		t.Fatal("dialAndHandshake should fail when agent never sends hello_ack")
	}
	if !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "read hello_ack") {
		t.Errorf("err = %v, want read-error wrapping io.EOF", err)
	}
}

func TestDialAndHandshake_SilentAgentTimesOut(t *testing.T) {
	orig := helloTimeout
	helloTimeout = 200 * time.Millisecond
	t.Cleanup(func() { helloTimeout = orig })

	sockPath := tempSocketPath(t)
	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mustClose(t, lis) })
	accepted := make(chan *net.UnixConn, 1)
	go func() {
		conn, aerr := lis.AcceptUnix()
		if aerr != nil {
			return
		}
		accepted <- conn
	}()

	start := time.Now()
	_, err = dialAndHandshake(sockPath)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("dialAndHandshake succeeded against a silent agent")
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("err = %v, want a timeout", err)
	}
	if elapsed > time.Second {
		t.Fatalf("dialAndHandshake took %s, want the hello deadline", elapsed)
	}
	select {
	case conn := <-accepted:
		mustClose(t, conn)
	default:
	}
}

func TestRoundTrip_SilentAfterHelloTimesOut(t *testing.T) {
	orig := requestTimeout
	requestTimeout = 200 * time.Millisecond
	t.Cleanup(func() { requestTimeout = orig })

	sockPath := tempSocketPath(t)
	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mustClose(t, lis) })

	got := make(chan *net.UnixConn, 1)
	go func() {
		conn, aerr := lis.AcceptUnix()
		if aerr != nil {
			return
		}
		r := bufio.NewReader(conn)
		if _, _, rerr := readEnvelope(r); rerr != nil {
			closeOrLog(conn, "silent peer")
			return
		}
		if werr := writeJSON(conn, HelloResponse{
			Type: TypeHelloAck, Version: ProtocolVersion, AgentPID: 1,
		}); werr != nil {
			closeOrLog(conn, "silent peer")
			return
		}
		// Leave the connection open and unread so the client blocks in
		// roundTrip until its own deadline, rather than seeing EOF.
		got <- conn
	}()

	conn, err := dialAndHandshake(sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer mustClose(t, conn)

	start := time.Now()
	_, err = roundTrip(conn, PingRequest{Type: TypePing, Version: ProtocolVersion}, TypePong)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("roundTrip succeeded against a silent agent")
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("err = %v, want a timeout", err)
	}
	if elapsed > time.Second {
		t.Fatalf("roundTrip took %s, want the request deadline", elapsed)
	}
	select {
	case peer := <-got:
		mustClose(t, peer)
	case <-time.After(time.Second):
		t.Error("fake agent did not finish hello")
	}
}

func TestDialAndHandshake_FailsOnMissingSocket(t *testing.T) {
	// A fresh short /tmp path. macOS rejects Unix socket names past 104
	// bytes, and this file is never created.
	_, err := dialAndHandshake(tempSocketPath(t))
	if err == nil {
		t.Fatal("dialAndHandshake should fail on missing socket")
	}
}

func TestRoundTrip_UnexpectedReplyRetiresConnection(t *testing.T) {
	sockPath := startFakeAgent(t, func(t *testing.T, rw *bufio.ReadWriter) {
		consumeClientHello(t, rw)
		reply(t, rw, HelloResponse{Type: TypeHelloAck, Version: ProtocolVersion})
		if err := rw.Flush(); err != nil {
			t.Logf("fake agent flush: %v", err)
		}
		if _, err := rw.ReadBytes('\n'); err != nil {
			return
		}
		reply(t, rw, PingResponse{Type: TypePong, Version: ProtocolVersion}) // wrong reply to status
	})
	conn, err := dialAndHandshake(sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer mustClose(t, conn)

	if _, err := Status(conn); err == nil || !strings.Contains(err.Error(), `unexpected response type "pong"`) {
		t.Fatalf("Status err = %v, want unexpected response type", err)
	}
	if _, err := Status(conn); !errors.Is(err, errConnBroken) {
		t.Fatalf("second Status err = %v, want errConnBroken", err)
	}
}

// otherUser makes this process's UID look different from every peer's,
// as if each socket belonged to another user.
func otherUser(t *testing.T) {
	t.Helper()
	orig := currentUID
	currentUID = func() int { return orig() + 1 }
	t.Cleanup(func() { currentUID = orig })
}

func TestDialAndHandshake_RefusesAnotherUsersAgent(t *testing.T) {
	readErr := make(chan error, 1)
	sockPath := startFakeAgent(t, func(_ *testing.T, rw *bufio.ReadWriter) {
		_, err := rw.ReadByte()
		readErr <- err
	})
	otherUser(t)

	conn, err := dialAndHandshake(sockPath)
	if err == nil {
		mustClose(t, conn)
		t.Fatal("dialAndHandshake accepted an agent owned by another user")
	}
	if !strings.Contains(err.Error(), "is not this process's UID") {
		t.Fatalf("err = %v, want the peer UID refusal", err)
	}
	select {
	case err := <-readErr:
		// Any successful read, even of a zero byte, means the client sent
		// something before refusing.
		if !errors.Is(err, io.EOF) {
			t.Fatalf("fake agent read err = %v, want io.EOF (client sent data before refusing)", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fake agent never saw the connection close")
	}
}

func TestDialAndHandshake_OlderAgentNamesItsPID(t *testing.T) {
	sockPath := startFakeAgent(t, func(t *testing.T, rw *bufio.ReadWriter) {
		consumeClientHello(t, rw)
		reply(t, rw, ErrorResponse{
			Type:     TypeError,
			Version:  7,
			Code:     ErrCodeProtocolVersionMismatch,
			Message:  "client version 1, server 7",
			AgentPID: 4242,
		})
	})
	_, err := dialAndHandshake(sockPath)
	if !errors.Is(err, errProtocolMismatch) {
		t.Fatalf("err = %v, want errProtocolMismatch", err)
	}
	for _, want := range []string{"pid 4242", "protocol version 7", "kill 4242"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %q, want it to contain %q", err, want)
		}
	}
}

func TestDialAndHandshake_RejectionWithoutPIDStaysGeneric(t *testing.T) {
	sockPath := startFakeAgent(t, func(t *testing.T, rw *bufio.ReadWriter) {
		consumeClientHello(t, rw)
		reply(t, rw, ErrorResponse{Type: TypeError, Version: 7, Code: ErrCodeProtocolVersionMismatch, Message: "client version 1, server 7"})
	})
	_, err := dialAndHandshake(sockPath)
	if err == nil || !strings.Contains(err.Error(), "agent rejected hello: protocol_version_mismatch") {
		t.Fatalf("err = %v, want the generic rejection", err)
	}
}

func TestDialAndHandshake_MismatchWithoutUsablePIDNeverSuggestsKill(t *testing.T) {
	for _, tc := range []struct {
		resp any
		name string
	}{
		{HelloResponse{Type: TypeHelloAck, Version: 7}, "hello_ack without pid"},
		{HelloResponse{Type: TypeHelloAck, Version: 7, AgentPID: -1}, "hello_ack with negative pid"},
		{ErrorResponse{Type: TypeError, Version: 7, Code: ErrCodeProtocolVersionMismatch, Message: "client version 1, server 7", AgentPID: -1}, "rejection with negative pid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sockPath := startFakeAgent(t, func(t *testing.T, rw *bufio.ReadWriter) {
				consumeClientHello(t, rw)
				reply(t, rw, tc.resp)
			})
			_, err := dialAndHandshake(sockPath)
			if err == nil {
				t.Fatal("dialAndHandshake should fail on version mismatch")
			}
			if strings.Contains(err.Error(), "kill") {
				t.Errorf("err = %q, must not suggest kill without a positive pid", err)
			}
		})
	}
}
