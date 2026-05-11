package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// Server owns the listening socket and dispatches incoming connections
// to per-connection handler goroutines.
type Server struct {
	shutdownErr error
	listener    *net.UnixListener
	sockPath    string
	// shutdownOnce guards Close so concurrent SIGTERM + accept-loop-exit
	// don't try to remove the socket twice.
	shutdownOnce sync.Once
}

// Listen creates the socket at sockPath, sets perm 0600, and returns a
// Server ready to Run. If a stale socket file exists from a prior
// crashed agent, Listen removes it before binding — but only after
// confirming no live agent is actually answering on it.
func Listen(sockPath string) (*Server, error) {
	if _, err := os.Stat(sockPath); err == nil {
		// File exists. Distinguish "stale file from prior crash" from
		// "another agent is running" by trying to connect.
		if conn, derr := net.DialTimeout("unix", sockPath, dialTimeout); derr == nil {
			closeOrLog(conn, "probe connection")
			return nil, fmt.Errorf("agent already running at %s", sockPath)
		}
		if rerr := os.Remove(sockPath); rerr != nil {
			return nil, fmt.Errorf("remove stale socket %s: %w", sockPath, rerr)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("stat socket %s: %w", sockPath, err)
	}

	laddr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("resolve unix addr: %w", err)
	}
	lis, err := net.ListenUnix("unix", laddr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", sockPath, err)
	}
	if err := os.Chmod(sockPath, 0o600); err != nil {
		closeOrLog(lis, "listener after chmod failure")
		if rerr := os.Remove(sockPath); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			return nil, fmt.Errorf("chmod socket: %w (cleanup also failed: %v)", err, rerr)
		}
		return nil, fmt.Errorf("chmod socket: %w", err)
	}
	return &Server{sockPath: sockPath, listener: lis}, nil
}

// SocketPath returns the path the server is bound to. Useful for tests
// and `sesh agent status` introspection in later phases.
func (s *Server) SocketPath() string {
	return s.sockPath
}

// Run blocks until ctx is cancelled or SIGTERM/SIGINT arrives, accepting
// connections and dispatching them on per-connection goroutines. On exit
// it closes the listener and removes the socket file.
func (s *Server) Run(ctx context.Context) error {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigCh)

	go func() {
		select {
		case <-ctx.Done():
		case <-sigCh:
		}
		if err := s.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: agent shutdown: %v\n", err) //nolint:errcheck // best-effort warning
		}
	}()

	for {
		conn, err := s.listener.AcceptUnix()
		if err != nil {
			// Listener closed during shutdown produces a net.ErrClosed
			// or equivalent; treat that as a clean exit, not an error.
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		go s.handleConn(conn)
	}
}

// Close shuts down the server: stops accepting, removes the socket file.
// Safe to call multiple times; subsequent calls are no-ops.
func (s *Server) Close() error {
	s.shutdownOnce.Do(func() {
		if cerr := s.listener.Close(); cerr != nil && !errors.Is(cerr, net.ErrClosed) {
			s.shutdownErr = fmt.Errorf("close listener: %w", cerr)
		}
		if rerr := os.Remove(s.sockPath); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			if s.shutdownErr == nil {
				s.shutdownErr = fmt.Errorf("remove socket: %w", rerr)
			}
		}
	})
	return s.shutdownErr
}

// handleConn services one client connection: peer-cred check, hello
// handshake, then ping until the peer disconnects or sends an unknown
// message. Each connection runs on its own goroutine; handleConn closes
// the connection on exit.
func (s *Server) handleConn(conn *net.UnixConn) {
	defer closeOrLog(conn, "client connection")

	if err := checkPeerCred(conn); err != nil {
		sendErrorAndIgnore(conn, ErrCodePeerCredMismatch, err.Error())
		return
	}

	r := bufio.NewReader(conn)

	// First message must be hello.
	env, raw, err := readEnvelope(r)
	if err != nil {
		if !isCleanDisconnect(err) {
			sendErrorAndIgnore(conn, ErrCodeInternal, err.Error())
		}
		return
	}
	if env.Type != TypeHello {
		sendErrorAndIgnore(conn, ErrCodeUnknownMessageType,
			fmt.Sprintf("first message must be %q, got %q", TypeHello, env.Type))
		return
	}
	if env.Version != ProtocolVersion {
		sendErrorAndIgnore(conn, ErrCodeProtocolVersionMismatch,
			fmt.Sprintf("client version %d, server %d", env.Version, ProtocolVersion))
		return
	}
	var hello HelloRequest
	if err := decodeMessage(raw, &hello); err != nil {
		sendErrorAndIgnore(conn, ErrCodeInternal, err.Error())
		return
	}
	if err := writeJSON(conn, HelloResponse{
		Type:     TypeHelloAck,
		Version:  ProtocolVersion,
		AgentPID: os.Getpid(),
	}); err != nil {
		return
	}

	// Subsequent messages.
	for {
		env, _, err := readEnvelope(r)
		if err != nil {
			return
		}
		switch env.Type {
		case TypePing:
			if err := writeJSON(conn, PingResponse{
				Type:    TypePong,
				Version: ProtocolVersion,
			}); err != nil {
				return
			}
		default:
			if err := writeJSON(conn, ErrorResponse{
				Type:    TypeError,
				Version: ProtocolVersion,
				Code:    ErrCodeUnknownMessageType,
				Message: fmt.Sprintf("type %q not recognized", env.Type),
			}); err != nil {
				return
			}
		}
	}
}

// sendErrorAndIgnore writes an ErrorResponse and silently discards any
// write failure — by the time we're sending an error, the client has
// already misbehaved or the connection is dying, so the secondary
// failure isn't actionable.
func sendErrorAndIgnore(conn *net.UnixConn, code, message string) {
	if err := writeJSON(conn, ErrorResponse{
		Type:    TypeError,
		Version: ProtocolVersion,
		Code:    code,
		Message: message,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: write error response: %v\n", err) //nolint:errcheck // best-effort warning
	}
}

// isCleanDisconnect reports whether err is a "peer closed the connection
// without sending any data" — i.e. a normal end-of-conversation, not a
// protocol error worth reporting.
func isCleanDisconnect(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}
