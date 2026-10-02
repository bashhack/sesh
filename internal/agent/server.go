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
	"time"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/secure"
)

// Server owns the listening socket and dispatches incoming connections
// to per-connection handler goroutines.
type Server struct {
	startedAt   time.Time
	shutdownErr error
	listener    *net.UnixListener
	sockPath    string
	keys        keystore
	// lockKeyMemory is set by WithLockedKeyMemory.
	lockKeyMemory bool
	// shutdownOnce guards Close so concurrent SIGTERM + accept-loop-exit
	// don't try to remove the socket twice.
	shutdownOnce sync.Once
}

// Listen creates the socket at sockPath, sets perm 0600, and returns a
// Server ready to Run. A leftover socket inode is removed only when
// connect fails with ECONNREFUSED, which means nothing is listening.
// Any other dial error leaves the path in place. The auto-lock timeouts
// default to DefaultIdleTimeout and DefaultMaxLifetime; opts override them.
func Listen(sockPath string, opts ...Option) (*Server, error) {
	srv := &Server{sockPath: sockPath}
	srv.keys.idleTimeout = DefaultIdleTimeout
	srv.keys.maxLifetime = DefaultMaxLifetime
	for _, opt := range opts {
		opt(srv)
	}
	// Reserved before the socket exists, so an agent that can't protect
	// its key never accepts a connection.
	if srv.lockKeyMemory {
		page, err := lockedPage()
		if err != nil {
			return nil, fmt.Errorf("reserve key memory: %w", err)
		}
		srv.keys.keyBuf = page
	}

	if _, err := os.Stat(sockPath); err == nil {
		conn, derr := net.DialTimeout("unix", sockPath, dialTimeout)
		if derr == nil {
			closeOrLog(conn, "probe connection")
			return nil, fmt.Errorf("agent already running at %s", sockPath)
		}
		if !errors.Is(derr, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("socket %s is not a stale listener: %w", sockPath, derr)
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
	srv.listener = lis
	srv.startedAt = srv.keys.clock().Now()
	return srv, nil
}

// SocketPath returns the path the server is bound to. Useful for tests
// and `sesh agent status` introspection in later phases.
func (s *Server) SocketPath() string {
	return s.sockPath
}

// Run blocks until ctx is cancelled or SIGTERM/SIGINT arrives, accepting
// connections and dispatching them on per-connection goroutines. SIGUSR1
// locks the agent without stopping it. On exit it closes the listener and
// removes the socket file.
func (s *Server) Run(ctx context.Context) error {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGUSR1)
	defer signal.Stop(sigCh)

	// Cancelled on every return so the watcher cannot outlive Run. Close
	// still runs on that wake: a parent cancel has to shut the listener
	// down, and an accept failure has to remove the socket.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		for {
			select {
			case <-runCtx.Done():
			case sig := <-sigCh:
				if sig == syscall.SIGUSR1 {
					s.keys.lock()
					fmt.Fprintln(os.Stderr, "sesh agent: locked (SIGUSR1)") //nolint:errcheck // best-effort log line
					continue
				}
			}
			if err := s.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "warning: agent shutdown: %v\n", err) //nolint:errcheck // best-effort warning
			}
			return
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
			if cerr := s.Close(); cerr != nil {
				return fmt.Errorf("accept: %w (shutdown: %v)", err, cerr)
			}
			return fmt.Errorf("accept: %w", err)
		}
		go s.handleConn(conn)
	}
}

// Close shuts down the server: stops accepting, removes the socket file,
// then zeroes the cached master key. An unlock still in progress on an
// open connection discards its key instead of installing it. Safe to
// call multiple times; subsequent calls are no-ops.
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
		s.keys.shutdown()
	})
	return s.shutdownErr
}

// handleConn services one client connection: peer-cred check, hello
// handshake, then unlock, encrypt, decrypt, status, and ping until the
// peer disconnects. Each connection runs on its own goroutine; handleConn
// closes the connection on exit.
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
			sendErrorAndIgnore(conn, readErrCode(err), err.Error())
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

	// Subsequent messages. A clean EOF is a normal disconnect; anything
	// else (truncated frame, malformed JSON) is reported, same as the
	// handshake read above.
	for {
		env, raw, err := readEnvelope(r)
		if err != nil {
			if !isCleanDisconnect(err) {
				sendErrorAndIgnore(conn, readErrCode(err), err.Error())
			}
			return
		}
		if !s.dispatch(conn, env, raw) {
			return
		}
	}
}

// dispatch serves one post-handshake message. false means the connection
// should close (write failure or a fatal version mismatch).
func (s *Server) dispatch(conn *net.UnixConn, env envelope, raw []byte) bool {
	if env.Version != ProtocolVersion {
		sendErrorAndIgnore(conn, ErrCodeProtocolVersionMismatch,
			fmt.Sprintf("client version %d, server %d", env.Version, ProtocolVersion))
		return false
	}
	switch env.Type {
	case TypePing:
		return writeJSON(conn, PingResponse{
			Type:    TypePong,
			Version: ProtocolVersion,
		}) == nil
	case TypeUnlock:
		return s.dispatchUnlock(conn, raw)
	case TypeDecrypt:
		return s.dispatchDecrypt(conn, raw)
	case TypeEncrypt:
		return s.dispatchEncrypt(conn, raw)
	case TypeStatus:
		return s.dispatchStatus(conn)
	case TypeLock:
		s.keys.lock()
		return writeJSON(conn, LockResponse{Type: TypeLockAck, Version: ProtocolVersion}) == nil
	case TypeStop:
		s.dispatchStop(conn)
		return false
	default:
		return writeJSON(conn, ErrorResponse{
			Type:    TypeError,
			Version: ProtocolVersion,
			Code:    ErrCodeUnknownMessageType,
			Message: fmt.Sprintf("type %q not recognized", env.Type),
		}) == nil
	}
}

func (s *Server) dispatchUnlock(conn *net.UnixConn, raw []byte) bool {
	defer secure.SecureZeroBytes(raw)
	var req UnlockRequest
	if err := decodeMessage(raw, &req); err != nil {
		secure.SecureZeroBytes(req.Password)
		sendErrorAndIgnore(conn, ErrCodeBadRequest, err.Error())
		return true
	}
	err := s.keys.Unlock(req.Password, req.Salt, req.Verify, database.Argon2idParams(req.Params))
	if err == nil {
		return writeJSON(conn, UnlockResponse{
			Type:    TypeUnlockAck,
			Version: ProtocolVersion,
		}) == nil
	}
	code := ErrCodeInternal
	switch {
	case errors.Is(err, errWrongPassword):
		code = ErrCodeWrongPassword
	case errors.Is(err, errBadRequest):
		code = ErrCodeBadRequest
	}
	sendErrorAndIgnore(conn, code, err.Error())
	return true
}

func (s *Server) dispatchDecrypt(conn *net.UnixConn, raw []byte) bool {
	var req DecryptRequest
	if err := decodeMessage(raw, &req); err != nil {
		sendErrorAndIgnore(conn, ErrCodeBadRequest, err.Error())
		return true
	}
	plain, err := s.keys.Decrypt(req.Ciphertext, req.Salt, req.UnlockID)
	if err != nil {
		sendErrorAndIgnore(conn, keystoreErrCode(err), err.Error())
		return true
	}
	defer secure.SecureZeroBytes(plain)
	return writeJSON(conn, DecryptResponse{
		Type:      TypeDecryptAck,
		Version:   ProtocolVersion,
		Plaintext: plain,
	}) == nil
}

func (s *Server) dispatchEncrypt(conn *net.UnixConn, raw []byte) bool {
	defer secure.SecureZeroBytes(raw)
	var req EncryptRequest
	if err := decodeMessage(raw, &req); err != nil {
		secure.SecureZeroBytes(req.Plaintext)
		sendErrorAndIgnore(conn, ErrCodeBadRequest, err.Error())
		return true
	}
	defer secure.SecureZeroBytes(req.Plaintext)
	ciphertext, salt, err := s.keys.Encrypt(req.Plaintext, req.UnlockID)
	if err != nil {
		sendErrorAndIgnore(conn, keystoreErrCode(err), err.Error())
		return true
	}
	return writeJSON(conn, EncryptResponse{
		Type:       TypeEncryptAck,
		Version:    ProtocolVersion,
		Ciphertext: ciphertext,
		Salt:       salt,
	}) == nil
}

func (s *Server) dispatchStatus(conn *net.UnixConn) bool {
	st := s.keys.snapshot()
	return writeJSON(conn, StatusResponse{
		Type:             TypeStatusAck,
		Version:          ProtocolVersion,
		Unlocked:         st.unlocked,
		UnlockID:         st.unlockID,
		AgentPID:         os.Getpid(),
		AgentStartedUnix: s.startedAt.Unix(),
		UnlockedAtUnix:   unixOrZero(st.unlockedAt),
		LastActivityUnix: unixOrZero(st.lastActivity),
		LastUnlockUnix:   unixOrZero(st.lastUnlock),
		LocksAtUnix:      unixOrZero(st.locksAt),
		IdleTimeoutSec:   int64(st.idleTimeout / time.Second),
		MaxLifetimeSec:   int64(st.maxLifetime / time.Second),
	}) == nil
}

// dispatchStop acknowledges a stop and then shuts the server down. The
// reply goes first so the client sees success before the socket closes.
func (s *Server) dispatchStop(conn *net.UnixConn) {
	if err := writeJSON(conn, StopResponse{Type: TypeStopAck, Version: ProtocolVersion}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: write stop_ack: %v\n", err) //nolint:errcheck // best-effort warning
	}
	if err := s.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: agent shutdown: %v\n", err) //nolint:errcheck // best-effort warning
	}
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func keystoreErrCode(err error) string {
	switch {
	case errors.Is(err, errNotUnlocked):
		return ErrCodeNotUnlocked
	case errors.Is(err, errDecryptFailed):
		return ErrCodeDecryptFailed
	case errors.Is(err, errUnlockMismatch):
		return ErrCodeUnlockMismatch
	case errors.Is(err, errBadRequest):
		return ErrCodeBadRequest
	default:
		return ErrCodeInternal
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
// protocol error worth reporting. io.ErrUnexpectedEOF is deliberately
// excluded: it means the peer closed mid-frame, which is a protocol
// violation we want to log via the regular error path.
func isCleanDisconnect(err error) bool {
	return errors.Is(err, io.EOF)
}

// readErrCode maps a frame read failure to the code sent back to the
// peer. An oversized frame is the client's fault; anything else is not
// attributable and stays internal.
func readErrCode(err error) string {
	if errors.Is(err, errFrameTooLarge) {
		return ErrCodeBadRequest
	}
	return ErrCodeInternal
}
