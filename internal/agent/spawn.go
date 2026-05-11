package agent

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// dialTimeout caps each individual connect attempt. Connecting to a
// local Unix socket is fast (single-digit milliseconds even loaded);
// 500ms is generous without being a hang.
const dialTimeout = 500 * time.Millisecond

// spawnPollInterval is how often EnsureAgent re-tries connecting after
// it has launched a daemon, waiting for the socket to appear.
const spawnPollInterval = 20 * time.Millisecond

// SpawnTimeout is the default upper bound on EnsureAgent — the full
// budget for "try existing, take lock, spawn, wait for socket." Exposed
// (capitalized) so tests can override with a shorter value.
const SpawnTimeout = 3 * time.Second

// AgentSpawnCommand returns the exec.Cmd to spawn when EnsureAgent needs
// to launch a daemon. By default invokes `<self> agent --socket <path>`.
// Tests overwrite to point at a helper that runs the agent in-process
// (via test-binary re-exec) and can hand the socket path through env
// vars instead of fighting flag.Parse over an unrecognized --socket.
var AgentSpawnCommand = func(sockPath string) (*exec.Cmd, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locate agent binary: %w", err)
	}
	return exec.Command(self, "agent", "--socket", sockPath), nil //nolint:gosec // self from os.Executable; sockPath validated upstream
}

// agentLogFile is the seam for redirecting the spawned daemon's stderr.
// Production opens the user's cache log file; tests redirect to /dev/null
// or a per-test path so they don't pollute the user's real cache.
var agentLogFile = openAgentLog

// EnsureAgent connects to the agent at the canonical socket path,
// auto-spawning a daemon if no live agent is reachable. Returns a
// connection that has already completed the hello handshake.
//
// The caller owns the returned connection and must Close it.
func EnsureAgent() (*net.UnixConn, error) {
	sockPath, err := SocketPath()
	if err != nil {
		return nil, err
	}

	// Fast path: agent already running and answering.
	if conn, err := dialAndHandshake(sockPath); err == nil {
		return conn, nil
	}

	// Slow path: serialize spawn attempts via a flock on a sibling lock
	// file. Two concurrent EnsureAgent callers race here; the loser
	// re-dials under the lock and short-circuits if the winner spawned
	// a working agent in the meantime.
	lockPath := sockPath + ".spawn.lock"
	lock, err := acquireSpawnLock(lockPath)
	if err != nil {
		return nil, fmt.Errorf("acquire spawn lock: %w", err)
	}
	defer lock.release()

	// Re-check under the lock — another EnsureAgent caller may have
	// already spawned an agent while we waited.
	if conn, err := dialAndHandshake(sockPath); err == nil {
		return conn, nil
	}

	// Remove any stale socket file before spawning so the agent's own
	// Listen() doesn't refuse with "agent already running."
	if _, err := os.Stat(sockPath); err == nil {
		if rerr := os.Remove(sockPath); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			return nil, fmt.Errorf("remove stale socket: %w", rerr)
		}
	}

	if err := spawnAgent(sockPath); err != nil {
		return nil, fmt.Errorf("spawn agent: %w", err)
	}

	// Poll for the socket. The agent typically binds within ~50ms on a
	// warm machine; SpawnTimeout caps the patience.
	deadline := time.Now().Add(SpawnTimeout)
	for time.Now().Before(deadline) {
		if conn, err := dialAndHandshake(sockPath); err == nil {
			return conn, nil
		}
		time.Sleep(spawnPollInterval)
	}
	return nil, fmt.Errorf("agent did not bind socket within %s", SpawnTimeout)
}

// DialExisting connects to a running agent without auto-spawning. Used
// by control paths where "no agent" should mean "nothing to do," not
// "start one."
func DialExisting() (*net.UnixConn, error) {
	sockPath, err := SocketPath()
	if err != nil {
		return nil, err
	}
	return dialAndHandshake(sockPath)
}

// dialAndHandshake opens a connection to sockPath and performs the hello
// handshake. Returns the connection only if the handshake succeeded with
// a matching protocol version; otherwise closes the connection and
// returns an error.
func dialAndHandshake(sockPath string) (*net.UnixConn, error) {
	raw, err := net.DialTimeout("unix", sockPath, dialTimeout)
	if err != nil {
		return nil, err
	}
	conn, ok := raw.(*net.UnixConn)
	if !ok {
		closeOrLog(raw, "non-Unix dial result")
		return nil, fmt.Errorf("dialed connection is not *net.UnixConn (%T)", raw)
	}

	if err := writeJSON(conn, HelloRequest{Type: TypeHello, Version: ProtocolVersion}); err != nil {
		closeOrLog(conn, "agent conn after hello write fail")
		return nil, fmt.Errorf("send hello: %w", err)
	}

	r := bufio.NewReader(conn)
	env, raw2, err := readEnvelope(r)
	if err != nil {
		closeOrLog(conn, "agent conn after hello_ack read fail")
		return nil, fmt.Errorf("read hello_ack: %w", err)
	}
	switch env.Type {
	case TypeHelloAck:
		if env.Version != ProtocolVersion {
			closeOrLog(conn, "agent conn after version mismatch")
			return nil, fmt.Errorf("agent protocol version %d != client %d", env.Version, ProtocolVersion)
		}
		var ack HelloResponse
		if err := decodeMessage(raw2, &ack); err != nil {
			closeOrLog(conn, "agent conn after hello_ack decode fail")
			return nil, err
		}
		return conn, nil
	case TypeError:
		var e ErrorResponse
		if derr := decodeMessage(raw2, &e); derr != nil {
			closeOrLog(conn, "agent conn after error decode fail")
			return nil, fmt.Errorf("agent rejected hello (and error payload undecodable): %w", derr)
		}
		closeOrLog(conn, "agent conn after rejection")
		return nil, fmt.Errorf("agent rejected hello: %s — %s", e.Code, e.Message)
	default:
		closeOrLog(conn, "agent conn after unexpected response")
		return nil, fmt.Errorf("unexpected response type %q to hello", env.Type)
	}
}

// spawnAgent forks the agent daemon as a detached child process. Stderr
// is redirected to a log file so the parent's terminal doesn't get
// noise; the child runs in a new session (Setsid) so it survives the
// parent's exit.
func spawnAgent(sockPath string) error {
	cmd, err := AgentSpawnCommand(sockPath)
	if err != nil {
		return err
	}

	logFile, err := agentLogFile()
	if err != nil {
		return err
	}
	// Don't close logFile here — the spawned process inherits the fd
	// and will use it for the lifetime of the daemon. Closing in the
	// parent would invalidate the inherited fd on macOS.

	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid = true

	if err := cmd.Start(); err != nil {
		closeOrLog(logFile, "agent log file after spawn failure")
		return fmt.Errorf("start agent: %w", err)
	}
	// Release the parent's reference; the child still has the inherited
	// fd (dup'd during fork). Without this, the file descriptor leaks
	// until the parent exits.
	closeOrLog(logFile, "agent log file (parent-side fd)")
	return nil
}

// openAgentLog opens the agent log file for appending. Caller is
// responsible for closing the *os.File when done (or letting it be
// inherited by a spawned process).
func openAgentLog() (*os.File, error) {
	path, err := LogPath()
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) //nolint:gosec // path is <cache>/sesh/logs/agent.log; cache dir is per-user
	if err != nil {
		return nil, fmt.Errorf("open agent log %s: %w", path, err)
	}
	return f, nil
}

// spawnLock is the flock-backed sentinel used to serialize concurrent
// spawn attempts.
type spawnLock struct {
	file *os.File
}

func (l *spawnLock) release() {
	if l.file == nil {
		return
	}
	if err := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN); err != nil {
		fmt.Fprintf(os.Stderr, "warning: release spawn lock: %v\n", err) //nolint:errcheck // best-effort warning
	}
	closeOrLog(l.file, "spawn lock file")
}

// acquireSpawnLock opens the lock file (creating it if needed) and takes
// an exclusive flock. Blocks until acquired.
func acquireSpawnLock(path string) (*spawnLock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create lock dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // path is <cache>/sesh/agent.sock.spawn.lock
	if err != nil {
		return nil, fmt.Errorf("open spawn lock %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		closeOrLog(f, "spawn lock file after flock fail")
		return nil, fmt.Errorf("flock spawn lock: %w", err)
	}
	return &spawnLock{file: f}, nil
}
