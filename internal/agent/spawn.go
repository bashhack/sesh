package agent

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// dialTimeout caps each individual connect attempt. Connecting to a
// local Unix socket is fast (single-digit milliseconds even loaded);
// 500ms is generous without being a hang.
const dialTimeout = 500 * time.Millisecond

// helloTimeout bounds the hello exchange after the dial succeeds.
// dialTimeout covers only the connect; a peer that accepts and never
// replies has to fail here instead of hanging the caller.
var helloTimeout = 2 * time.Second

// requestTimeout bounds one agent round trip other than unlock.
var requestTimeout = 5 * time.Second

// unlockTimeout bounds an unlock round trip. Argon2id may allocate up
// to 1 GiB, so this is longer than requestTimeout.
var unlockTimeout = 2 * time.Minute

// errProtocolMismatch means the agent answered hello with a different
// protocol version. That process still owns the socket.
var errProtocolMismatch = errors.New("agent protocol mismatch")

// spawnPollInterval is how often EnsureAgent re-tries connecting after
// it has launched a daemon, waiting for the socket to appear.
const spawnPollInterval = 20 * time.Millisecond

// spawnTimeout bounds how long EnsureAgent waits for a freshly spawned
// agent to bind its socket and answer hello.
const spawnTimeout = 3 * time.Second

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
func EnsureAgent() (*Conn, error) {
	sockPath, err := SocketPath()
	if err != nil {
		return nil, err
	}

	// Fast path: agent already running and answering. A live agent that
	// fails the handshake (version mismatch, timeout, permission) is
	// returned as-is — replacing it would orphan the process that still
	// holds the key.
	conn, err := dialAndHandshake(sockPath)
	if err == nil {
		return conn, nil
	}
	if !IsNotRunning(err) {
		return nil, err
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
	conn, err = dialAndHandshake(sockPath)
	if err == nil {
		return conn, nil
	}
	if !IsNotRunning(err) {
		return nil, err
	}
	// ECONNREFUSED means the inode is left over from a dead listener.
	// ENOENT means there is nothing to remove. Anything else was
	// rejected above.
	if errors.Is(err, syscall.ECONNREFUSED) {
		if rerr := os.Remove(sockPath); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			return nil, fmt.Errorf("remove stale socket: %w", rerr)
		}
	}

	child, err := spawnAgent(sockPath)
	if err != nil {
		return nil, fmt.Errorf("spawn agent: %w", err)
	}
	exited := make(chan error, 1)
	go func() {
		// Reap the child. A live agent blocks here until it exits; an
		// immediate exit unblocks the poll below.
		exited <- child.cmd.Wait()
	}()

	// Poll for the socket. The agent typically binds within ~50ms on a
	// warm machine; spawnTimeout caps the patience, and a child that
	// exits ends the wait immediately.
	deadline := time.NewTimer(spawnTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(spawnPollInterval)
	defer tick.Stop()
	for {
		conn, derr := dialAndHandshake(sockPath)
		if derr == nil {
			return conn, nil
		}
		if !IsNotRunning(derr) {
			return nil, derr
		}
		select {
		case werr := <-exited:
			return nil, errAgentExited(sockPath, werr, child)
		case <-deadline.C:
			return nil, fmt.Errorf("agent did not bind socket within %s", spawnTimeout)
		case <-tick.C:
		}
	}
}

// errAgentExited reports a spawned agent that exited before binding,
// with the last line it wrote to the agent log (an agent that refuses to
// start says why there).
func errAgentExited(sockPath string, werr error, child *spawnedAgent) error {
	err := fmt.Errorf("spawned agent exited before binding %s", sockPath)
	if werr != nil {
		err = fmt.Errorf("spawned agent exited before binding %s: %w", sockPath, werr)
	}
	if line := lastLogLine(child.logPath, child.logStart); line != "" {
		return fmt.Errorf("%w; agent log: %s", err, line)
	}
	return err
}

// lastLogLine returns the last non-empty line written to path at or after
// offset from, reading at most the final 4 KiB. Earlier runs' lines are
// never returned. Any read error yields "".
func lastLogLine(path string, from int64) string {
	if path == "" {
		return ""
	}
	f, err := os.Open(path) //nolint:gosec // path is the agent log this process opened
	if err != nil {
		return ""
	}
	defer closeOrLog(f, "agent log after read")
	info, err := f.Stat()
	if err != nil {
		return ""
	}
	start := max(from, info.Size()-4096)
	if start >= info.Size() {
		return ""
	}
	buf := make([]byte, info.Size()-start)
	if _, err := f.ReadAt(buf, start); err != nil && !errors.Is(err, io.EOF) {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(string(buf)), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// IsNotRunning reports whether a dial error means no agent owns the
// socket: a refused connect is a stale inode, and a missing path means
// nothing is there. Every other error belongs to a live or unreachable
// agent. EnsureAgent spawns only in the not-running case.
func IsNotRunning(err error) bool {
	return errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED)
}

// DialExisting connects to a running agent without auto-spawning. Used
// by control paths where "no agent" should mean "nothing to do," not
// "start one."
func DialExisting() (*Conn, error) {
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
func dialAndHandshake(sockPath string) (*Conn, error) {
	raw, err := net.DialTimeout("unix", sockPath, dialTimeout)
	if err != nil {
		return nil, err
	}
	conn, ok := raw.(*net.UnixConn)
	if !ok {
		closeOrLog(raw, "non-Unix dial result")
		return nil, fmt.Errorf("dialed connection is not *net.UnixConn (%T)", raw)
	}
	// Refuse an agent run by another user before sending anything: the
	// requests that follow can carry the master password.
	if err := checkPeerCred(conn); err != nil {
		closeOrLog(conn, "agent conn after peer check")
		return nil, fmt.Errorf("refuse agent at %s: %w", sockPath, err)
	}
	if err := conn.SetDeadline(time.Now().Add(helloTimeout)); err != nil {
		closeOrLog(conn, "agent conn after hello deadline")
		return nil, err
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
		var ack HelloResponse
		if err := decodeMessage(raw2, &ack); err != nil {
			closeOrLog(conn, "agent conn after hello_ack decode fail")
			return nil, err
		}
		if ack.Version != ProtocolVersion {
			closeOrLog(conn, "agent conn after version mismatch")
			return nil, fmt.Errorf("%w: agent protocol version %d != client %d (pid %d)",
				errProtocolMismatch, ack.Version, ProtocolVersion, ack.AgentPID)
		}
		if err := conn.SetDeadline(time.Time{}); err != nil {
			closeOrLog(conn, "agent conn after clearing hello deadline")
			return nil, err
		}
		return &Conn{uc: conn, r: r}, nil
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

// spawnedAgent is a started agent process and where its output goes.
// The log is appended to across runs, so logStart marks where this
// child's output begins.
type spawnedAgent struct {
	cmd      *exec.Cmd
	logPath  string
	logStart int64
}

// spawnAgent forks the agent daemon as a detached child process. The
// child never gets SESH_MASTER_PASSWORD, and runs from / unless the
// command sets a directory. Stderr goes to the agent log. Setsid keeps
// the child alive after the parent exits. The caller must Wait on the
// returned command.
func spawnAgent(sockPath string) (*spawnedAgent, error) {
	cmd, err := AgentSpawnCommand(sockPath)
	if err != nil {
		return nil, err
	}

	logFile, err := agentLogFile()
	if err != nil {
		return nil, err
	}
	// Don't close logFile here — the spawned process inherits the fd
	// and will use it for the lifetime of the daemon. Closing in the
	// parent would invalidate the inherited fd on macOS.

	if cmd.Path == "" && len(cmd.Args) > 0 {
		path, lerr := exec.LookPath(cmd.Args[0])
		if lerr != nil {
			closeOrLog(logFile, "agent log file after spawn failure")
			return nil, fmt.Errorf("resolve agent binary: %w", lerr)
		}
		cmd.Path = path
	}
	if cmd.Path != "" && !filepath.IsAbs(cmd.Path) {
		abs, aerr := filepath.Abs(cmd.Path)
		if aerr != nil {
			closeOrLog(logFile, "agent log file after spawn failure")
			return nil, fmt.Errorf("resolve agent binary: %w", aerr)
		}
		cmd.Path = abs
	}
	// The daemon runs from "/" unless the command chose a directory, so it
	// does not pin the CLI's working directory. The password is stripped
	// from whatever environment the child gets so `ps eww` on the
	// long-lived daemon cannot show it.
	if cmd.Dir == "" {
		cmd.Dir = "/"
	}
	cmd.Env = withoutMasterPassword(cmd.Env)
	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid = true

	child := &spawnedAgent{cmd: cmd, logPath: logFile.Name()}
	if info, serr := logFile.Stat(); serr == nil {
		child.logStart = info.Size()
	}
	if err := cmd.Start(); err != nil {
		closeOrLog(logFile, "agent log file after spawn failure")
		return nil, fmt.Errorf("start agent: %w", err)
	}
	// Release the parent's reference; the child still has the inherited
	// fd (dup'd during fork). Without this, the file descriptor leaks
	// until the parent exits.
	closeOrLog(logFile, "agent log file (parent-side fd)")
	return child, nil
}

// withoutMasterPassword returns env minus SESH_MASTER_PASSWORD. A nil env
// means the parent environment, matching exec.Cmd. The daemon is
// long-lived; that value would otherwise stay readable in its process
// environment.
func withoutMasterPassword(env []string) []string {
	const prefix = "SESH_MASTER_PASSWORD="
	src := env
	if src == nil {
		src = os.Environ()
	}
	dst := make([]string, 0, len(src))
	for _, entry := range src {
		if strings.HasPrefix(entry, prefix) {
			continue
		}
		dst = append(dst, entry)
	}
	return dst
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
	// flock(2) is associated with the open file description; closing the
	// last fd referring to it releases the advisory lock. We hold the
	// only reference, so close alone is sufficient.
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
