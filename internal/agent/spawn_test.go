package agent

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestAgentHelperProcess re-executes the test binary as a foreground
// agent daemon. Activated when SESH_TEST_AGENT_HELPER=1 is in the env;
// otherwise returns immediately so this entry is a no-op in normal
// `go test` runs.
func TestAgentHelperProcess(_ *testing.T) {
	if os.Getenv("SESH_TEST_AGENT_HELPER") != "1" {
		return
	}
	sockPath := os.Getenv("SESH_TEST_AGENT_SOCKET")
	if sockPath == "" {
		os.Exit(2)
	}
	srv, err := Listen(sockPath)
	if err != nil {
		os.Exit(3)
	}
	if err := srv.Run(context.Background()); err != nil {
		os.Exit(4)
	}
	os.Exit(0)
}

// useTestSpawn rewires AgentSpawnCommand + agentLogFile so EnsureAgent
// spawns a helper-process agent under t.TempDir() instead of the user's
// real cache directory. Restores both on test cleanup.
func useTestSpawn(t *testing.T) {
	t.Helper()
	sockPath := os.Getenv("SESH_AUTH_SOCK")
	if sockPath == "" {
		t.Fatal("useTestSpawn requires SESH_AUTH_SOCK")
	}
	origSpawn := AgentSpawnCommand
	origLog := agentLogFile
	logPath := filepath.Join(t.TempDir(), "agent.log")
	AgentSpawnCommand = func(string) (*exec.Cmd, error) {
		cmd := exec.Command(os.Args[0], "-test.run=TestAgentHelperProcess", "-test.v=false") //nolint:gosec // re-execs test binary
		cmd.Env = append(os.Environ(), "SESH_TEST_AGENT_HELPER=1", "SESH_TEST_AGENT_SOCKET="+sockPath)
		return cmd, nil
	}
	agentLogFile = func() (*os.File, error) {
		return os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) //nolint:gosec // path under t.TempDir
	}
	t.Cleanup(func() {
		AgentSpawnCommand = origSpawn
		agentLogFile = origLog
	})
}

// useTempSocketEnv points SESH_AUTH_SOCK at a fresh path under /tmp so
// SocketPath returns it and we don't touch the user's real cache.
func useTempSocketEnv(t *testing.T) string {
	t.Helper()
	sockPath := tempSocketPath(t)
	t.Setenv("SESH_AUTH_SOCK", sockPath)
	return sockPath
}

// killTestSpawnedChildren sends SIGTERM to every child of the current
// process. The helper-agent runs as a child; this reaps them between
// tests so a misbehaving test doesn't leave a daemon answering on the
// next test's socket path.
func killTestSpawnedChildren(t *testing.T) {
	t.Helper()
	out, err := exec.Command("pgrep", "-P", strconv.Itoa(os.Getpid())).Output()
	if err != nil {
		// No children, or pgrep unavailable on this platform.
		return
	}
	for line := range bytes.SplitSeq(out, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		pid, perr := strconv.Atoi(string(line))
		if perr != nil || pid <= 0 {
			continue
		}
		if kerr := syscall.Kill(pid, syscall.SIGTERM); kerr != nil && !errors.Is(kerr, syscall.ESRCH) {
			t.Logf("kill pid %d: %v", pid, kerr)
		}
	}
}

// waitForSocketGone polls until the socket file disappears (or the
// deadline expires). Used after killing the helper agent to confirm it
// shut down cleanly.
func waitForSocketGone(t *testing.T, sockPath string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sockPath); errors.Is(err, os.ErrNotExist) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// cleanupAgent reaps any spawned helper agent for sockPath and waits
// for the socket file to disappear. Defer this in tests that spawn.
func cleanupAgent(t *testing.T, sockPath string) {
	t.Helper()
	killTestSpawnedChildren(t)
	waitForSocketGone(t, sockPath)
}

func TestEnsureAgent_FastPathExisting(t *testing.T) {
	sockPath := useTempSocketEnv(t)
	useTestSpawn(t)

	stop := runServer(t, sockPath)
	defer stop()

	conn, err := EnsureAgent()
	if err != nil {
		t.Fatalf("EnsureAgent: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureAgent_SpawnsWhenMissing(t *testing.T) {
	sockPath := useTempSocketEnv(t)
	useTestSpawn(t)
	defer cleanupAgent(t, sockPath)

	conn, err := EnsureAgent()
	if err != nil {
		t.Fatalf("EnsureAgent: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sockPath); err != nil {
		t.Errorf("agent socket not present after spawn: %v", err)
	}
}

func TestEnsureAgent_StaleSocketRemoved(t *testing.T) {
	sockPath := useTempSocketEnv(t)
	useTestSpawn(t)
	defer cleanupAgent(t, sockPath)

	leftoverSocket(t, sockPath)

	conn, err := EnsureAgent()
	if err != nil {
		t.Fatalf("EnsureAgent: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureAgent_RaceSerializedExactlyOneSpawn(t *testing.T) {
	sockPath := useTempSocketEnv(t)
	useTestSpawn(t)
	defer cleanupAgent(t, sockPath)

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		spawnErr error
	)
	const N = 4
	wg.Add(N)
	for range N {
		go func() {
			defer wg.Done()
			conn, err := EnsureAgent()
			if err != nil {
				mu.Lock()
				if spawnErr == nil {
					spawnErr = err
				}
				mu.Unlock()
				return
			}
			if cerr := conn.Close(); cerr != nil {
				mu.Lock()
				if spawnErr == nil {
					spawnErr = cerr
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if spawnErr != nil {
		t.Fatalf("at least one EnsureAgent failed: %v", spawnErr)
	}
	// All succeeded → only one helper agent bound the socket. If two
	// had won the spawn race, the loser's Listen would have errored
	// with "agent already running," its handshake would have failed,
	// and EnsureAgent would have returned an error.
}

func TestDialExisting_FailsWhenNoAgent(t *testing.T) {
	useTempSocketEnv(t)
	useTestSpawn(t)

	conn, err := DialExisting()
	if err == nil {
		mustClose(t, conn)
		t.Fatal("DialExisting should fail when no agent is running")
	}
}

func discardAgentLog(t *testing.T) {
	t.Helper()
	orig := agentLogFile
	logPath := filepath.Join(t.TempDir(), "agent.log")
	agentLogFile = func() (*os.File, error) {
		return os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) //nolint:gosec // path under t.TempDir
	}
	t.Cleanup(func() { agentLogFile = orig })
}

func TestSpawnAgent_StripsMasterPassword(t *testing.T) {
	const secret = "super-secret-value"
	t.Setenv("SESH_MASTER_PASSWORD", secret)
	t.Setenv("SESH_KEEP_ME", "yes")
	discardAgentLog(t)

	out := filepath.Join(t.TempDir(), "env.txt")
	orig := AgentSpawnCommand
	AgentSpawnCommand = func(sockPath string) (*exec.Cmd, error) {
		cmd, err := orig(sockPath)
		if err != nil {
			return nil, err
		}
		// Keep Env nil so spawnAgent's environment is what the child sees.
		cmd.Path = "/bin/sh"
		cmd.Args = []string{"sh", "-c", `pwd > "$1"; echo --- >> "$1"; env >> "$1"`, "sh", out}
		return cmd, nil
	}
	t.Cleanup(func() { AgentSpawnCommand = orig })

	child, err := spawnAgent(tempSocketPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := child.cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(body, []byte("/\n")) {
		t.Fatalf("child cwd = %q, want /", firstLine(body))
	}
	if bytes.Contains(body, []byte("SESH_MASTER_PASSWORD=")) || bytes.Contains(body, []byte(secret)) {
		t.Fatal("spawned environment still contains SESH_MASTER_PASSWORD")
	}
	if !bytes.Contains(body, []byte("SESH_KEEP_ME=yes")) {
		t.Fatal("spawned environment dropped an unrelated variable")
	}
}

func firstLine(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func TestEnsureAgent_VersionMismatchDoesNotSpawn(t *testing.T) {
	const pid = 424242
	sockPath := startFakeAgent(t, func(t *testing.T, rw *bufio.ReadWriter) {
		consumeClientHello(t, rw)
		reply(t, rw, HelloResponse{Type: TypeHelloAck, Version: 99, AgentPID: pid})
	})
	t.Setenv("SESH_AUTH_SOCK", sockPath)

	spawned := false
	orig := AgentSpawnCommand
	AgentSpawnCommand = func(string) (*exec.Cmd, error) {
		spawned = true
		return nil, errors.New("should not spawn")
	}
	t.Cleanup(func() { AgentSpawnCommand = orig })

	_, err := EnsureAgent()
	if err == nil {
		t.Fatal("EnsureAgent succeeded against a mismatched agent")
	}
	if !errors.Is(err, errProtocolMismatch) {
		t.Fatalf("err = %v, want protocol mismatch", err)
	}
	if !strings.Contains(err.Error(), strconv.Itoa(pid)) {
		t.Fatalf("err = %v, want the old agent pid", err)
	}
	if spawned {
		t.Fatal("EnsureAgent spawned a replacement")
	}
	if _, statErr := os.Stat(sockPath); statErr != nil {
		t.Fatalf("socket removed: %v", statErr)
	}
}

func TestEnsureAgent_ChildExitStopsPoll(t *testing.T) {
	useTempSocketEnv(t)
	discardAgentLog(t)
	orig := AgentSpawnCommand
	AgentSpawnCommand = func(string) (*exec.Cmd, error) {
		return exec.Command("/bin/sh", "-c", "exit 1"), nil
	}
	t.Cleanup(func() { AgentSpawnCommand = orig })

	start := time.Now()
	_, err := EnsureAgent()
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("EnsureAgent succeeded after the child exited")
	}
	if !strings.Contains(err.Error(), "exited") {
		t.Fatalf("err = %v, want child-exit", err)
	}
	if elapsed >= time.Second {
		t.Fatalf("EnsureAgent waited %s after the child exited", elapsed)
	}
}

func TestSpawnAgent_FiltersHookEnvironment(t *testing.T) {
	discardAgentLog(t)
	out := filepath.Join(t.TempDir(), "env.txt")
	dir := t.TempDir()
	orig := AgentSpawnCommand
	AgentSpawnCommand = func(string) (*exec.Cmd, error) {
		cmd := exec.Command("sh", "-c", `pwd > "$1"; echo --- >> "$1"; env >> "$1"`, "sh", out)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "SESH_HOOK_VAR=kept", "SESH_MASTER_PASSWORD=from-hook"}
		cmd.Dir = dir
		return cmd, nil
	}
	t.Cleanup(func() { AgentSpawnCommand = orig })

	child, err := spawnAgent(tempSocketPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := child.cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	wantDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := firstLine(body); got != wantDir {
		t.Fatalf("child cwd = %q, want the hook's %q", got, wantDir)
	}
	if !bytes.Contains(body, []byte("SESH_HOOK_VAR=kept")) {
		t.Fatal("spawnAgent dropped the hook's environment")
	}
	if bytes.Contains(body, []byte("SESH_MASTER_PASSWORD=")) {
		t.Fatal("spawnAgent kept SESH_MASTER_PASSWORD from the hook's environment")
	}
}

func TestEnsureAgent_ExitReportsAgentLog(t *testing.T) {
	useTempSocketEnv(t)
	logPath := filepath.Join(t.TempDir(), "agent.log")
	if err := os.WriteFile(logPath, []byte("stale line from an earlier run\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	origSpawn, origLog := AgentSpawnCommand, agentLogFile
	t.Cleanup(func() { AgentSpawnCommand, agentLogFile = origSpawn, origLog })
	agentLogFile = func() (*os.File, error) {
		return os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // path under t.TempDir
	}

	AgentSpawnCommand = func(string) (*exec.Cmd, error) {
		return exec.Command("sh", "-c", `echo "harden agent: memlock limit is 0" >&2; exit 1`), nil
	}
	_, err := EnsureAgent()
	if err == nil || !strings.Contains(err.Error(), "agent log: harden agent: memlock limit is 0") {
		t.Fatalf("err = %v, want the agent's own reason", err)
	}

	// A child that writes nothing must not be blamed for earlier lines.
	AgentSpawnCommand = func(string) (*exec.Cmd, error) { return exec.Command("sh", "-c", "exit 1"), nil }
	_, err = EnsureAgent()
	if err == nil || strings.Contains(err.Error(), "agent log:") {
		t.Fatalf("err = %v, want no log line from earlier runs", err)
	}
}
