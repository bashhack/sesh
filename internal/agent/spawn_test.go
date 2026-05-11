package agent

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	origSpawn := AgentSpawnCommand
	origLog := agentLogFile
	logPath := filepath.Join(t.TempDir(), "agent.log")
	AgentSpawnCommand = func(sockPath string) (*exec.Cmd, error) {
		cmd := exec.Command(os.Args[0], "-test.run=TestAgentHelperProcess", "-test.v=false") //nolint:gosec // re-execs test binary
		cmd.Env = append(os.Environ(),
			"SESH_TEST_AGENT_HELPER=1",
			"SESH_TEST_AGENT_SOCKET="+sockPath,
		)
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

	if err := os.MkdirAll(filepath.Dir(sockPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sockPath, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}

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
