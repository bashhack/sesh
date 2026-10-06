package main

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// agentTestApp builds an App suitable for runAgent: buffered Stdin/out/err
// and a no-op Exit. The stderr buffer isn't returned because runAgent
// writes to it concurrently with the test goroutine; reading the buffer
// from the test would race.
func agentTestApp() *App {
	return &App{
		Stdin:  bytes.NewReader(nil),
		Stdout: new(bytes.Buffer),
		Stderr: new(bytes.Buffer),
		Exit:   func(int) {},
	}
}

// tempAgentSocket returns a short path suitable for binding (under /tmp
// to stay under macOS's 104-char socket-path limit).
func tempAgentSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ac")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() {
		if rerr := os.RemoveAll(dir); rerr != nil {
			t.Errorf("RemoveAll: %v", rerr)
		}
	})
	return filepath.Join(dir, "s")
}

func TestRunAgent_RejectsUnknownFlag(t *testing.T) {
	app := agentTestApp()
	err := runAgent(app, []string{"--bogus"})
	if err == nil {
		t.Fatal("runAgent should reject unknown flag")
	}
}

// waitForSocketBound polls until the socket accepts a connection. The file
// alone isn't enough: it appears at bind, a moment before listen, and a
// dial in between is refused. Polling avoids reading app.Stderr, which the
// agent is still writing.
func waitForSocketBound(t *testing.T, sockPath string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.DialTimeout("unix", sockPath, 100*time.Millisecond); err == nil {
			if err := conn.Close(); err != nil {
				t.Errorf("close: %v", err)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("socket %q did not accept a connection within 2s", sockPath)
}

func TestRunAgent_BindsAndShutsDownOnSIGTERM(t *testing.T) {
	sockPath := tempAgentSocket(t)
	app := agentTestApp()

	done := make(chan error, 1)
	go func() {
		done <- runAgent(app, []string{"--socket", sockPath})
	}()
	waitForSocketBound(t, sockPath)

	conn, err := net.DialTimeout("unix", sockPath, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Errorf("close: %v", err)
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runAgent returned err = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runAgent didn't exit within 2s of SIGTERM")
	}

	if _, err := os.Stat(sockPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket should be removed after shutdown, stat err = %v", err)
	}
}

func TestRunAgent_DefaultSocketPath(t *testing.T) {
	// SESH_AUTH_SOCK override gives us a deterministic path without
	// needing to peek at SocketPath's logic.
	sockPath := tempAgentSocket(t)
	t.Setenv("SESH_AUTH_SOCK", sockPath)

	app := agentTestApp()
	done := make(chan error, 1)
	go func() {
		done <- runAgent(app, nil) // no --socket flag → uses agent.SocketPath()
	}()
	waitForSocketBound(t, sockPath)

	// A successful dial means Accept is running, which is after Run
	// installs its SIGTERM handler. The socket file appears earlier,
	// between Listen and Run, so signaling on Stat alone can kill the
	// test process.
	conn, err := net.DialTimeout("unix", sockPath, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Errorf("close: %v", err)
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runAgent returned err = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runAgent didn't exit on SIGTERM")
	}

	if _, err := os.Stat(sockPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket should be removed after shutdown, stat err = %v", err)
	}
}
