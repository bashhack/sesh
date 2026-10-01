package agent

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
	"time"
)

// serve starts a server with opts and returns it plus a channel that
// receives Run's result. The server is closed on cleanup.
func serve(t *testing.T, sockPath string, opts ...Option) (*Server, <-chan error) {
	t.Helper()
	srv, err := Listen(sockPath, opts...)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Run(context.Background()) }()
	t.Cleanup(func() {
		if err := srv.Close(); err != nil {
			t.Errorf("close server: %v", err)
		}
	})
	return srv, done
}

func unlockClient(t *testing.T, sockPath string) (*Conn, string) {
	t.Helper()
	params := lightParams()
	salt, verify := sealVerify(t, "correct-horse", params)
	conn := dialClient(t, sockPath)
	if err := Unlock(conn, []byte("correct-horse"), salt, verify, params); err != nil {
		t.Fatal(err)
	}
	return conn, UnlockID(verify)
}

func TestServer_LockDropsKeyAndAllowsUnlock(t *testing.T) {
	sockPath := tempSocketPath(t)
	serve(t, sockPath)
	conn, id := unlockClient(t, sockPath)
	defer mustClose(t, conn)

	if err := Lock(conn); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if err := Lock(conn); err != nil {
		t.Fatalf("Lock while locked: %v", err)
	}
	_, _, err := Encrypt(conn, []byte("x"), id)
	var pe *ProtocolError
	if !errors.As(err, &pe) || pe.Code != ErrCodeNotUnlocked {
		t.Fatalf("Encrypt after lock err = %v, want not_unlocked", err)
	}
	params := lightParams()
	salt, verify := sealVerify(t, "correct-horse", params)
	if err := Unlock(conn, []byte("correct-horse"), salt, verify, params); err != nil {
		t.Fatalf("Unlock after lock: %v", err)
	}
}

func TestServer_StopShutsDown(t *testing.T) {
	sockPath := tempSocketPath(t)
	srv, done := serve(t, sockPath)
	conn, _ := unlockClient(t, sockPath)
	defer mustClose(t, conn)

	if err := Stop(conn); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v after stop, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server still running 2s after stop")
	}
	if _, err := os.Stat(sockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket still present after stop: %v", err)
	}
	if unlocked, _, _ := srv.keys.Status(); unlocked {
		t.Fatal("key still cached after stop")
	}
}

func TestServer_SIGUSR1LocksWithoutStopping(t *testing.T) {
	testSigtermMutex.Lock()
	defer testSigtermMutex.Unlock()

	sockPath := tempSocketPath(t)
	srv, _ := serve(t, sockPath)
	conn, _ := unlockClient(t, sockPath)
	defer mustClose(t, conn)

	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatalf("send SIGUSR1: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if unlocked, _, _ := srv.keys.Status(); !unlocked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("still unlocked 2s after SIGUSR1")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := Status(conn); err != nil {
		t.Fatalf("agent stopped serving after SIGUSR1: %v", err)
	}
}

func TestServer_StatusReportsSchedule(t *testing.T) {
	clk := newFakeClock()
	start := clk.Now()
	sockPath := tempSocketPath(t)
	serve(t, sockPath, withClock(clk), WithIdleTimeout(10*time.Minute), WithMaxLifetime(time.Hour))
	conn, id := unlockClient(t, sockPath)
	defer mustClose(t, conn)

	st, err := Status(conn)
	if err != nil {
		t.Fatal(err)
	}
	want := StatusResponse{
		Type:             TypeStatusAck,
		Version:          ProtocolVersion,
		Unlocked:         true,
		UnlockID:         id,
		AgentPID:         os.Getpid(),
		AgentStartedUnix: start.Unix(),
		UnlockedAtUnix:   start.Unix(),
		LastActivityUnix: start.Unix(),
		LastUnlockUnix:   start.Unix(),
		LocksAtUnix:      start.Add(10 * time.Minute).Unix(),
		IdleTimeoutSec:   600,
		MaxLifetimeSec:   3600,
	}
	if st != want {
		t.Fatalf("status = %+v\nwant     %+v", st, want)
	}

	if err := Lock(conn); err != nil {
		t.Fatal(err)
	}
	st, err = Status(conn)
	if err != nil {
		t.Fatal(err)
	}
	if st.Unlocked || st.LocksAtUnix != 0 || st.UnlockedAtUnix != 0 || st.LastUnlockUnix != start.Unix() {
		t.Fatalf("status after lock = %+v, want locked with last unlock kept", st)
	}
}
