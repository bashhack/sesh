package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/touchid"
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
	_, _, err := Encrypt(conn, []byte("x"), nil, id)
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
	if srv.keys.snapshot().unlocked {
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
	for srv.keys.snapshot().unlocked {
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
		AgentBuild:       Build(),
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

func TestListen_RefusesWithoutLockedKeyMemory(t *testing.T) {
	orig := lockedPage
	t.Cleanup(func() { lockedPage = orig })
	lockedPage = func() ([]byte, error) { return nil, errors.New("memlock limit is 0") }

	sockPath := tempSocketPath(t)
	srv, err := Listen(sockPath, WithLockedKeyMemory())
	if err == nil {
		mustClose(t, srv)
		t.Fatal("Listen succeeded without locked key memory")
	}
	if !strings.Contains(err.Error(), "memlock limit is 0") {
		t.Fatalf("err = %v, want the lock failure", err)
	}
	if _, err := os.Stat(sockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket exists after a refused start: %v", err)
	}
}

func TestListen_KeyLivesInLockedPage(t *testing.T) {
	page := make([]byte, 4096)
	orig := lockedPage
	t.Cleanup(func() { lockedPage = orig })
	lockedPage = func() ([]byte, error) { return page, nil }

	srv, err := Listen(tempSocketPath(t), WithLockedKeyMemory())
	if err != nil {
		t.Fatal(err)
	}
	defer mustClose(t, srv)
	params := lightParams()
	salt, verify := sealVerify(t, "correct-horse", params)
	if err := srv.keys.Unlock([]byte("correct-horse"), salt, verify, params); err != nil {
		t.Fatal(err)
	}
	if &srv.keys.derivedKey[0] != &page[0] {
		t.Fatal("the unlocked key is not in the reserved page")
	}
}

func TestServer_RunReturnsAfterKeyIsZeroed(t *testing.T) {
	// Hold Close between removing the socket and zeroing the key, the
	// window a slow machine can stretch.
	testHookBeforeKeyShutdown = func() { time.Sleep(50 * time.Millisecond) }
	t.Cleanup(func() { testHookBeforeKeyShutdown = nil })

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
	if srv.keys.snapshot().unlocked {
		t.Fatal("Run returned before the key was zeroed")
	}
}

func TestServer_StopRepliesAfterShutdown(t *testing.T) {
	// Slow the key zeroing so a reply sent before shutdown would arrive
	// while the agent is still unlocked and listening.
	testHookBeforeKeyShutdown = func() { time.Sleep(50 * time.Millisecond) }
	t.Cleanup(func() { testHookBeforeKeyShutdown = nil })

	sockPath := tempSocketPath(t)
	srv, _ := serve(t, sockPath)
	conn, _ := unlockClient(t, sockPath)
	defer mustClose(t, conn)

	if err := Stop(conn); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// No waiting: stop_ack must mean the agent is already gone.
	if srv.keys.snapshot().unlocked {
		t.Fatal("stop_ack arrived before the key was zeroed")
	}
	if _, err := os.Stat(sockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stop_ack arrived before the socket was removed: %v", err)
	}
}

func TestServer_StopReportsFailedShutdown(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions, so the socket removal can't be made to fail")
	}
	// Not serve(): its cleanup treats the Close error this test causes as a
	// failure.
	sockPath := tempSocketPath(t)
	srv, err := Listen(sockPath)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Run(context.Background()) }() //nolint:errcheck // shutdown is driven by Stop below
	conn, _ := unlockClient(t, sockPath)
	defer mustClose(t, conn)

	// A read-only directory makes removing the socket file fail.
	dir := filepath.Dir(sockPath)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Errorf("restore dir permissions: %v", err)
		}
	})

	err = Stop(conn)
	var pe *ProtocolError
	if !errors.As(err, &pe) || pe.Code != ErrCodeInternal || !strings.Contains(pe.Message, "remove socket") {
		t.Fatalf("Stop err = %v, want an internal_error naming the failed socket removal", err)
	}
}

// Locked is true once the agent locks, and once its connection is lost,
// as when it stops; not for a secret that doesn't decrypt.
func TestLocked(t *testing.T) {
	sockPath := tempSocketPath(t)
	_, done := serve(t, sockPath)
	conn, id := unlockClient(t, sockPath)
	o := NewOracle(conn, id)
	defer o.Close()
	if _, err := o.DecryptEntry([]byte("not sealed"), make([]byte, 16), nil); err == nil || Locked(err) {
		t.Errorf("a secret that doesn't decrypt: %v, Locked %v", err, Locked(err))
	}
	if Locked(nil) {
		t.Error("Locked(nil)")
	}
	ctl := dialClient(t, sockPath)
	defer mustClose(t, ctl)
	if err := Lock(ctl); err != nil {
		t.Fatal(err)
	}
	if _, err := o.DecryptEntry([]byte("x"), make([]byte, 16), nil); !Locked(err) {
		t.Errorf("after lock: %v, not Locked", err)
	}
	if err := Stop(ctl); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the agent didn't stop")
	}
	for i := range 2 { // the request that loses it, then one on the retired connection
		if _, err := o.DecryptEntry([]byte("x"), make([]byte, 16), nil); !Locked(err) {
			t.Errorf("request %d after stop: %v, not Locked", i+1, err)
		}
	}
}

// An oracle's Check reports the agent locked, without restarting its idle
// timer, and Touch is refused once it's locked.
func TestOracle_CheckAndTouch(t *testing.T) {
	sockPath := tempSocketPath(t)
	serve(t, sockPath)
	conn, id := unlockClient(t, sockPath)
	o := NewOracle(conn, id)
	defer o.Close()
	if err := o.Check(); err != nil {
		t.Fatalf("Check while unlocked: %v", err)
	}
	if err := o.Touch(); err != nil {
		t.Fatalf("Touch while unlocked: %v", err)
	}
	ctl := dialClient(t, sockPath)
	defer mustClose(t, ctl)
	if err := Lock(ctl); err != nil {
		t.Fatal(err)
	}
	if err := o.Check(); !Locked(err) {
		t.Errorf("Check once locked: %v, not Locked", err)
	}
	if err := o.Touch(); !Locked(err) {
		t.Errorf("Touch once locked: %v, not Locked", err)
	}
}

// After the computer sleeps past the idle timeout, the first request finds
// the agent locked, and an unlock on the same connection unlocks it again;
// one that stops when it locks stops when nothing unlocks it within the
// idle timeout, and when its sweep, with no request at all, locks it.
func TestServer_LocksAfterSleep(t *testing.T) {
	t.Run("status, then unlock again", func(t *testing.T) {
		clk := monoClock()
		sockPath := tempSocketPath(t)
		srv, done := serve(t, sockPath, withClock(clk), WithIdleTimeout(10*time.Minute), WithExitOnAutoLock())
		conn, _ := unlockClient(t, sockPath)
		defer mustClose(t, conn)
		clk.sleep(8 * time.Hour)
		if st, err := Status(conn); err != nil || st.Unlocked {
			t.Fatalf("status after the sleep: %+v, %v", st, err)
		}
		params := lightParams()
		salt, verify := sealVerify(t, "correct-horse", params)
		if err := Unlock(conn, []byte("correct-horse"), salt, verify, params); err != nil {
			t.Fatalf("unlock on the same connection after the sleep: %v", err)
		}
		// Unlocked again and in use: the stop it scheduled, due 10 minutes
		// after the late lock, finds it so, and leaves it.
		clk.advance(9 * time.Minute)
		if err := Touch(conn, UnlockID(verify)); err != nil {
			t.Fatal(err)
		}
		clk.advance(2 * time.Minute)
		select {
		case <-done:
			t.Fatal("the agent stopped though it was unlocked again")
		case <-time.After(100 * time.Millisecond):
		}
		if !srv.keys.snapshot().unlocked {
			t.Error("the agent isn't unlocked")
		}
	})
	t.Run("not unlocked again", func(t *testing.T) {
		clk := monoClock()
		sockPath := tempSocketPath(t)
		_, done := serve(t, sockPath, withClock(clk), WithIdleTimeout(10*time.Minute), WithExitOnAutoLock())
		conn, _ := unlockClient(t, sockPath)
		defer mustClose(t, conn)
		clk.sleep(8 * time.Hour)
		if st, err := Status(conn); err != nil || st.Unlocked {
			t.Fatalf("status after the sleep: %+v, %v", st, err)
		}
		clk.advance(10 * time.Minute)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the agent didn't stop, though nothing unlocked it")
		}
	})
	t.Run("sweep", func(t *testing.T) {
		clk := monoClock()
		sockPath := tempSocketPath(t)
		_, done := serve(t, sockPath, withClock(clk), withSweepEvery(20*time.Millisecond), WithIdleTimeout(10*time.Minute), WithExitOnAutoLock())
		conn, _ := unlockClient(t, sockPath)
		defer mustClose(t, conn)
		clk.sleep(8 * time.Hour)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the sweep didn't lock and stop the agent")
		}
	})
}

// After a sleep, an unlock with Touch ID as the first request asks for the
// fingerprint: the key past its deadline isn't taken as unlocked.
func TestTouchIDFirstAfterSleep(t *testing.T) {
	clk := monoClock()
	sockPath := tempSocketPath(t)
	serve(t, sockPath, withClock(clk), WithIdleTimeout(10*time.Minute))
	pub, prompts := softwareChip(t, nil)
	conn, verify, id := unlockForTouchID(t, sockPath)
	defer mustClose(t, conn)
	w, err := WrapKey(conn, id, WrapForTouchID, pub)
	if err != nil {
		t.Fatal(err)
	}
	clk.sleep(8 * time.Hour)
	if err := UnlockTouchID(conn, touchid.NewFile(id, []byte("chip blob"), pub, w), verify); err != nil {
		t.Fatal(err)
	}
	if *prompts != 1 {
		t.Errorf("Touch ID prompts = %d, want 1: the expired key was taken as unlocked", *prompts)
	}
}

// After a late lock, an agent unlocked again and then locked by hand keeps
// running: a lock asked for doesn't stop it, and the stop scheduled at the
// late lock is for that lock only.
func TestServer_ManualLockAfterLateLock(t *testing.T) {
	clk := monoClock()
	sockPath := tempSocketPath(t)
	_, done := serve(t, sockPath, withClock(clk), WithIdleTimeout(10*time.Minute), WithExitOnAutoLock())
	conn, _ := unlockClient(t, sockPath)
	defer mustClose(t, conn)
	clk.sleep(8 * time.Hour)
	if st, err := Status(conn); err != nil || st.Unlocked {
		t.Fatalf("status after the sleep: %+v, %v", st, err)
	}
	params := lightParams()
	salt, verify := sealVerify(t, "correct-horse", params)
	if err := Unlock(conn, []byte("correct-horse"), salt, verify, params); err != nil {
		t.Fatal(err)
	}
	if err := Lock(conn); err != nil {
		t.Fatal(err)
	}
	clk.advance(11 * time.Minute)
	select {
	case <-done:
		t.Fatal("the agent stopped after a lock asked for")
	case <-time.After(100 * time.Millisecond):
	}
}

// With WithLockOnSleep, the first request after the computer slept finds
// the agent locked, though no timeout has passed; a pause awake, or a
// short step of the clock, doesn't lock it. Without it, a short sleep
// leaves it unlocked.
func TestLockOnSleep(t *testing.T) {
	for _, c := range []struct {
		pass   func(clk *fakeClock, check func())
		name   string
		opts   []Option
		locked bool
	}{
		// Small steps of the clock, each seen, don't add up to a sleep.
		{func(clk *fakeClock, check func()) {
			clk.sleep(6 * time.Second)
			check()
			clk.sleep(6 * time.Second)
		}, "the clock stepped 6s twice", []Option{WithLockOnSleep()}, false},
		{func(clk *fakeClock, _ func()) { clk.sleep(30 * time.Second) }, "asleep 30s", []Option{WithLockOnSleep()}, true},
		{func(clk *fakeClock, _ func()) { clk.sleep(2 * time.Second) }, "the clock stepped 2s", []Option{WithLockOnSleep()}, false},
		{func(clk *fakeClock, _ func()) { clk.advance(30 * time.Second) }, "awake 30s", []Option{WithLockOnSleep()}, false},
		{func(clk *fakeClock, _ func()) { clk.sleep(30 * time.Second) }, "asleep 30s, not asked to", nil, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			clk := monoClock()
			sockPath := tempSocketPath(t)
			serve(t, sockPath, append(c.opts, withClock(clk), WithIdleTimeout(10*time.Minute))...)
			conn, id := unlockClient(t, sockPath)
			defer mustClose(t, conn)
			c.pass(clk, func() {
				if _, _, err := Encrypt(conn, []byte("x"), nil, id); err != nil {
					t.Fatalf("between the steps: %v", err)
				}
			})
			_, _, err := Encrypt(conn, []byte("x"), nil, id)
			var pe *ProtocolError
			if locked := errors.As(err, &pe) && pe.Code == ErrCodeNotUnlocked; locked != c.locked {
				t.Errorf("locked = %v (%v), want %v", locked, err, c.locked)
			}
		})
	}
}

// With WithScreenLock, the agent locks while the screen is locked, and
// stays unlocked while it isn't.
func TestLockOnScreenLock(t *testing.T) {
	var screen atomic.Bool
	sockPath := tempSocketPath(t)
	serve(t, sockPath, WithScreenLock(screen.Load), withScreenEvery(10*time.Millisecond))
	conn, id := unlockClient(t, sockPath)
	defer mustClose(t, conn)
	time.Sleep(50 * time.Millisecond)
	if _, _, err := Encrypt(conn, []byte("x"), nil, id); err != nil {
		t.Fatalf("unlocked, screen not locked: %v", err)
	}
	screen.Store(true)
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, _, err := Encrypt(conn, []byte("x"), nil, id)
		var pe *ProtocolError
		if errors.As(err, &pe) && pe.Code == ErrCodeNotUnlocked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the screen locked, the agent didn't: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
