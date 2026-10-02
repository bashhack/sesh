package agent

import (
	"bytes"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/secure"
)

func lightParams() database.Argon2idParams {
	return database.Argon2idParams{Time: 1, Memory: 8, Threads: 1, KeyLen: 32}
}

func sealVerify(t *testing.T, password string, params database.Argon2idParams) (salt, verify []byte) {
	t.Helper()
	salt = []byte("0123456789abcdef")
	key := database.DeriveKey([]byte(password), salt, params)
	t.Cleanup(func() { secure.SecureZeroBytes(key) })
	blob, err := database.Encrypt(key, []byte(database.VerifyPlaintext))
	if err != nil {
		t.Fatalf("encrypt verify: %v", err)
	}
	return salt, blob
}

func TestKeystore_UnlockAndRoundTrip(t *testing.T) {
	params := lightParams()
	salt, verify := sealVerify(t, "correct-horse", params)
	var ks keystore
	if err := ks.Unlock([]byte("correct-horse"), salt, verify, params); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	unlocked, id, _ := ks.Status()
	if !unlocked {
		t.Fatal("status unlocked = false")
	}
	if id != UnlockID(verify) {
		t.Fatalf("unlock id = %q, want %q", id, UnlockID(verify))
	}

	ct, entrySalt, err := ks.Encrypt([]byte("secret"), id)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := ks.Decrypt(ct, entrySalt, id)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, []byte("secret")) {
		t.Fatalf("plaintext = %q", got)
	}
}

func TestKeystore_WrongPasswordStaysLocked(t *testing.T) {
	params := lightParams()
	salt, verify := sealVerify(t, "correct-horse", params)
	var ks keystore
	err := ks.Unlock([]byte("nope"), salt, verify, params)
	if !errors.Is(err, errWrongPassword) {
		t.Fatalf("Unlock err = %v, want wrong password", err)
	}
	if unlocked, _, _ := ks.Status(); unlocked {
		t.Fatal("wrong password left the keystore unlocked")
	}
}

func TestKeystore_DecryptBeforeUnlock(t *testing.T) {
	var ks keystore
	_, err := ks.Decrypt([]byte("ct"), []byte("salt"), "")
	if !errors.Is(err, errNotUnlocked) {
		t.Fatalf("Decrypt err = %v, want locked", err)
	}
}

func TestKeystore_ReUnlockReplacesKey(t *testing.T) {
	params := lightParams()
	saltA, verifyA := sealVerify(t, "password-a", params)
	var ks keystore
	if err := ks.Unlock([]byte("password-a"), saltA, verifyA, params); err != nil {
		t.Fatal(err)
	}
	ct, entrySalt, err := ks.Encrypt([]byte("secret"), UnlockID(verifyA))
	if err != nil {
		t.Fatal(err)
	}

	saltB, verifyB := sealVerify(t, "password-b", params)
	if err := ks.Unlock([]byte("password-b"), saltB, verifyB, params); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Decrypt(ct, entrySalt, UnlockID(verifyA)); !errors.Is(err, errUnlockMismatch) {
		t.Fatalf("decrypt with the old id err = %v, want unlock mismatch", err)
	}
	if _, err := ks.Decrypt(ct, entrySalt, UnlockID(verifyB)); !errors.Is(err, errDecryptFailed) {
		t.Fatalf("decrypt under the new key err = %v, want decrypt failed", err)
	}
	if _, id, _ := ks.Status(); id != UnlockID(verifyB) {
		t.Fatalf("unlock id = %q, want password-b id", id)
	}
}

func TestKeystore_RejectsShortSalt(t *testing.T) {
	var ks keystore
	err := ks.Unlock([]byte("pw"), []byte("short"), bytes.Repeat([]byte("v"), 28), lightParams())
	if !errors.Is(err, errBadRequest) {
		t.Fatalf("err = %v, want bad request", err)
	}
}

func TestKeystore_RejectsOutOfRangeParams(t *testing.T) {
	params := lightParams()
	params.Memory = 0
	var ks keystore
	err := ks.Unlock([]byte("pw"), bytes.Repeat([]byte("s"), 16), bytes.Repeat([]byte("v"), 28), params)
	if !errors.Is(err, errBadRequest) {
		t.Fatalf("err = %v, want bad request", err)
	}
}

func TestKeystore_ShutdownClearsKeyAndRefusesUnlock(t *testing.T) {
	params := lightParams()
	salt, verify := sealVerify(t, "correct-horse", params)
	var ks keystore
	if err := ks.Unlock([]byte("correct-horse"), salt, verify, params); err != nil {
		t.Fatal(err)
	}
	ks.shutdown()
	if unlocked, _, _ := ks.Status(); unlocked {
		t.Fatal("shutdown left the keystore unlocked")
	}
	orig := deriveKey
	t.Cleanup(func() { deriveKey = orig })
	deriveKey = func(password, salt []byte, p database.Argon2idParams) []byte {
		t.Error("Unlock ran Argon2id after shutdown")
		return orig(password, salt, p)
	}
	if _, err := ks.Decrypt([]byte("ct"), []byte("0123456789abcdef"), UnlockID(verify)); !errors.Is(err, errNotUnlocked) {
		t.Fatalf("Decrypt after shutdown err = %v, want locked", err)
	}
	if err := ks.Unlock([]byte("correct-horse"), salt, verify, params); !errors.Is(err, errShutDown) {
		t.Fatalf("Unlock after shutdown err = %v, want errShutDown", err)
	}
}

func TestKeystore_ConcurrentUnlocksLeaveOneKey(t *testing.T) {
	params := lightParams()
	saltA, verifyA := sealVerify(t, "password-a", params)
	saltB, verifyB := sealVerify(t, "password-b", params)
	var ks keystore

	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := ks.Unlock([]byte("password-a"), saltA, verifyA, params); err != nil {
			errCh <- err
		}
	}()
	go func() {
		defer wg.Done()
		if err := ks.Unlock([]byte("password-b"), saltB, verifyB, params); err != nil {
			errCh <- err
		}
	}()
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	unlocked, id, _ := ks.Status()
	if !unlocked {
		t.Fatal("concurrent unlocks left the keystore locked")
	}
	if id != UnlockID(verifyA) && id != UnlockID(verifyB) {
		t.Fatalf("unlock id = %q, want one of the two passwords", id)
	}
	ct, entrySalt, err := ks.Encrypt([]byte("secret"), id)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ks.Decrypt(ct, entrySalt, id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("secret")) {
		t.Fatalf("plaintext = %q", got)
	}
}

func TestKeystore_UnlocksDeriveOneAtATime(t *testing.T) {
	var mu sync.Mutex
	var inFlight, peak int
	orig := deriveKey
	t.Cleanup(func() { deriveKey = orig })
	deriveKey = func(password, salt []byte, p database.Argon2idParams) []byte {
		mu.Lock()
		inFlight++
		peak = max(peak, inFlight)
		mu.Unlock()
		// Hold the derivation open long enough for the others to overlap
		// if nothing serializes them.
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		inFlight--
		mu.Unlock()
		return orig(password, salt, p)
	}

	params := lightParams()
	salt, verify := sealVerify(t, "correct-horse", params)
	var ks keystore
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			if err := ks.Unlock([]byte("correct-horse"), salt, verify, params); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if peak != 1 {
		t.Fatalf("peak concurrent derivations = %d, want 1", peak)
	}
}

func TestKeystore_ShutdownDuringUnlockDiscardsKey(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	orig := deriveKey
	t.Cleanup(func() { deriveKey = orig })
	deriveKey = func(password, salt []byte, p database.Argon2idParams) []byte {
		close(entered)
		<-release
		return orig(password, salt, p)
	}

	params := lightParams()
	salt, verify := sealVerify(t, "correct-horse", params)
	var ks keystore
	done := make(chan error, 1)
	go func() { done <- ks.Unlock([]byte("correct-horse"), salt, verify, params) }()

	<-entered
	ks.shutdown() // must not wait for the derivation
	close(release)
	if err := <-done; !errors.Is(err, errShutDown) {
		t.Fatalf("Unlock err = %v, want errShutDown", err)
	}
	if unlocked, _, _ := ks.Status(); unlocked {
		t.Fatal("an unlock that finished after shutdown installed its key")
	}
}

// fakeClock fires timers only when the test calls advance. With
// stopIgnored set, Stop reports success but the timer still fires, which
// is how a timer already running its callback behaves.
type fakeClock struct {
	now         time.Time
	timers      []*fakeTimer
	mu          sync.Mutex
	stopIgnored bool
}

type fakeTimer struct {
	at      time.Time
	f       func()
	clk     *fakeClock
	stopped bool
	fired   bool
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 5, 3, 9, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) AfterFunc(d time.Duration, f func()) stopper {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{at: c.now.Add(d), f: f, clk: c}
	c.timers = append(c.timers, t)
	return t
}

func (t *fakeTimer) Stop() bool {
	t.clk.mu.Lock()
	defer t.clk.mu.Unlock()
	if !t.clk.stopIgnored {
		t.stopped = true
	}
	return true
}

// advance moves the clock forward and runs every timer that came due,
// in deadline order, outside the clock's lock.
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var due []*fakeTimer
	for _, t := range c.timers {
		if !t.stopped && !t.fired && !t.at.After(c.now) {
			t.fired = true
			due = append(due, t)
		}
	}
	c.mu.Unlock()
	slices.SortFunc(due, func(a, b *fakeTimer) int { return a.at.Compare(b.at) })
	for _, t := range due {
		t.f()
	}
}

func timedKeystore(t *testing.T, idle, maxLife time.Duration) (*keystore, *fakeClock, []byte) {
	t.Helper()
	clk := newFakeClock()
	ks := &keystore{clk: clk, idleTimeout: idle, maxLifetime: maxLife}
	params := lightParams()
	salt, verify := sealVerify(t, "correct-horse", params)
	if err := ks.Unlock([]byte("correct-horse"), salt, verify, params); err != nil {
		t.Fatal(err)
	}
	return ks, clk, verify
}

func isUnlocked(ks *keystore) bool {
	unlocked, _, _ := ks.Status()
	return unlocked
}

func TestKeystore_IdleTimeoutLocksAfterInactivity(t *testing.T) {
	ks, clk, _ := timedKeystore(t, 10*time.Minute, 0)
	clk.advance(10*time.Minute - time.Second)
	if !isUnlocked(ks) {
		t.Fatal("locked before the idle timeout")
	}
	clk.advance(time.Second)
	if isUnlocked(ks) {
		t.Fatal("still unlocked after the idle timeout")
	}
}

func TestKeystore_ActivityRestartsIdleTimer(t *testing.T) {
	ks, clk, verify := timedKeystore(t, 10*time.Minute, 0)
	clk.advance(6 * time.Minute)
	if _, _, err := ks.Encrypt([]byte("x"), UnlockID(verify)); err != nil {
		t.Fatal(err)
	}
	clk.advance(6 * time.Minute) // past the original deadline
	if !isUnlocked(ks) {
		t.Fatal("encrypt did not restart the idle timer")
	}
	clk.advance(4 * time.Minute)
	if isUnlocked(ks) {
		t.Fatal("still unlocked 10m after the last activity")
	}
}

func TestKeystore_StatusIsNotActivity(t *testing.T) {
	ks, clk, _ := timedKeystore(t, 10*time.Minute, 0)
	clk.advance(9 * time.Minute)
	ks.snapshot()
	ks.Status()
	clk.advance(time.Minute)
	if isUnlocked(ks) {
		t.Fatal("a status check kept the keystore unlocked")
	}
}

func TestKeystore_MaxLifetimeLocksDespiteActivity(t *testing.T) {
	ks, clk, verify := timedKeystore(t, 10*time.Minute, time.Hour)
	for range 11 {
		clk.advance(5 * time.Minute)
		if _, _, err := ks.Encrypt([]byte("x"), UnlockID(verify)); err != nil {
			t.Fatal(err)
		}
	}
	clk.advance(5 * time.Minute) // 60m since unlock
	if isUnlocked(ks) {
		t.Fatal("still unlocked past the max lifetime")
	}
}

func TestKeystore_ZeroTimeoutsNeverLock(t *testing.T) {
	ks, clk, _ := timedKeystore(t, 0, 0)
	clk.advance(1000 * time.Hour)
	if !isUnlocked(ks) {
		t.Fatal("locked with both timeouts disabled")
	}
	if st := ks.snapshot(); !st.locksAt.IsZero() {
		t.Fatalf("locksAt = %v, want zero with both timeouts disabled", st.locksAt)
	}
}

func TestKeystore_LockCancelsTimersAndAllowsUnlock(t *testing.T) {
	ks, clk, verify := timedKeystore(t, 10*time.Minute, time.Hour)
	ks.lock()
	if isUnlocked(ks) {
		t.Fatal("lock left the keystore unlocked")
	}
	salt, _ := sealVerify(t, "correct-horse", lightParams())
	if err := ks.Unlock([]byte("correct-horse"), salt, verify, lightParams()); err != nil {
		t.Fatalf("Unlock after lock: %v", err)
	}
	if st := ks.snapshot(); st.lastUnlock.IsZero() {
		t.Fatal("lastUnlock not recorded")
	}
	clk.advance(9 * time.Minute)
	if !isUnlocked(ks) {
		t.Fatal("a timer from before the lock fired after the re-unlock")
	}
}

func TestKeystore_StaleTimerDoesNotLockNewUnlock(t *testing.T) {
	ks, clk, verify := timedKeystore(t, 10*time.Minute, 0)
	clk.mu.Lock()
	clk.stopIgnored = true // the first unlock's timer fires regardless
	clk.mu.Unlock()
	clk.advance(5 * time.Minute)
	salt, _ := sealVerify(t, "correct-horse", lightParams())
	if err := ks.Unlock([]byte("correct-horse"), salt, verify, lightParams()); err != nil {
		t.Fatal(err)
	}
	clk.advance(5 * time.Minute) // first unlock's idle deadline
	if !isUnlocked(ks) {
		t.Fatal("the first unlock's timer locked the second unlock's key")
	}
}

func TestKeystore_LocksAtIsEarlierDeadline(t *testing.T) {
	ks, clk, _ := timedKeystore(t, 10*time.Minute, 15*time.Minute)
	start := clk.Now()
	if got := ks.snapshot().locksAt; !got.Equal(start.Add(10 * time.Minute)) {
		t.Fatalf("locksAt = %v, want the idle deadline", got)
	}
	clk.advance(8 * time.Minute)
	if _, _, err := ks.Encrypt([]byte("x"), ks.snapshot().unlockID); err != nil {
		t.Fatal(err)
	}
	if got := ks.snapshot().locksAt; !got.Equal(start.Add(15 * time.Minute)) {
		t.Fatalf("locksAt = %v, want the max-lifetime deadline", got)
	}
}

func TestKeystore_ReusesKeyBuffer(t *testing.T) {
	ks := &keystore{keyBuf: make([]byte, 64)}
	page := &ks.keyBuf[0]
	params := lightParams()
	salt, verify := sealVerify(t, "correct-horse", params)
	for range 3 {
		if err := ks.Unlock([]byte("correct-horse"), salt, verify, params); err != nil {
			t.Fatal(err)
		}
		if &ks.derivedKey[0] != page {
			t.Fatal("key was not stored in the preallocated buffer")
		}
		ks.lock()
	}
	if &ks.keyBuf[0] != page {
		t.Fatal("preallocated buffer was replaced")
	}
	for _, b := range ks.keyBuf {
		if b != 0 {
			t.Fatal("key buffer not zeroed after lock")
		}
	}
}

func TestKeystore_ActivityAtIdleDeadlineKeepsKey(t *testing.T) {
	ks, clk, verify := timedKeystore(t, 10*time.Minute, 0)
	clk.mu.Lock()
	clk.stopIgnored = true // the old idle timer is already running when activity restarts it
	clk.mu.Unlock()
	clk.advance(10*time.Minute - time.Second)
	if _, _, err := ks.Encrypt([]byte("x"), UnlockID(verify)); err != nil {
		t.Fatal(err)
	}
	clk.advance(time.Second) // the old deadline passes; the new one is 10m away
	if !isUnlocked(ks) {
		t.Fatal("the old idle timer locked the key right after fresh activity")
	}
}
