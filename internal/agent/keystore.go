package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/secure"
)

// deriveKey is the KDF Unlock runs. Tests replace it to observe how many
// derivations are in flight.
var deriveKey = database.DeriveKey

var (
	errWrongPassword  = errors.New("wrong master password")
	errNotUnlocked    = errors.New("agent is locked")
	errDecryptFailed  = errors.New("decrypt failed")
	errUnlockMismatch = errors.New("unlock mismatch")
	errBadRequest     = errors.New("bad request")
	errShutDown       = errors.New("agent is shutting down")
)

// clock is the time source the keystore schedules auto-locks with.
// Tests substitute one they can advance by hand.
type clock interface {
	Now() time.Time
	AfterFunc(d time.Duration, f func()) stopper
}

type stopper interface{ Stop() bool }

type realClock struct{}

func (realClock) Now() time.Time                              { return time.Now() }
func (realClock) AfterFunc(d time.Duration, f func()) stopper { return time.AfterFunc(d, f) }

// keystore is the only place the derived master key lives in the agent
// process. Methods copy the key out of the lock before doing KDF or
// AES work, then zero the copy.
//
// While unlocked, two timers can lock it again: the idle timer restarts
// on every unlock, encrypt, and decrypt; the max-lifetime timer starts at
// unlock and is never extended. A zero duration disables that timer.
type keystore struct {
	lastActivity time.Time
	unlockedAt   time.Time
	// lastUnlock survives lock so status can report when the key was
	// last installed.
	lastUnlock time.Time
	clk        clock
	log        *agentLog
	// onAutoLock, when set, runs after a timer locks the keystore, outside
	// mu, with the reason ("idle timeout" or "max lifetime").
	onAutoLock func(reason string)
	idleTimer  stopper
	maxTimer   stopper
	// keyBuf is the key's storage, kept for the life of the keystore and
	// reused across unlocks; derivedKey is a view into it while unlocked
	// and nil while locked. The agent daemon preallocates it in locked
	// memory; otherwise it is a heap slice made on first unlock.
	keyBuf      []byte
	unlockID    string
	derivedKey  []byte
	idleTimeout time.Duration
	maxLifetime time.Duration
	// generation increases on every unlock, lock, and shutdown. A timer
	// only acts if the generation it was scheduled under is still current.
	generation uint64
	mu         sync.Mutex
	// shutDown is set by shutdown and guarded by mu. Once set, no key is
	// ever installed again.
	shutDown bool
	// unlockMu is held across derive and install so two unlocks cannot
	// run Argon2id at once or overwrite each other's key.
	unlockMu sync.Mutex
}

// keyState is a point-in-time view of the keystore for status replies.
type keyState struct {
	lastActivity time.Time
	unlockedAt   time.Time
	lastUnlock   time.Time
	// locksAt is the earlier of the two auto-lock deadlines; zero when
	// locked or when both timers are disabled.
	locksAt     time.Time
	unlockID    string
	idleTimeout time.Duration
	maxLifetime time.Duration
	unlocked    bool
}

// Unlock derives a key from password and caches it when the verify blob
// opens. password is zeroed before return. A cached key is zeroed first
// so a re-unlock replaces it completely.
func (k *keystore) Unlock(password, salt, verify []byte, params database.Argon2idParams) error {
	k.unlockMu.Lock()
	defer k.unlockMu.Unlock()
	defer secure.SecureZeroBytes(password)

	if k.isShutDown() {
		return errShutDown
	}

	if err := database.ValidateUnlockMaterial(salt, verify, params); err != nil {
		return fmt.Errorf("%w: %v", errBadRequest, err)
	}

	derived := deriveKey(password, salt, params)
	defer secure.SecureZeroBytes(derived)

	opened, err := database.Decrypt(derived, verify)
	if err != nil || !bytes.Equal(opened, []byte(database.VerifyPlaintext)) {
		secure.SecureZeroBytes(opened)
		return errWrongPassword
	}
	secure.SecureZeroBytes(opened)

	k.mu.Lock()
	defer k.mu.Unlock()
	if k.shutDown {
		return errShutDown
	}
	k.installLocked(derived)
	k.unlockID = UnlockID(verify)
	now := k.clock().Now()
	k.unlockedAt, k.lastActivity, k.lastUnlock = now, now, now
	k.generation++
	k.scheduleLocked()
	// Logged under mu, like every lock, so the log's order is the order
	// the transitions happened in.
	k.log.printf("unlocked")
	return nil
}

func (k *keystore) Decrypt(ciphertext, salt []byte, unlockID string) ([]byte, error) {
	keyCopy, err := k.copyKey(unlockID)
	if err != nil {
		return nil, err
	}
	defer secure.SecureZeroBytes(keyCopy)

	plain, err := database.DecryptEntry(keyCopy, ciphertext, salt)
	if err != nil {
		return nil, errDecryptFailed
	}
	return plain, nil
}

func (k *keystore) Encrypt(plaintext []byte, unlockID string) (ciphertext, salt []byte, err error) {
	keyCopy, err := k.copyKey(unlockID)
	if err != nil {
		return nil, nil, err
	}
	defer secure.SecureZeroBytes(keyCopy)
	return database.EncryptEntry(keyCopy, plaintext)
}

// lock zeroes the cached key and cancels both timers, logging reason. A
// later unlock is allowed. Locking an already-locked keystore changes
// nothing.
func (k *keystore) lock(reason string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.clearLocked()
	k.log.printf("locked (%s)", reason)
}

// shutdown zeroes the cached master key and refuses every later unlock.
// It does not wait for an unlock in progress: that unlock discards its
// key when it finishes.
func (k *keystore) shutdown() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.shutDown = true
	k.clearLocked()
}

func (k *keystore) Status() (unlocked bool, id string, last time.Time) {
	st := k.snapshot()
	return st.unlocked, st.unlockID, st.lastActivity
}

func (k *keystore) snapshot() keyState {
	k.mu.Lock()
	defer k.mu.Unlock()
	st := keyState{
		lastUnlock:  k.lastUnlock,
		idleTimeout: k.idleTimeout,
		maxLifetime: k.maxLifetime,
	}
	if k.derivedKey == nil {
		return st
	}
	st.unlocked = true
	st.unlockID = k.unlockID
	st.lastActivity = k.lastActivity
	st.unlockedAt = k.unlockedAt
	if k.idleTimeout > 0 {
		st.locksAt = k.lastActivity.Add(k.idleTimeout)
	}
	if k.maxLifetime > 0 {
		if maxAt := k.unlockedAt.Add(k.maxLifetime); st.locksAt.IsZero() || maxAt.Before(st.locksAt) {
			st.locksAt = maxAt
		}
	}
	return st
}

func (k *keystore) copyKey(wantID string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	// No cached key is not_unlocked, including when wantID is empty or
	// names a vault this process has never unlocked.
	if k.derivedKey == nil {
		return nil, errNotUnlocked
	}
	if wantID != k.unlockID {
		return nil, errUnlockMismatch
	}
	cp := make([]byte, len(k.derivedKey))
	copy(cp, k.derivedKey)
	k.lastActivity = k.clock().Now()
	k.restartIdleLocked()
	return cp, nil
}

// installLocked copies derived into keyBuf, making a heap buffer if
// none was preallocated (or it is too small). Any previous key is zeroed
// first. Caller holds mu.
func (k *keystore) installLocked(derived []byte) {
	if cap(k.keyBuf) < len(derived) {
		if k.keyBuf != nil {
			secure.SecureZeroBytes(k.keyBuf[:cap(k.keyBuf)])
		}
		k.keyBuf = make([]byte, len(derived))
	}
	secure.SecureZeroBytes(k.keyBuf[:cap(k.keyBuf)])
	k.derivedKey = k.keyBuf[:len(derived)]
	copy(k.derivedKey, derived)
}

// clearLocked zeroes the key, clears unlock state, stops both timers, and
// retires the current generation. keyBuf stays allocated (zeroed) for the
// next unlock. Caller holds mu.
func (k *keystore) clearLocked() {
	if k.keyBuf != nil {
		secure.SecureZeroBytes(k.keyBuf[:cap(k.keyBuf)])
	}
	k.derivedKey = nil
	k.unlockID = ""
	k.lastActivity = time.Time{}
	k.unlockedAt = time.Time{}
	k.stopTimersLocked()
	k.generation++
}

// scheduleLocked starts both timers for the current generation. Caller
// holds mu.
func (k *keystore) scheduleLocked() {
	k.stopTimersLocked()
	gen := k.generation
	if k.idleTimeout > 0 {
		k.idleTimer = k.clock().AfterFunc(k.idleTimeout, func() { k.autoLock(gen, true) })
	}
	if k.maxLifetime > 0 {
		k.maxTimer = k.clock().AfterFunc(k.maxLifetime, func() { k.autoLock(gen, false) })
	}
}

// restartIdleLocked restarts the idle timer from now. The max-lifetime
// timer is left alone. Caller holds mu.
func (k *keystore) restartIdleLocked() {
	if k.idleTimeout <= 0 {
		return
	}
	if k.idleTimer != nil {
		k.idleTimer.Stop()
	}
	gen := k.generation
	k.idleTimer = k.clock().AfterFunc(k.idleTimeout, func() { k.autoLock(gen, true) })
}

func (k *keystore) stopTimersLocked() {
	if k.idleTimer != nil {
		k.idleTimer.Stop()
		k.idleTimer = nil
	}
	if k.maxTimer != nil {
		k.maxTimer.Stop()
		k.maxTimer = nil
	}
}

// autoLock locks the keystore when a timer from generation gen fires,
// unless a later unlock, lock, or shutdown already moved on. An idle
// timer also re-checks the idle deadline: activity restarts the timer,
// but Stop can't cancel a callback that has already started, so a stale
// one may arrive after fresh activity.
func (k *keystore) autoLock(gen uint64, idle bool) {
	k.mu.Lock()
	if gen != k.generation || k.derivedKey == nil {
		k.mu.Unlock()
		return
	}
	reason := "max lifetime"
	if idle {
		if k.clock().Now().Before(k.lastActivity.Add(k.idleTimeout)) {
			k.mu.Unlock()
			return
		}
		reason = "idle timeout"
	}
	k.clearLocked()
	k.log.printf("locked after %s", reason)
	after := k.onAutoLock
	k.mu.Unlock()
	if after != nil {
		after(reason)
	}
}

func (k *keystore) clock() clock {
	if k.clk == nil {
		return realClock{}
	}
	return k.clk
}

// UnlockID is the hex SHA-256 of the verify blob a key was checked
// against. The blob itself is stored on disk, so the id is not a secret.
func UnlockID(verify []byte) string {
	sum := sha256.Sum256(verify)
	return hex.EncodeToString(sum[:])
}

func (k *keystore) isShutDown() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.shutDown
}
