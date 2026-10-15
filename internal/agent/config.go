package agent

import (
	"io"
	"time"
)

// Default auto-lock timeouts. Either can be disabled with 0.
const (
	DefaultIdleTimeout = 10 * time.Minute
	DefaultMaxLifetime = 8 * time.Hour
)

// Option configures a Server.
type Option func(*Server)

// WithIdleTimeout locks the agent after d without an unlock, encrypt, or
// decrypt. 0 disables the idle timeout.
func WithIdleTimeout(d time.Duration) Option {
	return func(s *Server) { s.keys.idleTimeout = d }
}

// WithMaxLifetime locks the agent d after each unlock, however busy it
// is. 0 disables the limit.
func WithMaxLifetime(d time.Duration) Option {
	return func(s *Server) { s.keys.maxLifetime = d }
}

// WithLockOnSleep locks the agent once the computer has slept, as soon as
// it wakes: on its next request, or its sweep.
func WithLockOnSleep() Option {
	return func(s *Server) { s.keys.lockOnSleep = true }
}

// WithScreenLock locks the agent whenever locked says the computer's
// screen is locked, which it asks every couple of seconds.
func WithScreenLock(locked func() bool) Option {
	return func(s *Server) { s.screenLocked = locked }
}

// withScreenEvery sets how often the server asks whether the screen is
// locked. Tests only.
func withScreenEvery(d time.Duration) Option {
	return func(s *Server) { s.screenEvery = d }
}

// WithExitOnAutoLock makes the agent shut down instead of staying locked
// when the idle timeout or max lifetime locks it, and when no unlock
// arrives within the idle timeout of starting. A locked agent has nothing
// to serve, and a new one starts on the next command, so exiting costs
// nothing and stops an agent outliving the sesh build that started it.
// An explicit lock (lock request or SIGUSR1) still leaves it running.
func WithExitOnAutoLock() Option {
	return func(s *Server) { s.exitOnAutoLock = true }
}

// withLogOutput sends the agent log to w instead of stderr. Tests only.
func withLogOutput(w io.Writer) Option {
	return func(s *Server) { s.logOut = w }
}

// withSweepEvery sets how often the server checks its key's deadlines by
// the wall clock. Tests only.
func withSweepEvery(d time.Duration) Option {
	return func(s *Server) { s.sweepEvery = d }
}

// withClock replaces the keystore's time source. Tests only.
func withClock(c clock) Option {
	return func(s *Server) { s.keys.clk = c }
}

// WithLockedKeyMemory makes Listen reserve the key's storage up front: one
// page outside the Go heap, locked into RAM so the key is never written
// to swap, reused for the agent's lifetime. Listen fails if the page
// can't be mapped and locked.
func WithLockedKeyMemory() Option {
	return func(s *Server) { s.lockKeyMemory = true }
}

// lockedPage returns the page WithLockedKeyMemory reserves. Tests replace
// it to simulate failure.
var lockedPage = mapLockedPage
