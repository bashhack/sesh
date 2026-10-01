package agent

import "time"

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

// withClock replaces the keystore's time source. Tests only.
func withClock(c clock) Option {
	return func(s *Server) { s.keys.clk = c }
}
