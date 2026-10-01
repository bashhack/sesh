//go:build linux || darwin

package agent

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// disableCoreDumps sets the core-file size limit to zero so a crash
// can't write the agent's memory to disk.
func disableCoreDumps() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("disable core dumps: %w", err)
	}
	return nil
}

// WithLockedKeyMemory keeps the cached key in a page outside the Go heap
// that is locked into RAM, so it is never written to swap. The page is
// allocated on the first unlock and reused for the agent's lifetime. If
// the page can't be mapped or locked, the key falls back to the heap and
// a warning is logged.
func WithLockedKeyMemory() Option {
	return func(s *Server) { s.keys.alloc = lockedAlloc }
}

func lockedAlloc(n int) []byte {
	size := max(os.Getpagesize(), n)
	b, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: map locked key page: %v; key stays on the heap\n", err) //nolint:errcheck // best-effort warning
		return make([]byte, n)
	}
	if err := unix.Mlock(b); err != nil {
		fmt.Fprintf(os.Stderr, "warning: lock key page in memory: %v; it may be swapped\n", err) //nolint:errcheck // best-effort warning
	}
	return b[:n]
}
