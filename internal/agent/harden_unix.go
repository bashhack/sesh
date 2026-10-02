//go:build linux || darwin

package agent

import (
	"errors"
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

// mapLockedPage maps one anonymous page and locks it into RAM.
func mapLockedPage() ([]byte, error) {
	b, err := unix.Mmap(-1, 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return nil, fmt.Errorf("map key page: %w", err)
	}
	if err := unix.Mlock(b); err != nil {
		lockErr := fmt.Errorf("lock key page in memory: %w", err)
		if uerr := unix.Munmap(b); uerr != nil {
			return nil, errors.Join(lockErr, fmt.Errorf("unmap key page: %w", uerr))
		}
		return nil, lockErr
	}
	return b, nil
}
