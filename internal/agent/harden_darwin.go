//go:build darwin

package agent

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// Harden makes the current process's memory harder to read: no core
// dumps, and PT_DENY_ATTACH, which refuses debugger attach for the rest
// of the process's life. Root is not stopped. Call it from the agent
// daemon only; it changes the whole process. Every step is attempted;
// the error joins any that failed.
func Harden() error {
	var attachErr error
	if err := unix.PtraceDenyAttach(); err != nil {
		attachErr = fmt.Errorf("deny debugger attach: %w", err)
	}
	return errors.Join(disableCoreDumps(), attachErr)
}
