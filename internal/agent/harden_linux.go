//go:build linux

package agent

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// Harden makes the current process's memory harder to read: no core
// dumps, and not dumpable, which also stops processes of the same user
// from attaching with ptrace or reading /proc/<pid>/mem. Root is not
// stopped. Call it from the agent daemon only; it changes the whole
// process. Every step is attempted; the error joins any that failed.
func Harden() error {
	var dumpErr error
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		dumpErr = fmt.Errorf("mark process not dumpable: %w", err)
	}
	return errors.Join(disableCoreDumps(), dumpErr)
}
