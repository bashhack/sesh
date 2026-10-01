//go:build linux

package agent

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func checkPlatformHardening() error {
	dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil || dumpable != 0 {
		return fmt.Errorf("dumpable = %d, err %v; want 0", dumpable, err)
	}
	return nil
}
