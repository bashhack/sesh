//go:build darwin

package agent

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// readPeerUID returns the connecting peer's UID via LOCAL_PEERCRED. The
// xucred struct's Uid field carries the effective UID of the peer at
// connect(2) time.
func readPeerUID(fd int) (uint32, error) {
	xucred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, fmt.Errorf("getsockopt LOCAL_PEERCRED: %w", err)
	}
	return xucred.Uid, nil
}
