//go:build linux

package agent

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// readPeerUID returns the connecting peer's UID via SO_PEERCRED. The
// kernel populates this from the credentials present at connect(2) time,
// so a process that re-exec()'d into another UID is reflected here.
func readPeerUID(fd int) (uint32, error) {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, fmt.Errorf("getsockopt SO_PEERCRED: %w", err)
	}
	return cred.Uid, nil
}
