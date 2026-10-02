//go:build linux || darwin

package agent

import (
	"fmt"
	"net"
	"os"
)

// currentUID is this process's UID. Tests replace it to simulate a peer
// owned by another user.
var currentUID = os.Getuid

// checkPeerCred returns nil iff the process at the other end of conn runs
// as the same UID as this one. Both sides call it: the agent on every
// client, and the CLI on the agent before sending anything, since the
// CLI's requests can carry the master password.
//
// The socket file is mode 0600, so cross-UID connect attempts should
// already be denied by the filesystem — this check is defense-in-depth
// against permission misconfiguration, bind-mount weirdness, or a socket
// path (SESH_AUTH_SOCK) pointing at another user's socket.
func checkPeerCred(conn *net.UnixConn) error {
	uid, err := peerUID(conn)
	if err != nil {
		return fmt.Errorf("read peer cred: %w", err)
	}
	if want := currentUID(); uid != uint32(want) { //nolint:gosec // UIDs are non-negative
		return fmt.Errorf("peer UID %d is not this process's UID %d", uid, want)
	}
	return nil
}

// peerUID extracts the connecting process's UID from a Unix socket.
// Uses SO_PEERCRED on Linux and LOCAL_PEERCRED on macOS — both surfaced
// by golang.org/x/sys/unix.GetsockoptUcred / GetsockoptXucred.
func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("syscall conn: %w", err)
	}
	var uid uint32
	var cerr error
	ctlErr := raw.Control(func(fd uintptr) {
		uid, cerr = readPeerUID(int(fd))
	})
	if ctlErr != nil {
		return 0, ctlErr
	}
	if cerr != nil {
		return 0, cerr
	}
	return uid, nil
}
