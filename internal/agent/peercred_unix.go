//go:build linux || darwin

package agent

import (
	"fmt"
	"net"
	"os"
)

// checkPeerCred returns nil iff the connection is from the same UID as
// the agent process. Otherwise an error suitable for logging and
// closing the connection.
//
// The socket file is mode 0600, so cross-UID connect attempts should
// already be denied by the filesystem — this check is defense-in-depth
// against permission misconfiguration, bind-mount weirdness, or future
// changes that loosen the directory permissions.
func checkPeerCred(conn *net.UnixConn) error {
	uid, err := peerUID(conn)
	if err != nil {
		return fmt.Errorf("read peer cred: %w", err)
	}
	if uid != uint32(os.Getuid()) { //nolint:gosec // os.Getuid returns int but UIDs are non-negative
		return fmt.Errorf("peer UID %d != agent UID %d", uid, os.Getuid())
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
