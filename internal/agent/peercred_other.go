//go:build !linux && !darwin

package agent

import (
	"fmt"
	"net"
)

// checkPeerCred is a build-stub for platforms sesh-agent doesn't support.
// The package still compiles on those platforms so callers can import it
// without build-tagging their own files, but any actual use returns an
// error at runtime.
func checkPeerCred(_ *net.UnixConn) error {
	return fmt.Errorf("peer credential check not implemented on this platform")
}
