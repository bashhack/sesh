// Package agent implements the sesh agent daemon and its client protocol.
// The daemon listens on a per-UID Unix socket and serves a versioned
// JSON-over-newline protocol; clients (the sesh CLI) auto-spawn it on
// demand.
package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// SocketPath returns the canonical Unix-socket path that both the daemon
// and its clients use to find each other. Resolves under os.UserCacheDir
// so it's per-user (no cross-user collisions) and ephemeral by convention.
//
// Override via the SESH_AUTH_SOCK env var for containers / multi-instance
// dev setups; most users never touch it. A path longer than a socket
// allows is an error that says so, rather than the system's bare
// "invalid argument" on connect.
func SocketPath() (string, error) {
	if override := os.Getenv("SESH_AUTH_SOCK"); override != "" {
		if n := len(override); n > maxSocketPath() {
			return "", fmt.Errorf("SESH_AUTH_SOCK is %d characters (%s), but a socket path can be at most %d here; set SESH_AUTH_SOCK to a shorter path", n, override, maxSocketPath())
		}
		return override, nil
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locate user cache dir: %w", err)
	}
	dir := filepath.Join(cache, "sesh")
	path := filepath.Join(dir, "agent.sock")
	if n := len(path); n > maxSocketPath() {
		return "", fmt.Errorf("the agent's socket path is %d characters (%s), but a socket path can be at most %d here; set SESH_AUTH_SOCK to a shorter path, in a folder only you can write to", n, path, maxSocketPath())
	}
	if err := privateDir(dir); err != nil {
		return "", fmt.Errorf("create agent dir %s: %w", dir, err)
	}
	return path, nil
}

// LogPath returns the file the auto-spawned agent's stderr is redirected
// to: <user cache dir>/sesh/logs/agent.log (~/Library/Caches on macOS,
// $XDG_CACHE_HOME or ~/.cache on Linux). The OS may clean the cache dir;
// the log is for diagnosing recent runs, not a permanent record.
func LogPath() (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locate user cache dir: %w", err)
	}
	for _, dir := range []string{filepath.Join(cache, "sesh"), filepath.Join(cache, "sesh", "logs")} {
		if err := privateDir(dir); err != nil {
			return "", fmt.Errorf("create agent log dir %s: %w", dir, err)
		}
	}
	return filepath.Join(cache, "sesh", "logs", "agent.log"), nil
}

// privateDir creates dir if needed and makes it accessible to this user
// only, including when it already existed with wider permissions.
func privateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700) //nolint:gosec // a directory needs the execute bit to be entered; 0700 is owner-only
}

// maxSocketPath is the longest path a Unix socket can have here: the
// system's address buffer less the byte that ends the string (103 on
// macOS, 107 on Linux).
func maxSocketPath() int {
	return len(syscall.RawSockaddrUnix{}.Path) - 1
}
