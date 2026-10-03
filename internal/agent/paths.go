// Package agent implements the sesh agent daemon and its client protocol.
// The daemon listens on a per-UID Unix socket and serves a versioned
// JSON-over-newline protocol; clients (the sesh CLI) auto-spawn it on
// demand in master password mode, the default.
package agent

import (
	"fmt"
	"os"
	"path/filepath"
)

// SocketPath returns the canonical Unix-socket path that both the daemon
// and its clients use to find each other. Resolves under os.UserCacheDir
// so it's per-user (no cross-user collisions) and ephemeral by convention.
//
// Override via the SESH_AUTH_SOCK env var for containers / multi-instance
// dev setups; most users never touch it.
func SocketPath() (string, error) {
	if override := os.Getenv("SESH_AUTH_SOCK"); override != "" {
		return override, nil
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locate user cache dir: %w", err)
	}
	dir := filepath.Join(cache, "sesh")
	if err := privateDir(dir); err != nil {
		return "", fmt.Errorf("create agent dir %s: %w", dir, err)
	}
	return filepath.Join(dir, "agent.sock"), nil
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
