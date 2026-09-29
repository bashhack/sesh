// Package agent implements the sesh-agent daemon and its client protocol.
// The daemon listens on a per-UID Unix socket and serves a versioned
// JSON-over-newline protocol; clients (the sesh CLI) auto-spawn it on
// demand when SESH_KEY_SOURCE=password is in use.
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
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create agent dir %s: %w", dir, err)
	}
	return filepath.Join(dir, "agent.sock"), nil
}

// LogPath returns the file the auto-spawned agent's stderr is redirected
// to. Kept separate from the socket path: socket lives in cache dir
// (ephemeral, OS may clean), logs live in a state dir (persistent across
// reboots so post-mortem debugging works).
func LogPath() (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locate user cache dir: %w", err)
	}
	// macOS conventions put logs under ~/Library/Logs/sesh; Linux's XDG
	// state dir is the analog. os.UserCacheDir() returns paths under
	// ~/Library/Caches on macOS and $XDG_CACHE_HOME on Linux — using
	// a sibling "logs" directory under the same parent keeps platform
	// branching out of this function while still landing in a sensible
	// location on each.
	dir := filepath.Join(cache, "sesh", "logs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create agent log dir %s: %w", dir, err)
	}
	return filepath.Join(dir, "agent.log"), nil
}
