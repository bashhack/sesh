package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSocketPath_HonorsAuthSockOverride(t *testing.T) {
	t.Setenv("SESH_AUTH_SOCK", "/tmp/explicit.sock")
	got, err := SocketPath()
	if err != nil {
		t.Fatalf("SocketPath: %v", err)
	}
	if got != "/tmp/explicit.sock" {
		t.Errorf("SocketPath = %q, want /tmp/explicit.sock", got)
	}
}

func TestSocketPath_DefaultsUnderUserCacheDir(t *testing.T) {
	t.Setenv("SESH_AUTH_SOCK", "")
	got, err := SocketPath()
	if err != nil {
		t.Fatalf("SocketPath: %v", err)
	}
	if !strings.HasSuffix(got, filepath.Join("sesh", "agent.sock")) {
		t.Errorf("SocketPath = %q, want suffix sesh/agent.sock", got)
	}
}

func TestSocketPath_RefusesAPathTooLongForASocket(t *testing.T) {
	limit := maxSocketPath()
	t.Setenv("SESH_AUTH_SOCK", "/"+strings.Repeat("s", limit-1))
	if _, err := SocketPath(); err != nil {
		t.Errorf("SocketPath at the limit (%d characters): %v", limit, err)
	}

	tooLong := "/" + strings.Repeat("s", limit)
	t.Setenv("SESH_AUTH_SOCK", tooLong)
	_, err := SocketPath()
	for _, wantSub := range []string{tooLong, fmt.Sprintf("%d characters", limit+1), fmt.Sprintf("at most %d", limit), "set SESH_AUTH_SOCK to a shorter path"} {
		if err == nil || !strings.Contains(err.Error(), wantSub) {
			t.Errorf("SocketPath with a %d-character SESH_AUTH_SOCK: err = %v, want it to contain %q", limit+1, err, wantSub)
		}
	}

	// The default path is too long when the cache folder is nested deep.
	cache := filepath.Join(t.TempDir(), strings.Repeat("c", limit))
	t.Setenv("HOME", cache)
	t.Setenv("XDG_CACHE_HOME", cache)
	t.Setenv("SESH_AUTH_SOCK", "")
	_, err = SocketPath()
	if wantSub := "set SESH_AUTH_SOCK to a shorter path"; err == nil || !strings.Contains(err.Error(), wantSub) {
		t.Errorf("SocketPath under a deep cache folder: err = %v, want it to contain %q", err, wantSub)
	}
}

func TestLogPath_UnderUserCacheLogsDir(t *testing.T) {
	got, err := LogPath()
	if err != nil {
		t.Fatalf("LogPath: %v", err)
	}
	if !strings.HasSuffix(got, filepath.Join("sesh", "logs", "agent.log")) {
		t.Errorf("LogPath = %q, want suffix sesh/logs/agent.log", got)
	}
}

func TestPaths_TightenExistingDirs(t *testing.T) {
	home := filepath.Dir(tempSocketPath(t)) // short enough for the socket path
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	t.Setenv("SESH_AUTH_SOCK", "")
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	seshDir, logDir := filepath.Join(cache, "sesh"), filepath.Join(cache, "sesh", "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{seshDir, logDir} {
		if err := os.Chmod(d, 0o755); err != nil { //nolint:gosec // deliberately loose, to be tightened
			t.Fatal(err)
		}
	}

	if _, err := SocketPath(); err != nil {
		t.Fatalf("SocketPath: %v", err)
	}
	if _, err := LogPath(); err != nil {
		t.Fatalf("LogPath: %v", err)
	}
	for _, d := range []string{seshDir, logDir} {
		info, err := os.Stat(d)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o700 {
			t.Errorf("%s mode = %o, want 700", d, perm)
		}
	}
}
