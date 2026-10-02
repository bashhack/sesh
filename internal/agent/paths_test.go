package agent

import (
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
	home := t.TempDir()
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
