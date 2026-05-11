package agent

import (
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
