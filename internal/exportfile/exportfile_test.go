package exportfile

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Only the names for a process's own output are devices by name; any other path is one when it's not a regular file.
func TestIsDevice(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "backup.json")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{
		"/dev/stdout": true, "/dev/stderr": true, "/dev/tty": true, "/dev/fd/1": true, "/proc/self/fd/1": true, "/dev/null": true, fifo: true,
		"/dev/shm/backup.json": false, file: false, dir: false, filepath.Join(dir, "missing.json"): false,
	} {
		if got := IsDevice(path); got != want {
			t.Errorf("IsDevice(%q) = %v", path, got)
		}
	}
}

// The vault's own files are refused, through a link too, even to one not there yet, and a device through a link is a device.
func TestOpenRefusesTheVault(t *testing.T) {
	dir := t.TempDir()
	vault := filepath.Join(dir, "passwords.db")
	if err := os.WriteFile(vault, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "v.enc")
	if err := os.Symlink(vault, link); err != nil {
		t.Fatal(err)
	}
	// A link to a vault file not there yet.
	journal := filepath.Join(t.TempDir(), "j.enc")
	if err := os.Symlink(vault+"-journal", journal); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{vault, vault + "-wal", link, journal} {
		if _, err := Open(p, true, vault); err == nil || !strings.Contains(err.Error(), "is the vault itself") {
			t.Errorf("%s: %v", p, err)
		}
	}
	if f, err := Open(filepath.Join(dir, "other.enc"), false, vault); err != nil || f.Device() {
		t.Errorf("another file: %v", err)
	}
	null := filepath.Join(t.TempDir(), "null")
	if err := os.Symlink("/dev/null", null); err != nil {
		t.Fatal(err)
	}
	if f, err := Open(null, false, vault); err != nil || !f.Device() {
		t.Errorf("a device through a link: %v", err)
	}
}
