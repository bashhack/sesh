package exportfile

import (
	"os"
	"path/filepath"
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
