package atomicfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passwords.key")
	if err := Write(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path) //nolint:gosec // the test's own temp file
	if err != nil || string(got) != "second" {
		t.Fatalf("contents = %q, %v; want the replacement", got, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("directory holds %d files, want only the written one (no temporary files left)", len(entries))
	}
}

func TestWrite_Fails(t *testing.T) {
	dir := t.TempDir()
	// A directory where the file should go can't be replaced by a rename.
	path := filepath.Join(dir, "taken")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("x"), 0o600); err == nil {
		t.Fatal("expected an error")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".taken.") {
			t.Errorf("temporary file %s left behind after a failure", e.Name())
		}
	}
	if err := Write(filepath.Join(dir, "missing", "f"), []byte("x"), 0o600); err == nil {
		t.Error("expected an error for a missing directory")
	}
}

// A pending file leaves path as it was until committed; abandoned, it leaves nothing behind.
func TestCreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "export.enc")
	if err := os.WriteFile(path, []byte("before"), 0o644); err != nil { //nolint:gosec // test
		t.Fatal(err)
	}
	p, err := Create(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Write([]byte("half")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "before" { //nolint:errcheck,gosec // compared
		t.Errorf("while pending: %q", b)
	}
	p.Abort()
	if entries, _ := os.ReadDir(dir); len(entries) != 1 { //nolint:errcheck // counted
		t.Errorf("after abandoning, %d files", len(entries))
	}
	p, err = Create(path, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Write([]byte("after")); err != nil {
		t.Fatal(err)
	}
	if err := p.Commit(); err != nil {
		t.Fatal(err)
	}
	p.Abort()                                            // does nothing once committed
	if b, _ := os.ReadFile(path); string(b) != "after" { //nolint:errcheck,gosec // compared
		t.Errorf("committed: %q", b)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o640 {
		t.Errorf("mode: %v, %v", info, err)
	}
	if _, err := Create(filepath.Join(dir, "missing", "x"), 0o600); err == nil {
		t.Error("a missing folder made a file")
	}
}
