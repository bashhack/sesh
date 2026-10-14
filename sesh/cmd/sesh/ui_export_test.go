package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/tui"
)

// The app's export is sesh's encrypted export of every entry, written to a file it asks before replacing; a device,
// or a path that isn't a full one, is refused.
func TestUI_Export(t *testing.T) {
	healthVault(t)
	store, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	u := newUIVault(store)
	defer u.Close() //nolint:errcheck // test cleanup
	file := filepath.Join(t.TempDir(), "backup.enc")
	said, err := u.Export(file, []byte("export-pass-1234"), false)
	if err != nil || !strings.HasPrefix(said, "Exported 4 entries to ") {
		t.Fatalf("%q, %v", said, err)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := password.ReadSealed(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if list, err := sealed.Entries([]byte("export-pass-1234")); err != nil || len(list) != 4 {
		t.Errorf("the export: %d entries, %v", len(list), err)
	}
	if info, err := os.Stat(file); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("its mode: %v, %v", info, err)
	}
	if _, err := u.Export(file, []byte("export-pass-1234"), false); !errors.Is(err, tui.ErrExists) {
		t.Errorf("a file there: %v", err)
	}
	if _, err := u.Export(file, []byte("export-pass-1234"), true); err != nil {
		t.Errorf("replacing it: %v", err)
	}
	if _, err := u.Export("/dev/null", []byte("export-pass-1234"), false); err == nil || !strings.Contains(err.Error(), "device or pipe") {
		t.Errorf("a device: %v", err)
	}
	if _, err := u.Export("backup.enc", []byte("export-pass-1234"), false); err == nil || !strings.Contains(err.Error(), "isn't a full path") {
		t.Errorf("a relative path: %v", err)
	}
	// Each export read every entry, and the audit log says so: two exports of four.
	if log := mustRun(t, runAudit); strings.Count(log, "  access  ") != 8 {
		t.Errorf("the audit log doesn't record the reads:\n%s", log)
	}
}
