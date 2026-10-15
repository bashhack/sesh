package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/database"
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
	// A device through a link is one too.
	link := filepath.Join(t.TempDir(), "null.enc")
	if err := os.Symlink("/dev/null", link); err != nil {
		t.Fatal(err)
	}
	if _, err := u.Export(link, []byte("export-pass-1234"), false); err == nil || !strings.Contains(err.Error(), "device or pipe") {
		t.Errorf("a device through a link: %v", err)
	}
	// The vault's own files aren't written over, asked or not.
	for _, f := range []string{store.Path(), store.Path() + "-wal"} {
		for _, replace := range []bool{false, true} {
			if _, err := u.Export(f, []byte("export-pass-1234"), replace); err == nil || !strings.Contains(err.Error(), "is the vault itself") {
				t.Errorf("%s, replace %v: %v", f, replace, err)
			}
		}
	}
	if _, err := database.VaultSummary(store.Path()); err != nil {
		t.Fatalf("the vault after: %v", err)
	}
	// The password given is wiped.
	pw := []byte("export-pass-1234")
	if _, err := u.Export(filepath.Join(t.TempDir(), "x.enc"), pw, false); err != nil || string(pw) == "export-pass-1234" {
		t.Errorf("the password after: %q, %v", pw, err)
	}
	if _, err := u.Export("backup.enc", []byte("export-pass-1234"), false); err == nil || !strings.Contains(err.Error(), "isn't a full path") {
		t.Errorf("a relative path: %v", err)
	}
	// Each export read every entry, and the audit log says so: three exports of four.
	if log := mustRun(t, runAudit); strings.Count(log, "  access  ") != 12 {
		t.Errorf("the audit log doesn't record the reads:\n%s", log)
	}
}

// A master password changed by another command while the app has the vault open locks it, rather than exporting.
func TestUI_ExportKeyChanged(t *testing.T) {
	healthVault(t)
	store, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	u := newUIVault(store)
	defer u.Close() //nolint:errcheck // test cleanup
	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, stderr := rekeyTestApp("y\n")
	if err := runRotateMasterPassword(app, rotateTestCfg("health-password-1234", "new-password-5678", "new-password-5678")); err != nil {
		t.Fatalf("rotate: %v\n%s", err, stderr)
	}
	file := filepath.Join(t.TempDir(), "x.enc")
	if _, err := u.Export(file, []byte("export-pass-1234"), false); !errors.Is(err, tui.ErrLocked) {
		t.Errorf("%v", err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("a file was left: %v", err)
	}
}

// The command line's export, set up as main sets it up, refuses the vault's
// own file even with --force, and the vault is left whole.
func TestExport_RefusesTheVault(t *testing.T) {
	healthVault(t)
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	stderr := new(bytes.Buffer)
	app := NewDefaultApp(VersionInfo{}, appSettingsFrom(cfg))
	app.Stdin, app.Stdout, app.Stderr = strings.NewReader(""), new(bytes.Buffer), stderr
	app.Exit = func(int) {}
	run(app, []string{"sesh", "export", "--format", "json", "--file", cfg.DBPath.Value, "--force"})
	if !strings.Contains(stderr.String(), "is the vault itself") {
		t.Errorf("exporting over the vault:\n%s", stderr)
	}
	if _, err := database.VaultSummary(cfg.DBPath.Value); err != nil {
		t.Errorf("the vault after: %v", err)
	}
}
