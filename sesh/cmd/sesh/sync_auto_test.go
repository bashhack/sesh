package main

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/config"
)

// runAuto runs the sesh command args as sesh would, giving its stdout and
// what its automatic sync said.
func runAuto(t *testing.T, args ...string) (stdout, synced string) {
	t.Helper()
	var said bytes.Buffer
	orig := autoSyncOut
	autoSyncOut = &said
	t.Cleanup(func() { autoSyncOut = orig })
	app := agentTestApp()
	code := -1
	app.Exit = func(c int) { code = c }
	run(app, append([]string{"sesh"}, args...))
	if code > 0 {
		t.Fatalf("sesh %v: exit %d\n%s", args, code, app.Stderr.(*bytes.Buffer).String())
	}
	return app.Stdout.(*bytes.Buffer).String(), said.String()
}

// A command opening the vault takes what changed on another computer
// first; one changing it sends the change after; with nothing new, it
// says nothing.
func TestAutoSync_PullsAndPushes(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a")
	syncComputer(t, laptop, "laptop")
	putEntry(t, "password/a", "secret-2")
	if _, err := runSyncOut(t, "", false); err != nil {
		t.Fatal(err)
	}

	syncComputer(t, desktop, "desktop")
	out, synced := runAuto(t, "get", "password/a")
	if !strings.Contains(out, "secret-2") || !strings.Contains(synced, "Synced: 1 taken.") {
		t.Fatalf("desktop get: %q, synced %q", out, synced)
	}
	if _, synced := runAuto(t, "get", "password/a"); synced != "" {
		t.Errorf("a get with nothing new said: %q", synced)
	}
	if _, synced := runAuto(t, "trash", "password/a", "--force"); !strings.Contains(synced, "Synced: 1 sent.") {
		t.Errorf("desktop trash: synced %q", synced)
	}

	syncComputer(t, laptop, "laptop")
	if _, synced := runAuto(t, "list"); !strings.Contains(synced, "Synced: 1 taken.") {
		t.Errorf("laptop list: synced %q", synced)
	}
}

// sync.auto off: commands sync nothing.
func TestAutoSync_Off(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a")
	syncComputer(t, laptop, "laptop")
	putEntry(t, "password/a", "secret-2")
	if _, err := runSyncOut(t, "", false); err != nil {
		t.Fatal(err)
	}
	syncComputer(t, desktop, "desktop")
	t.Setenv(config.EnvSyncAuto, "false")
	if out, synced := runAuto(t, "get", "password/a"); !strings.Contains(out, "secret-1") || synced != "" {
		t.Errorf("get with sync.auto off: %q, synced %q", out, synced)
	}
}

// A master password changed on another computer isn't taken by a command:
// it works with the vault as it is, and says to run sesh sync.
func TestAutoSync_PasswordChangedElsewhere(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a")
	syncComputer(t, laptop, "laptop")
	changePassword(t, "old-password-1", "new-password-2")
	syncComputer(t, desktop, "desktop")
	t.Setenv("SESH_MASTER_PASSWORD", "old-password-1")
	out, synced := runAuto(t, "get", "password/a")
	if !strings.Contains(out, "secret-1") || !strings.Contains(synced, "nothing syncs until sesh sync takes it") {
		t.Errorf("desktop get: %q, synced %q", out, synced)
	}
	// A command changing the vault says it once, and sends nothing.
	if _, synced := runAuto(t, "trash", "password/a", "--force"); strings.Count(synced, "nothing syncs until") != 1 {
		t.Errorf("desktop trash: synced %q", synced)
	}
}

// syncsLogged is how many syncs the audit log of the vault at db has.
func syncsLogged(t *testing.T, db string) int {
	t.Helper()
	d, err := sql.Open("sqlite", db)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close() //nolint:errcheck // read only
	var n int
	if err := d.QueryRow(`SELECT count(*) FROM audit_log WHERE event_type = 'sync'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A command that changes nothing syncs once, as it opens; one that changes
// the vault, again as it closes.
func TestAutoSync_PushesOnlyAChange(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	_, desktop := syncedPair(t, dir, folder, "password/a")
	ddb := syncComputer(t, desktop, "desktop")
	before := syncsLogged(t, ddb)
	runAuto(t, "get", "password/a")
	if n := syncsLogged(t, ddb) - before; n != 1 {
		t.Errorf("a get synced %d times", n)
	}
	before = syncsLogged(t, ddb)
	runAuto(t, "trash", "password/a", "--force")
	if n := syncsLogged(t, ddb) - before; n != 2 {
		t.Errorf("a trash synced %d times", n)
	}
}

// One name made on two computers: the line names what was renamed, as a
// command naming one may find the other.
func TestAutoSync_NamesARename(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a")
	syncComputer(t, laptop, "laptop")
	putEntry(t, "password/gh", "laptop-secret")
	if _, err := runSyncOut(t, "", false); err != nil {
		t.Fatal(err)
	}
	syncComputer(t, desktop, "desktop")
	putEntry(t, "password/gh", "desktop-secret")
	if _, synced := runAuto(t, "list"); !strings.Contains(synced, "1 renamed, made on two computers under one name (password/gh (2)") {
		t.Errorf("desktop list: synced %q", synced)
	}
}

// A sync folder not there now (a drive not connected) is said by sesh
// sync status, not by every command.
func TestAutoSync_FolderAway(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	_, desktop := syncedPair(t, dir, folder, "password/a")
	syncComputer(t, desktop, "desktop")
	if err := os.Rename(folder, folder+"-away"); err != nil {
		t.Fatal(err)
	}
	if out, synced := runAuto(t, "get", "password/a"); !strings.Contains(out, "secret-1") || synced != "" {
		t.Errorf("get with the folder away: %q, synced %q", out, synced)
	}
}

// A change made offline, then a command with the folder back: the change
// is sent by the command's own sync.
func TestAutoSync_SendsAWaitingChange(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, _ := syncedPair(t, dir, folder, "password/a")
	syncComputer(t, laptop, "laptop")
	if err := os.Rename(folder, folder+"-away"); err != nil {
		t.Fatal(err)
	}
	changePassword(t, "old-password-1", "new-password-2")
	if err := os.Rename(folder+"-away", folder); err != nil {
		t.Fatal(err)
	}
	if _, synced := runAuto(t, "list"); !strings.Contains(synced, "sent this computer's master password change") {
		t.Errorf("laptop list: synced %q", synced)
	}
	if out, err := runSyncOut(t, "", false, "status"); err != nil || strings.Contains(out, "hasn't reached the sync folder yet") {
		t.Errorf("status after: %q, %v", out, err)
	}
}

// A problem in the folder is said once by a command, even one that syncs
// again as it closes.
func TestAutoSync_SaysAProblemOnce(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	_, desktop := syncedPair(t, dir, folder, "password/a")
	syncComputer(t, desktop, "desktop")
	bad := filepath.Join(folder, "entries", "0123456789abcdef0123456789abcdef.sesh")
	if err := os.WriteFile(bad, []byte("not a sesh file"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, synced := runAuto(t, "trash", "password/a", "--force")
	if strings.Count(synced, "problem") != 1 || !strings.Contains(synced, "Synced: 1 sent.") {
		t.Errorf("desktop trash: synced %q", synced)
	}
}
