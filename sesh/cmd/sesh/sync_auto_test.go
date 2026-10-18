package main

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/tui"
	"github.com/bashhack/sesh/internal/vault"
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
	ddb := syncComputer(t, desktop, "desktop")
	t.Setenv("SESH_MASTER_PASSWORD", "old-password-1")
	out, synced := runAuto(t, "get", "password/a")
	if !strings.Contains(out, "secret-1") || !strings.Contains(synced, "nothing syncs until sesh sync takes it") {
		t.Errorf("desktop get: %q, synced %q", out, synced)
	}
	// Said once a day: not by the next command, again a day later.
	if _, synced := runAuto(t, "trash", "password/a", "--force"); synced != "" {
		t.Errorf("desktop trash: synced %q", synced)
	}
	sqlExec(t, ddb, `UPDATE sync_warned SET at = ?`, time.Now().Add(-25*time.Hour).UTC())
	if _, synced := runAuto(t, "list"); strings.Count(synced, "nothing syncs until") != 1 {
		t.Errorf("desktop list a day later: synced %q", synced)
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
// the vault, again as it closes. A sync with nothing to do isn't logged.
func TestAutoSync_PushesOnlyAChange(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	_, desktop := syncedPair(t, dir, folder, "password/a")
	ddb := syncComputer(t, desktop, "desktop")
	before, logged := autoSyncsRun, syncsLogged(t, ddb)
	runAuto(t, "get", "password/a")
	if n := autoSyncsRun - before; n != 1 {
		t.Errorf("a get synced %d times", n)
	}
	if n := syncsLogged(t, ddb) - logged; n != 0 {
		t.Errorf("a sync with nothing to do was logged %d times", n)
	}
	before, logged = autoSyncsRun, syncsLogged(t, ddb)
	runAuto(t, "trash", "password/a", "--force")
	if n := autoSyncsRun - before; n != 2 {
		t.Errorf("a trash synced %d times", n)
	}
	if n := syncsLogged(t, ddb) - logged; n != 1 {
		t.Errorf("a trash's syncs were logged %d times", n)
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
	if strings.Count(synced, "not a sesh sync file") != 1 || !strings.Contains(synced, "Synced: 1 sent.") {
		t.Errorf("desktop trash: synced %q", synced)
	}
}

// A fork: settled by a command's own sync when this computer's change is
// the one kept, left to sesh sync with a note when the other's is.
func TestAutoSync_Fork(t *testing.T) {
	orig := forkKept
	t.Cleanup(func() { forkKept = orig })
	for _, ours := range []bool{true, false} {
		forkKept = func(string, string) bool { return !ours }
		dir := t.TempDir()
		folder := filepath.Join(dir, "sync")
		laptop, desktop := syncedPair(t, dir, folder, "password/a")
		old, err := os.ReadFile(filepath.Join(folder, "sesh-sync.json"))
		if err != nil {
			t.Fatal(err)
		}
		ldb := syncComputer(t, laptop, "laptop")
		changePassword(t, "old-password-1", "laptop-password-2")
		if err := os.WriteFile(filepath.Join(folder, "sesh-sync.json"), old, 0o600); err != nil {
			t.Fatal(err)
		}
		syncComputer(t, desktop, "desktop")
		changePassword(t, "old-password-1", "desktop-password-3")
		syncComputer(t, laptop, "laptop")
		t.Setenv("SESH_MASTER_PASSWORD", "laptop-password-2")
		_, synced := runAuto(t, "list")
		switch {
		case ours && (!strings.Contains(synced, "this computer's is kept") || folderKeyID(t, folder) != vaultKeyID(t, ldb)):
			t.Errorf("ours kept: synced %q", synced)
		case !ours && (!strings.Contains(synced, "the other's is kept; nothing syncs until sesh sync takes it") || folderKeyID(t, folder) == vaultKeyID(t, ldb)):
			t.Errorf("theirs kept: synced %q", synced)
		}
	}
}

// A sync folder that doesn't answer in time isn't waited for.
func TestAutoSync_FolderStuck(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	_, desktop := syncedPair(t, dir, folder, "password/a")
	syncComputer(t, desktop, "desktop")
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	origRead, origBudget := readDir, autoSyncBudget
	readDir = func(string) ([]os.DirEntry, error) { <-release; return nil, nil }
	autoSyncBudget = 50 * time.Millisecond
	t.Cleanup(func() { readDir, autoSyncBudget = origRead, origBudget })
	before := autoSyncsRun
	_, synced := runAuto(t, "trash", "password/a", "--force")
	if strings.Count(synced, "didn't answer in 50ms") != 1 || autoSyncsRun-before != 1 {
		t.Errorf("trash with the folder stuck: synced %q, %d syncs", synced, autoSyncsRun-before)
	}
	// With the first look still waiting, the next doesn't wait, and says so.
	if _, synced := runAuto(t, "list"); !strings.Contains(synced, "still hasn't answered") {
		t.Errorf("list with the folder stuck: synced %q", synced)
	}
}

// Each problem is said, once a day by its own text: another the same day
// is said too.
func TestAutoSync_SaysEachProblem(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	_, desktop := syncedPair(t, dir, folder, "password/a")
	syncComputer(t, desktop, "desktop")
	for i, name := range []string{"0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210"} {
		bad := filepath.Join(folder, "entries", name+".sesh")
		if err := os.WriteFile(bad, []byte("not a sesh file"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, synced := runAuto(t, "list"); !strings.Contains(synced, name) {
			t.Errorf("problem %d not said: %q", i, synced)
		}
		if err := os.Remove(bad); err != nil {
			t.Fatal(err)
		}
	}
}

// The app syncs as a command does: to take changes, to send its own (only
// when it has one), and now, even with sync.auto off.
func TestUISync(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a")
	syncComputer(t, laptop, "laptop")
	putEntry(t, "password/a", "secret-2")
	if _, err := runSyncOut(t, "", false); err != nil {
		t.Fatal(err)
	}
	syncComputer(t, desktop, "desktop")
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAuditStore(store)
	v := newUIVault(store)
	off := *cfg
	off.SyncAuto.Value = false
	if said, _ := uiSync(&off, v, tui.SyncPull); said != nil {
		t.Errorf("a pull with sync.auto off: %q", said)
	}
	if said, ran := uiSync(cfg, v, tui.SyncPush); said != nil || ran {
		t.Errorf("a push with nothing to send: %q", said)
	}
	if said, ran := uiSync(cfg, v, tui.SyncPull); len(said) != 1 || said[0] != "Synced: 1 taken." || !ran {
		t.Errorf("a pull: %q", said)
	}
	// The app sees what the pull took, on its own connection.
	if changed, err := v.Check(); err != nil || !changed {
		t.Errorf("the app's check after a pull: %v, %v", changed, err)
	}
	if said, _ := uiSync(&off, v, tui.SyncNow); len(said) != 1 || !strings.Contains(said[0], "nothing to do") {
		t.Errorf("sync now with sync.auto off: %q", said)
	}
}

// The app says a warning that hasn't changed once, not on every sync.
func TestUISync_WarnsOnce(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a")
	syncComputer(t, laptop, "laptop")
	changePassword(t, "old-password-1", "new-password-2")
	syncComputer(t, desktop, "desktop")
	t.Setenv("SESH_MASTER_PASSWORD", "old-password-1")
	putEntry(t, "password/b", "b")
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAuditStore(store)
	v := newUIVault(store)
	if said, ran := uiSync(cfg, v, tui.SyncPush); len(said) != 1 || !strings.Contains(said[0], "nothing syncs until") || ran {
		t.Fatalf("the first push: %q, ran %v", said, ran)
	}
	if said, _ := uiSync(cfg, v, tui.SyncPush); len(said) != 0 {
		t.Errorf("the next push: %q", said)
	}
	if said, _ := uiSync(cfg, v, tui.SyncNow); len(said) != 1 {
		t.Errorf("sync now: %q", said)
	}
}

// A folder that doesn't answer is asked once: the app's syncs on their own
// wait a while, and a probe still waiting isn't joined by another.
func TestUISync_FolderStuck(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	_, desktop := syncedPair(t, dir, folder, "password/a")
	syncComputer(t, desktop, "desktop")
	putEntry(t, "password/b", "b")
	// Answering, but too late.
	var reads atomic.Int32
	origRead, origBudget := readDir, autoSyncBudget
	readDir = func(string) ([]os.DirEntry, error) { reads.Add(1); time.Sleep(60 * time.Millisecond); return nil, nil }
	autoSyncBudget = 20 * time.Millisecond
	t.Cleanup(func() { readDir, autoSyncBudget = origRead, origBudget })
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAuditStore(store)
	v := newUIVault(store)
	if said, ran := uiSync(cfg, v, tui.SyncPush); len(said) != 1 || !strings.Contains(said[0], "didn't answer") || ran {
		t.Fatalf("the first push: %q, ran %v", said, ran)
	}
	time.Sleep(100 * time.Millisecond) // the first read ended
	if said, _ := uiSync(cfg, v, tui.SyncPush); said != nil || reads.Load() != 1 {
		t.Errorf("the next push: %q, folder read %d times", said, reads.Load())
	}
	if said, _ := uiSync(cfg, v, tui.SyncNow); len(said) != 1 || reads.Load() != 2 {
		t.Errorf("sync now: %q, folder read %d times", said, reads.Load())
	}
	// One still waiting isn't joined by another, nor said to be waited for.
	if said, _ := uiSync(cfg, v, tui.SyncNow); len(said) != 1 || !strings.Contains(said[0], "still hasn't answered") || reads.Load() != 2 {
		t.Errorf("sync now again: %q, folder read %d times", said, reads.Load())
	}
}

// A save of the app's after a sync that changed nothing isn't taken for
// the sync's change.
func TestUISync_SaveAfterSync(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	_, desktop := syncedPair(t, dir, folder, "password/a")
	syncComputer(t, desktop, "desktop")
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAuditStore(store)
	v := newUIVault(store)
	if _, ran := uiSync(cfg, v, tui.SyncPull); !ran {
		t.Fatal("the pull didn't run")
	}
	k, err := vault.ParseKey("password/c")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.wrote(store.Put(k, []byte("c"))); err != nil {
		t.Fatal(err)
	}
	if changed, err := v.Check(); err != nil || changed {
		t.Errorf("the app's check after its own save: %v, %v", changed, err)
	}
}

// After a pull the app said, another command's write that changes no
// entry isn't a change; nor is the app's own save after another command
// wrote during a sync.
func TestUISync_OthersWritesAroundASync(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a")
	syncComputer(t, laptop, "laptop")
	putEntry(t, "password/a", "secret-2")
	if _, err := runSyncOut(t, "", false); err != nil {
		t.Fatal(err)
	}
	ddb := syncComputer(t, desktop, "desktop")
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAuditStore(store)
	v := newUIVault(store)
	other := func() {
		t.Helper()
		sqlExec(t, ddb, `INSERT INTO audit_log (event_type, detail, created_at) VALUES ('test', 'another command', ?)`, time.Now().UTC())
	}
	if said, _ := uiSync(cfg, v, tui.SyncPull); len(said) != 1 {
		t.Fatalf("the pull: %q", said)
	}
	if changed, err := v.Check(); err != nil || !changed {
		t.Fatalf("after the pull: %v, %v", changed, err)
	}
	other()
	if changed, err := v.Check(); err != nil || changed {
		t.Errorf("another command's write after: %v, %v", changed, err)
	}
	other()
	if _, ran := uiSync(cfg, v, tui.SyncPull); !ran {
		t.Fatal("the second pull didn't run")
	}
	k, err := vault.ParseKey("password/c")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.wrote(store.Put(k, []byte("c"))); err != nil {
		t.Fatal(err)
	}
	if changed, err := v.Check(); err != nil || changed {
		t.Errorf("the app's save after another command wrote: %v, %v", changed, err)
	}
}
