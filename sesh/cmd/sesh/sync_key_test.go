package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/syncfolder"
)

// syncedPair makes a laptop and a desktop syncing through folder, under
// the master password old-password-1, the laptop with entries; it returns
// their homes.
func syncedPair(t *testing.T, dir, folder string, entries ...string) (laptop, desktop string) {
	t.Helper()
	t.Setenv("SESH_MASTER_PASSWORD", "old-password-1")
	laptop, desktop = filepath.Join(dir, "laptop"), filepath.Join(dir, "desktop")
	syncComputer(t, laptop, "laptop")
	for i, e := range entries {
		putEntry(t, e, "secret-"+string(rune('1'+i)))
	}
	if _, err := runSyncOut(t, "", false, "init", folder); err != nil {
		t.Fatal(err)
	}
	syncComputer(t, desktop, "desktop")
	if _, err := runSyncOut(t, "", false, "join", folder); err != nil {
		t.Fatal(err)
	}
	return laptop, desktop
}

// changePassword runs sesh passwd from old to next on the computer whose
// settings are in force.
func changePassword(t *testing.T, old, next string) string {
	t.Helper()
	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, stderr := rekeyTestApp("y\n")
	if err := runRekey(app, nil, rotateTestCfg(old, next, next)); err != nil {
		t.Fatalf("passwd: %v\n%s", err, stderr)
	}
	t.Setenv("SESH_MASTER_PASSWORD", next)
	return stderr.String()
}

func folderKeyID(t *testing.T, folder string) string {
	t.Helper()
	info, err := syncfolder.New(folder).ReadInfo()
	if err != nil {
		t.Fatal(err)
	}
	return database.UnlockID(info.Key.Verify)
}

func vaultKeyID(t *testing.T, db string) string {
	t.Helper()
	m, err := database.ReadUnlockMaterial(db)
	if err != nil {
		t.Fatal(err)
	}
	return database.UnlockID(m.Verify)
}

// A master password changed on the laptop goes to the sync folder, every
// file sealed again with the new key; the desktop, at its next sync, asks
// for it at a terminal (refusing without one), switches to it, and syncs.
func TestSync_PasswordChangeAcrossComputers(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a", "password/b")

	ldb := syncComputer(t, laptop, "laptop")
	said := changePassword(t, "old-password-1", "new-password-2")
	if !strings.Contains(said, "Sent the change to the sync folder") || !strings.Contains(said, "sealing 2 entries' files again") {
		t.Errorf("passwd:\n%s", said)
	}
	if folderKeyID(t, folder) != vaultKeyID(t, ldb) {
		t.Fatal("the folder doesn't have the laptop's new key record")
	}
	putEntry(t, "password/c", "3")
	if _, err := runSyncOut(t, "", false); err != nil {
		t.Fatal(err)
	}

	ddb := syncComputer(t, desktop, "desktop")
	t.Setenv("SESH_MASTER_PASSWORD", "old-password-1")
	if out, err := runSyncOut(t, "", false, "status"); err != nil || !strings.Contains(out, "⚠️  the master password was changed on another computer") {
		t.Errorf("desktop status: %q, %v", out, err)
	}
	if out, err := runSyncOut(t, "", false); err == nil || !strings.Contains(err.Error(), "no terminal here") {
		t.Errorf("desktop sync without a terminal: %q, %v", out, err)
	}
	if got := getEntry(t, "password/a"); got != "secret-1" {
		t.Errorf("the desktop's vault, on its own password meanwhile: %q", got)
	}
	stubTerminalPrompt(t, interactivePrompt(t, "wrong-password", "new-password-2"))
	out, err := runSyncOut(t, "", false)
	if err != nil || !strings.Contains(out, "now opens with the new master password") || !strings.Contains(out, "password/c") {
		t.Fatalf("desktop takes the new password: %q, %v", out, err)
	}
	if vaultKeyID(t, ddb) != folderKeyID(t, folder) {
		t.Error("the desktop's vault isn't on the folder's key record")
	}
	t.Setenv("SESH_MASTER_PASSWORD", "new-password-2")
	if got := getEntry(t, "password/c"); got != "3" {
		t.Errorf("the desktop has c = %q", got)
	}
	if out, err := runSyncOut(t, "", false); err != nil || !strings.Contains(out, "nothing to do") {
		t.Errorf("desktop again: %q, %v", out, err)
	}
	syncComputer(t, laptop, "laptop")
	if out, err := runSyncOut(t, "", false); err != nil || !strings.Contains(out, "nothing to do") {
		t.Errorf("laptop after: %q, %v", out, err)
	}
	for _, f := range scanFolder(t, folder) {
		if f.KeyIDString() != folderKeyID(t, folder) {
			t.Errorf("%s sealed with another key", filepath.Base(f.Path))
		}
	}
}

func scanFolder(t *testing.T, folder string) []syncfolder.File {
	t.Helper()
	c, err := syncfolder.New(folder).Scan()
	if err != nil {
		t.Fatal(err)
	}
	return c.Files
}

// A change made with the folder out of reach waits, and the next sync
// sends it; one waiting when another computer's change reached the folder
// first isn't kept: the other is taken.
func TestSync_PasswordChangeOffline(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a")

	syncComputer(t, laptop, "laptop")
	if err := os.Rename(folder, folder+"-away"); err != nil {
		t.Fatal(err)
	}
	if said := changePassword(t, "old-password-1", "new-password-2"); !strings.Contains(said, "can't be read now") {
		t.Errorf("passwd with the folder away:\n%s", said)
	}
	if err := os.Rename(folder+"-away", folder); err != nil {
		t.Fatal(err)
	}
	if out, err := runSyncOut(t, "", false, "status"); err != nil || !strings.Contains(out, "hasn't reached the sync folder yet") {
		t.Errorf("laptop status: %q, %v", out, err)
	}
	if out, err := runSyncOut(t, "", false); err != nil || !strings.Contains(out, "Sent this computer's master password change") {
		t.Fatalf("laptop sync: %q, %v", out, err)
	}

	// The desktop takes it, then changes it with the folder away; the
	// laptop changes it too, and its change reaches the folder first.
	// Sent later, the laptop no longer had the old key: the folder's files
	// wait for the desktop, which seals them again as it takes the change.
	syncComputer(t, desktop, "desktop")
	t.Setenv("SESH_MASTER_PASSWORD", "old-password-1")
	stubTerminalPrompt(t, interactivePrompt(t, "new-password-2"))
	if out, err := runSyncOut(t, "", false); err != nil || !strings.Contains(out, "sealed again with the new master password") && !strings.Contains(out, "now opens with") {
		t.Fatalf("desktop takes it: %q, %v", out, err)
	}
	for _, f := range scanFolder(t, folder) {
		if f.KeyIDString() != folderKeyID(t, folder) {
			t.Errorf("%s still sealed with the old key", filepath.Base(f.Path))
		}
	}
	if err := os.Rename(folder, folder+"-away"); err != nil {
		t.Fatal(err)
	}
	changePassword(t, "new-password-2", "desktop-password-3")
	if err := os.Rename(folder+"-away", folder); err != nil {
		t.Fatal(err)
	}
	syncComputer(t, laptop, "laptop")
	changePassword(t, "new-password-2", "laptop-password-4")

	syncComputer(t, desktop, "desktop")
	t.Setenv("SESH_MASTER_PASSWORD", "desktop-password-3")
	stubTerminalPrompt(t, interactivePrompt(t, "laptop-password-4"))
	out, err := runSyncOut(t, "", false)
	if err != nil || !strings.Contains(out, "own master password change wasn't kept") {
		t.Fatalf("desktop, its change behind the laptop's: %q, %v", out, err)
	}
	t.Setenv("SESH_MASTER_PASSWORD", "laptop-password-4")
	if got := getEntry(t, "password/a"); got != "secret-1" {
		t.Errorf("the desktop has a = %q", got)
	}
}

// A master password change is refused while the folder has one changed on
// another computer, not taken here yet.
func TestSync_PasswordChangeRefusedBehind(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a")
	syncComputer(t, laptop, "laptop")
	changePassword(t, "old-password-1", "new-password-2")

	syncComputer(t, desktop, "desktop")
	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, stderr := rekeyTestApp("y\n")
	err := runRekey(app, nil, rotateTestCfg("old-password-1", "desktop-password-3", "desktop-password-3"))
	if err == nil || !strings.Contains(err.Error(), "changed on another computer: take it first") {
		t.Errorf("passwd behind the folder: %v\n%s", err, stderr)
	}
}

// A vault that left the folder and changed its master password is switched
// to the folder's as it joins again (decided with the user), keeping what
// it agreed: a deletion made elsewhere meanwhile holds.
func TestSync_RejoinAfterOwnChange(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a", "password/b")

	ldb := syncComputer(t, laptop, "laptop")
	if _, err := runSyncOut(t, "", false, "leave"); err != nil {
		t.Fatal(err)
	}
	if said := changePassword(t, "old-password-1", "laptop-password-2"); !strings.Contains(said, "joining it again asks for the folder's master password") {
		t.Errorf("passwd, left the folder:\n%s", said)
	}
	syncComputer(t, desktop, "desktop")
	t.Setenv("SESH_MASTER_PASSWORD", "old-password-1")
	purgeEntry(t, "password/b")
	if _, err := runSyncOut(t, "", false); err != nil {
		t.Fatal(err)
	}

	syncComputer(t, laptop, "laptop")
	t.Setenv("SESH_MASTER_PASSWORD", "")
	stubTerminalPrompt(t, interactivePrompt(t, "old-password-1", "laptop-password-2"))
	out, err := runSyncOut(t, "", false, "join", folder)
	if err != nil || !strings.Contains(out, "own master password change, made while it was away, wasn't kept") || !strings.Contains(out, "again") {
		t.Fatalf("join again: %q, %v", out, err)
	}
	if vaultKeyID(t, ldb) != folderKeyID(t, folder) {
		t.Error("the laptop isn't on the folder's key record")
	}
	t.Setenv("SESH_MASTER_PASSWORD", "old-password-1")
	if entryExists(t, "password/b") {
		t.Error("b, deleted on the desktop meanwhile, came back")
	}
}

// sesh ui's change of the master password goes to the sync folder too.
func TestSync_UIPasswordChangeSends(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, _ := syncedPair(t, dir, folder, "password/a")
	ldb := syncComputer(t, laptop, "laptop")
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	cfg.SyncDir = config.Setting[string]{Value: folder, Source: config.FromFile}
	ch, err := uiChangePassword(cfg, []byte("old-password-1"), []byte("new-password-2"))
	if err != nil || !strings.Contains(strings.Join(ch.Said, "\n"), "Sent the change to the sync folder") {
		t.Fatalf("ui change: %+v, %v", ch, err)
	}
	if folderKeyID(t, folder) != vaultKeyID(t, ldb) {
		t.Error("the folder doesn't have the new key record")
	}
}

// A change whose key record reached the folder, its sync then cut short,
// has nothing left to send: the next sync says nothing of it.
func TestSync_PasswordChangeSentThenCut(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, _ := syncedPair(t, dir, folder, "password/a")
	ldb := syncComputer(t, laptop, "laptop")
	if err := os.Rename(folder, folder+"-away"); err != nil {
		t.Fatal(err)
	}
	changePassword(t, "old-password-1", "new-password-2")
	if err := os.Rename(folder+"-away", folder); err != nil {
		t.Fatal(err)
	}
	// As if the change had been sent, and the sync after it cut short.
	m, err := database.ReadUnlockMaterial(ldb)
	if err != nil {
		t.Fatal(err)
	}
	f := syncfolder.New(folder)
	info, err := f.ReadInfo()
	if err != nil {
		t.Fatal(err)
	}
	info.Key = syncfolder.KeyRecord{Salt: m.Salt, Verify: m.Verify, Params: m.Params}
	if err := f.WriteInfo(info); err != nil {
		t.Fatal(err)
	}
	if out, err := runSyncOut(t, "", false); err != nil || strings.Contains(out, "Sent this computer's") || !strings.Contains(out, "1 entry's file is sealed with the old master password's key") {
		t.Errorf("sync: %q, %v", out, err)
	}
	if got, err := database.VaultKeyChange(ldb); err != nil || got != "" {
		t.Errorf("a change still to send: %q, %v", got, err)
	}
}
