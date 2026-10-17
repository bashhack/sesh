package main

import (
	"bytes"
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
	if err != nil || !strings.Contains(out, "opens with the folder's master password now") || !strings.Contains(out, "again") {
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
	if out, err := runSyncOut(t, "", false); err != nil || strings.Contains(out, "Sent this computer's") || !strings.Contains(out, "1 entry's file sealed again with the new master password's key") {
		t.Errorf("sync: %q, %v", out, err)
	}
	if got, err := database.VaultKeyChange(ldb); err != nil || got != "" {
		t.Errorf("a change still to send: %q, %v", got, err)
	}
}

// An older sesh-sync.json put back after a change isn't taken: a sync
// writes the folder's record as it is now, asking nothing.
func TestSync_PasswordChangeRolledBack(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a")
	old, err := os.ReadFile(filepath.Join(folder, "sesh-sync.json"))
	if err != nil {
		t.Fatal(err)
	}
	ldb := syncComputer(t, laptop, "laptop")
	changePassword(t, "old-password-1", "new-password-2")
	syncComputer(t, desktop, "desktop")
	t.Setenv("SESH_MASTER_PASSWORD", "old-password-1")
	stubTerminalPrompt(t, interactivePrompt(t, "new-password-2"))
	if _, err := runSyncOut(t, "", false); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(folder, "sesh-sync.json"), old, 0o600); err != nil {
		t.Fatal(err)
	}
	// The desktop knows the change through the links it took with it.
	syncComputer(t, desktop, "desktop")
	t.Setenv("SESH_MASTER_PASSWORD", "new-password-2")
	if out, err := runSyncOut(t, "", false, "status"); err != nil || !strings.Contains(out, "an older one, put back") {
		t.Errorf("status, rolled back: %q, %v", out, err)
	}
	out, err := runSyncOut(t, "", false)
	if err != nil || !strings.Contains(out, "was an older one, put back: written as it is now") {
		t.Fatalf("sync, rolled back: %q, %v", out, err)
	}
	if folderKeyID(t, folder) != vaultKeyID(t, ldb) {
		t.Error("the folder isn't back on the new key record")
	}
	syncComputer(t, laptop, "laptop")
	if out, err := runSyncOut(t, "", false); err != nil || !strings.Contains(out, "nothing to do") {
		t.Errorf("laptop after: %q, %v", out, err)
	}
}

// A change whose link from this vault's key doesn't hold isn't taken: a
// proof that doesn't open with this vault's key is refused before the new
// password is asked; an old key, sealed in the link, that isn't this
// vault's, after.
func TestSync_PasswordChangeLinkTampered(t *testing.T) {
	for _, part := range []string{"proof", "key"} {
		t.Run(part, func(t *testing.T) {
			dir := t.TempDir()
			folder := filepath.Join(dir, "sync")
			laptop, desktop := syncedPair(t, dir, folder, "password/a")
			syncComputer(t, laptop, "laptop")
			changePassword(t, "old-password-1", "new-password-2")
			f := syncfolder.New(folder)
			info, err := f.ReadInfo()
			if err != nil || len(info.Links) != 1 {
				t.Fatalf("links: %+v, %v", info, err)
			}
			l := &info.Links[0]
			if part == "proof" {
				l.Proof[len(l.Proof)-1] ^= 1
			} else {
				newKey := database.DeriveKey([]byte("new-password-2"), info.Key.Salt, info.Key.Params)
				other, err := database.NewKeyLink(bytes.Repeat([]byte{7}, 32), newKey, l.From, l.To)
				if err != nil {
					t.Fatal(err)
				}
				l.Key, l.KeySalt = other.Key, other.KeySalt
			}
			if err := f.WriteInfo(info); err != nil {
				t.Fatal(err)
			}
			syncComputer(t, desktop, "desktop")
			t.Setenv("SESH_MASTER_PASSWORD", "old-password-1")
			if part == "proof" {
				stubTerminalPrompt(t, interactivePrompt(t))
			} else {
				stubTerminalPrompt(t, interactivePrompt(t, "new-password-2"))
			}
			if out, err := runSyncOut(t, "", false); err == nil || !strings.Contains(err.Error(), "wasn't made by a computer that had this vault's key") {
				t.Errorf("desktop sync: %q, %v", out, err)
			}
			if got := getEntry(t, "password/a"); got != "secret-1" {
				t.Errorf("the desktop's vault after: %q", got)
			}
			// A link whose proof doesn't hold doesn't stop the desktop
			// changing its own.
			if part == "proof" {
				if said := changePassword(t, "old-password-1", "desktop-password-3"); !strings.Contains(said, "Sent the change") {
					t.Errorf("passwd over a tampered link:\n%s", said)
				}
			}
		})
	}
}

// A key record no change from this vault's leads to (another vault's,
// say) isn't taken, and asks nothing; sesh passwd isn't refused, and puts
// this vault's back.
func TestSync_PasswordChangeForged(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a")
	syncComputer(t, filepath.Join(dir, "stranger"), "stranger")
	t.Setenv("SESH_MASTER_PASSWORD", "stranger-password-9")
	putEntry(t, "password/z", "z")
	sdb := syncComputer(t, filepath.Join(dir, "stranger"), "stranger")
	m, err := database.ReadUnlockMaterial(sdb)
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

	syncComputer(t, desktop, "desktop")
	t.Setenv("SESH_MASTER_PASSWORD", "old-password-1")
	stubTerminalPrompt(t, interactivePrompt(t))
	if out, err := runSyncOut(t, "", false); err == nil || !strings.Contains(err.Error(), "wasn't made by a computer that had this vault's key") {
		t.Errorf("desktop sync, forged: %q, %v", out, err)
	}
	ldb := syncComputer(t, laptop, "laptop")
	if said := changePassword(t, "old-password-1", "new-password-2"); !strings.Contains(said, "Sent the change to the sync folder") {
		t.Errorf("passwd over a forged record:\n%s", said)
	}
	if folderKeyID(t, folder) != vaultKeyID(t, ldb) {
		t.Error("passwd didn't put this vault's record back")
	}
}

// Two computers change the password with the folder away; the laptop's
// reaches it first. Every file opens through the links, so none is left
// on a key no computer has, and every entry stays.
func TestSync_PasswordChangedOnBothOffline(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a", "password/b")
	if err := os.Rename(folder, folder+"-away"); err != nil {
		t.Fatal(err)
	}
	syncComputer(t, laptop, "laptop")
	changePassword(t, "old-password-1", "laptop-password-2")
	syncComputer(t, desktop, "desktop")
	changePassword(t, "old-password-1", "desktop-password-3")
	putEntry(t, "password/c", "3")
	if err := os.Rename(folder+"-away", folder); err != nil {
		t.Fatal(err)
	}
	syncComputer(t, laptop, "laptop")
	t.Setenv("SESH_MASTER_PASSWORD", "laptop-password-2")
	if out, err := runSyncOut(t, "", false); err != nil || !strings.Contains(out, "Sent this computer's master password change") {
		t.Fatalf("laptop sends: %q, %v", out, err)
	}
	for _, file := range scanFolder(t, folder) {
		if file.KeyIDString() != folderKeyID(t, folder) {
			t.Errorf("%s left on the old key after the laptop's send", filepath.Base(file.Path))
		}
	}
	syncComputer(t, desktop, "desktop")
	t.Setenv("SESH_MASTER_PASSWORD", "desktop-password-3")
	stubTerminalPrompt(t, interactivePrompt(t, "laptop-password-2"))
	out, err := runSyncOut(t, "", false)
	if err != nil || !strings.Contains(out, "own master password change wasn't kept") {
		t.Fatalf("desktop takes the laptop's: %q, %v", out, err)
	}
	t.Setenv("SESH_MASTER_PASSWORD", "laptop-password-2")
	syncComputer(t, laptop, "laptop")
	if _, err := runSyncOut(t, "", false); err != nil {
		t.Fatal(err)
	}
	if got := getEntry(t, "password/c"); got != "3" {
		t.Errorf("the laptop has c = %q", got)
	}
}

// A vault that leaves with a change not sent, then joins again, sends it.
func TestSync_LeaveWithChangeToSend(t *testing.T) {
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
	if out, err := runSyncOut(t, "", false, "leave"); err != nil || !strings.Contains(out, "joining it again sends it") {
		t.Errorf("leave: %q, %v", out, err)
	}
	out, err := runSyncOut(t, "", false, "join", folder)
	if err != nil || !strings.Contains(out, "not sent before it left, goes to it now") || !strings.Contains(out, "Sent this computer's master password change") {
		t.Fatalf("join again: %q, %v", out, err)
	}
	if folderKeyID(t, folder) != vaultKeyID(t, ldb) {
		t.Error("the folder doesn't have the change")
	}
}

// A computer that forgot its own master password, after another changed
// it, takes the change with its recovery key.
func TestSync_RecoverTakesAChange(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a")
	ddb := syncComputer(t, desktop, "desktop")
	m, err := database.ReadUnlockMaterial(ddb)
	if err != nil {
		t.Fatal(err)
	}
	k, last := fixedRecoveryKey(t)
	key := database.DeriveKey([]byte("old-password-1"), m.Salt, m.Params)
	if saved, err := makeRecoveryKey(keyWrap(key), ddb, m.Verify, withLines(interactivePrompt(t), last)); err != nil || !saved {
		t.Fatalf("recovery key: %v, %v", saved, err)
	}
	syncComputer(t, laptop, "laptop")
	changePassword(t, "old-password-1", "new-password-2")

	syncComputer(t, desktop, "desktop")
	t.Setenv("SESH_MASTER_PASSWORD", "")
	out, err := runRecoverWith(t, []string{strings.ToLower(k.String()), "new-password-2"}, false)
	if err != nil || !strings.Contains(out, "this vault takes that one") {
		t.Fatalf("recover: %v\n%s", err, out)
	}
	if vaultKeyID(t, ddb) != folderKeyID(t, folder) {
		t.Error("the desktop isn't on the folder's key record")
	}
	t.Setenv("SESH_MASTER_PASSWORD", "new-password-2")
	if got := getEntry(t, "password/a"); got != "secret-1" {
		t.Errorf("the desktop has a = %q", got)
	}
}

// Two changes from one key (a record put back between them): every
// computer settles on the one whose key record's ID sorts last, the other
// asked for it, and every file then opens on both.
func TestSync_PasswordChangeFork(t *testing.T) {
	orig := forkKept
	t.Cleanup(func() { forkKept = orig })
	for name, kept := range map[string]func(string, string) bool{
		"last kept":  func(f, o string) bool { return f > o },
		"first kept": func(f, o string) bool { return f < o },
	} {
		t.Run(name, func(t *testing.T) {
			forkKept = kept
			forkSettles(t)
		})
	}
}

func forkSettles(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a", "password/b")
	old, err := os.ReadFile(filepath.Join(folder, "sesh-sync.json"))
	if err != nil {
		t.Fatal(err)
	}
	ldb := syncComputer(t, laptop, "laptop")
	changePassword(t, "old-password-1", "laptop-password-2")
	if err := os.WriteFile(filepath.Join(folder, "sesh-sync.json"), old, 0o600); err != nil {
		t.Fatal(err)
	}
	ddb := syncComputer(t, desktop, "desktop")
	changePassword(t, "old-password-1", "desktop-password-3")

	pw := map[string]string{laptop: "laptop-password-2", desktop: "desktop-password-3"}
	other := map[string]string{laptop: desktop, desktop: laptop}
	for round := range 3 {
		for _, c := range []string{laptop, desktop} {
			syncComputer(t, c, filepath.Base(c))
			t.Setenv("SESH_MASTER_PASSWORD", pw[c])
			stubTerminalPrompt(t, interactivePrompt(t, pw[other[c]]))
			out, err := runSyncOut(t, "", false)
			if err != nil {
				t.Fatalf("round %d, %s: %q, %v", round, filepath.Base(c), out, err)
			}
			if strings.Contains(out, "now opens with the new master password") {
				pw[c] = pw[other[c]]
			}
		}
	}
	if pw[laptop] != pw[desktop] || vaultKeyID(t, ldb) != vaultKeyID(t, ddb) || vaultKeyID(t, ldb) != folderKeyID(t, folder) {
		t.Fatalf("not settled: %v", pw)
	}
	for _, f := range scanFolder(t, folder) {
		if f.KeyIDString() != folderKeyID(t, folder) {
			t.Errorf("%s left on another key", filepath.Base(f.Path))
		}
	}
	for _, c := range []string{laptop, desktop} {
		syncComputer(t, c, filepath.Base(c))
		t.Setenv("SESH_MASTER_PASSWORD", pw[c])
		if got := getEntry(t, "password/b"); got != "secret-2" {
			t.Errorf("%s has b = %q", filepath.Base(c), got)
		}
	}
}

// A vault restored from a backup made two changes ago takes the change
// the folder has, through the links it kept: from its key then.
func TestSync_RestoredTwoChangesBack(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, _ := syncedPair(t, dir, folder, "password/a")
	ldb := syncComputer(t, laptop, "laptop")
	backup := filepath.Join(dir, "backup.db")
	if err := database.CopyTo(ldb, backup); err != nil {
		t.Fatal(err)
	}
	changePassword(t, "old-password-1", "new-password-2")
	changePassword(t, "new-password-2", "new-password-3")
	if err := database.RestoreInPlace(ldb, backup); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SESH_MASTER_PASSWORD", "old-password-1")
	stubTerminalPrompt(t, interactivePrompt(t, "new-password-3"))
	out, err := runSyncOut(t, "", false)
	if err != nil || !strings.Contains(out, "now opens with the new master password") {
		t.Fatalf("sync after the restore: %q, %v", out, err)
	}
	if vaultKeyID(t, ldb) != folderKeyID(t, folder) {
		t.Error("the restored vault isn't on the folder's key record")
	}
}

// A computer behind, meeting a superseded record put back, is warned; the
// newest password, typed, doesn't open it, so nothing changes; once a
// computer with the newest writes it back, that one is taken.
func TestSync_PasswordChangeSuperseded(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a")
	syncComputer(t, laptop, "laptop")
	changePassword(t, "old-password-1", "new-password-2")
	middle, err := os.ReadFile(filepath.Join(folder, "sesh-sync.json"))
	if err != nil {
		t.Fatal(err)
	}
	changePassword(t, "new-password-2", "new-password-3")
	if err := os.WriteFile(filepath.Join(folder, "sesh-sync.json"), middle, 0o600); err != nil {
		t.Fatal(err)
	}
	ddb := syncComputer(t, desktop, "desktop")
	t.Setenv("SESH_MASTER_PASSWORD", "old-password-1")
	stubTerminalPrompt(t, interactivePrompt(t, "new-password-3", "new-password-3", "new-password-3"))
	out, err := runSyncOut(t, "", false)
	if err == nil || !strings.Contains(out, "may be an older record put back") {
		t.Errorf("desktop, a superseded record put back: %q, %v", out, err)
	}
	syncComputer(t, laptop, "laptop")
	t.Setenv("SESH_MASTER_PASSWORD", "new-password-3")
	if out, err := runSyncOut(t, "", false); err != nil || !strings.Contains(out, "older one, put back") {
		t.Fatalf("laptop writes it back: %q, %v", out, err)
	}
	syncComputer(t, desktop, "desktop")
	t.Setenv("SESH_MASTER_PASSWORD", "old-password-1")
	stubTerminalPrompt(t, interactivePrompt(t, "new-password-3"))
	if out, err := runSyncOut(t, "", false); err != nil || !strings.Contains(out, "now opens with the new master password") {
		t.Fatalf("desktop takes the newest: %q, %v", out, err)
	}
	if vaultKeyID(t, ddb) != folderKeyID(t, folder) {
		t.Error("the desktop isn't on the folder's key record")
	}
}

// A file from another sync folder, sealed with a key of no vault here,
// doesn't stop a computer behind taking a change.
func TestSync_PasswordChangeForeignFile(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a")
	syncComputer(t, filepath.Join(dir, "them"), "them")
	t.Setenv("SESH_MASTER_PASSWORD", "their-password-9")
	putEntry(t, "password/z", "z")
	if _, err := runSyncOut(t, "", false, "init", filepath.Join(dir, "theirs")); err != nil {
		t.Fatal(err)
	}
	des, err := os.ReadDir(filepath.Join(dir, "theirs", "entries"))
	if err != nil || len(des) == 0 {
		t.Fatalf("their files: %v, %v", des, err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "theirs", "entries", des[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, "entries", des[0].Name()), b, 0o600); err != nil {
		t.Fatal(err)
	}
	syncComputer(t, laptop, "laptop")
	changePassword(t, "old-password-1", "new-password-2")
	syncComputer(t, desktop, "desktop")
	t.Setenv("SESH_MASTER_PASSWORD", "old-password-1")
	stubTerminalPrompt(t, interactivePrompt(t, "new-password-2"))
	if out, err := runSyncOut(t, "", false); !strings.Contains(out, "now opens with the new master password") {
		t.Errorf("desktop takes the change: %q, %v", out, err)
	}
}

// A computer one change behind, after another two changes behind took
// the newest (adding a link from its own key), sees a change, not a fork,
// whichever way forks would settle.
func TestSync_PasswordChangeOneBehind(t *testing.T) {
	orig := forkKept
	t.Cleanup(func() { forkKept = orig })
	for name, kept := range map[string]func(string, string) bool{
		"last kept":  func(f, o string) bool { return f > o },
		"first kept": func(f, o string) bool { return f < o },
	} {
		t.Run(name, func(t *testing.T) {
			forkKept = kept
			dir := t.TempDir()
			folder := filepath.Join(dir, "sync")
			laptop, desktop := syncedPair(t, dir, folder, "password/a")
			third := filepath.Join(dir, "third")
			syncComputer(t, third, "third")
			t.Setenv("SESH_MASTER_PASSWORD", "old-password-1")
			if _, err := runSyncOut(t, "", false, "join", folder); err != nil {
				t.Fatal(err)
			}
			syncComputer(t, laptop, "laptop")
			changePassword(t, "old-password-1", "new-password-2")
			syncComputer(t, desktop, "desktop")
			t.Setenv("SESH_MASTER_PASSWORD", "old-password-1")
			stubTerminalPrompt(t, interactivePrompt(t, "new-password-2"))
			if _, err := runSyncOut(t, "", false); err != nil {
				t.Fatal(err)
			}
			syncComputer(t, laptop, "laptop")
			changePassword(t, "new-password-2", "new-password-3")
			syncComputer(t, third, "third")
			t.Setenv("SESH_MASTER_PASSWORD", "old-password-1")
			stubTerminalPrompt(t, interactivePrompt(t, "new-password-3"))
			if _, err := runSyncOut(t, "", false); err != nil {
				t.Fatal(err)
			}
			ddb := syncComputer(t, desktop, "desktop")
			t.Setenv("SESH_MASTER_PASSWORD", "new-password-2")
			stubTerminalPrompt(t, interactivePrompt(t, "new-password-3"))
			out, err := runSyncOut(t, "", false)
			if err != nil || strings.Contains(out, "from the same one") || !strings.Contains(out, "now opens with the new master password") {
				t.Fatalf("desktop, one change behind: %q, %v", out, err)
			}
			if vaultKeyID(t, ddb) != folderKeyID(t, folder) {
				t.Error("the desktop isn't on the newest key record")
			}
		})
	}
}

// A link in the folder whose proof doesn't hold isn't kept by a computer
// taking the change it sits beside.
func TestSync_PasswordChangeKeepsOnlyVerifiedLinks(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a")
	syncComputer(t, laptop, "laptop")
	changePassword(t, "old-password-1", "new-password-2")
	f := syncfolder.New(folder)
	info, err := f.ReadInfo()
	if err != nil || len(info.Links) != 1 {
		t.Fatalf("links: %+v, %v", info, err)
	}
	newKey := database.DeriveKey([]byte("new-password-2"), info.Key.Salt, info.Key.Params)
	junkID := database.UnlockID(bytes.Repeat([]byte{9}, 32))
	junk, err := database.NewKeyLink(bytes.Repeat([]byte{7}, 32), newKey, junkID, info.Links[0].To)
	if err != nil {
		t.Fatal(err)
	}
	junk.Proof[len(junk.Proof)-1] ^= 1
	info.Links = append(info.Links, *junk)
	if err := f.WriteInfo(info); err != nil {
		t.Fatal(err)
	}
	ddb := syncComputer(t, desktop, "desktop")
	t.Setenv("SESH_MASTER_PASSWORD", "old-password-1")
	stubTerminalPrompt(t, interactivePrompt(t, "new-password-2"))
	if out, err := runSyncOut(t, "", false); err != nil {
		t.Fatalf("desktop takes the change: %q, %v", out, err)
	}
	links, err := database.VaultKeyLinks(ddb)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range links {
		if l.From == junkID {
			t.Errorf("the desktop kept a link whose proof doesn't hold: %+v", links)
		}
	}
}

// Joining again after only the folder's master password changed says so.
func TestSync_RejoinAfterFolderChange(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a")
	syncComputer(t, desktop, "desktop")
	if _, err := runSyncOut(t, "", false, "leave"); err != nil {
		t.Fatal(err)
	}
	syncComputer(t, laptop, "laptop")
	changePassword(t, "old-password-1", "new-password-2")
	syncComputer(t, desktop, "desktop")
	t.Setenv("SESH_MASTER_PASSWORD", "")
	stubTerminalPrompt(t, interactivePrompt(t, "new-password-2", "old-password-1"))
	out, err := runSyncOut(t, "", false, "join", folder)
	if err != nil || !strings.Contains(out, "The folder's master password changed while this vault was away") {
		t.Fatalf("join again: %q, %v", out, err)
	}
}

// Someone who learned an old master password can't make a computer take a
// change from it, nor stop its own: a change from a key this vault
// replaced is settled as two changes from one key, and passwd goes on.
func TestSync_PasswordChangeFromOldKey(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, _ := syncedPair(t, dir, folder, "password/a")
	ldb := syncComputer(t, laptop, "laptop")
	old, err := database.ReadUnlockMaterial(ldb)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := database.DeriveKey([]byte("old-password-1"), old.Salt, old.Params)
	changePassword(t, "old-password-1", "new-password-2")

	// Their own vault's key record, and a link to it from the old key.
	syncComputer(t, filepath.Join(dir, "them"), "them")
	t.Setenv("SESH_MASTER_PASSWORD", "their-password-9")
	putEntry(t, "password/z", "z")
	tdb := syncComputer(t, filepath.Join(dir, "them"), "them")
	theirs, err := database.ReadUnlockMaterial(tdb)
	if err != nil {
		t.Fatal(err)
	}
	theirKey := database.DeriveKey([]byte("their-password-9"), theirs.Salt, theirs.Params)
	link, err := database.NewKeyLink(oldKey, theirKey, database.UnlockID(old.Verify), database.UnlockID(theirs.Verify))
	if err != nil {
		t.Fatal(err)
	}
	f := syncfolder.New(folder)
	info, err := f.ReadInfo()
	if err != nil {
		t.Fatal(err)
	}
	info.Key = syncfolder.KeyRecord{Salt: theirs.Salt, Verify: theirs.Verify, Params: theirs.Params}
	info.Links = append(info.Links, *link)
	if err := f.WriteInfo(info); err != nil {
		t.Fatal(err)
	}

	syncComputer(t, laptop, "laptop")
	if said := changePassword(t, "new-password-2", "new-password-3"); !strings.Contains(said, "Sent the change") {
		t.Errorf("passwd after a change from an old key:\n%s", said)
	}
	if folderKeyID(t, folder) != vaultKeyID(t, ldb) {
		t.Error("the folder isn't on the laptop's key record")
	}
}
