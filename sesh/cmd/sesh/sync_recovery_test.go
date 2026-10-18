package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/recovery"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/syncfolder"
)

// madeRecoveryKey makes a recovery key for the vault at db, whose master
// password is pw, as sesh recovery new does, and returns it.
func madeRecoveryKey(t *testing.T, db, pw string) recovery.Key {
	t.Helper()
	m, err := database.ReadUnlockMaterial(db)
	if err != nil {
		t.Fatal(err)
	}
	k, last := fixedRecoveryKey(t)
	key := database.DeriveKey([]byte(pw), m.Salt, m.Params)
	defer secure.SecureZeroBytes(key)
	if saved, err := makeRecoveryKey(keyWrap(key), db, m.Verify, withLines(interactivePrompt(t), last)); err != nil || !saved {
		t.Fatalf("recovery key: %v, %v", saved, err)
	}
	return k
}

// opensNot fails the test if k opens the vault at db's recovery key record.
func opensNot(t *testing.T, k recovery.Key, db string) {
	t.Helper()
	f, err := database.ReadRecovery(db)
	if errors.Is(err, database.ErrNoRecovery) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Unwrap(recovery.Wrapped(f), []byte(f.UnlockID)); !errors.Is(err, recovery.ErrWrongKey) {
		t.Errorf("a recovery key that shouldn't still opens the vault (err %v)", err)
	}
}

func hasNoRecovery(t *testing.T, db string) {
	t.Helper()
	if _, err := database.ReadRecovery(db); !errors.Is(err, database.ErrNoRecovery) {
		t.Errorf("the vault has a recovery key record still: %v", err)
	}
}

// syncSays syncs the computer whose settings are in force, failing the
// test unless it succeeds saying want.
func syncSays(t *testing.T, who, want string) string {
	t.Helper()
	out, err := runSyncOut(t, "", false)
	if err != nil || !strings.Contains(out, want) {
		t.Fatalf("%s sync, wanting %q: %q, %v", who, want, out, err)
	}
	return out
}

// A recovery key made on one computer opens the vault on every computer
// once each syncs; removed on one, it's removed on every one.
func TestSync_RecoveryKeyShared(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a")
	ldb := syncComputer(t, laptop, "laptop")
	k := madeRecoveryKey(t, ldb, "old-password-1")
	syncSays(t, "laptop", "This computer's recovery key goes to the other computers")
	ddb := syncComputer(t, desktop, "desktop")
	syncSays(t, "desktop", "The recovery key made on laptop on ")
	opensVault(t, k, ddb)
	lr, lerr := database.ReadRecovery(ldb)
	dr, derr := database.ReadRecovery(ddb)
	if lerr != nil || derr != nil || !lr.CreatedAt.Equal(dr.CreatedAt) {
		t.Errorf("made on the laptop at %v, on the desktop at %v (%v, %v)", lr, dr, lerr, derr)
	}
	syncSays(t, "desktop again", "nothing to do")

	syncComputer(t, laptop, "laptop")
	syncSays(t, "laptop", "nothing to do")
	if err := database.RemoveRecovery(ldb); err != nil {
		t.Fatal(err)
	}
	syncSays(t, "laptop", "The recovery key's removal goes to the other computers")
	syncComputer(t, desktop, "desktop")
	syncSays(t, "desktop", "The recovery key was removed on laptop")
	hasNoRecovery(t, ddb)
}

// A computer joining a sync folder gets the recovery key the others use.
func TestSync_RecoveryKeyJoining(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	t.Setenv("SESH_MASTER_PASSWORD", "old-password-1")
	ldb := syncComputer(t, filepath.Join(dir, "laptop"), "laptop")
	putEntry(t, "password/a", "a")
	k := madeRecoveryKey(t, ldb, "old-password-1")
	if out, err := runSyncOut(t, "", false, "init", folder); err != nil || !strings.Contains(out, "recovery key goes to the other computers") {
		t.Fatalf("init: %q, %v", out, err)
	}
	ddb := syncComputer(t, filepath.Join(dir, "desktop"), "desktop")
	if out, err := runSyncOut(t, "", false, "join", folder); err != nil || !strings.Contains(out, "The recovery key made on laptop") {
		t.Fatalf("join: %q, %v", out, err)
	}
	opensVault(t, k, ddb)
}

// Two recovery keys made before either computer saw the other's: the first
// in the folder is kept on both, and the other computer says its own
// doesn't work.
func TestSync_RecoveryKeyRace(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a")
	ldb := syncComputer(t, laptop, "laptop")
	first := madeRecoveryKey(t, ldb, "old-password-1")
	ddb := syncComputer(t, desktop, "desktop")
	second := madeRecoveryKey(t, ddb, "old-password-1")
	syncComputer(t, laptop, "laptop")
	syncSays(t, "laptop", "recovery key goes to the other computers")
	syncComputer(t, desktop, "desktop")
	syncSays(t, "desktop", "The recovery key made here doesn't work: one made on laptop")
	opensVault(t, first, ddb)
	opensNot(t, second, ddb)
	syncComputer(t, laptop, "laptop")
	syncSays(t, "laptop", "nothing to do")
	opensVault(t, first, ldb)
}

// Two keys sent at once, from the same record seen (each computer's sync
// tool not yet showing the other's): the one whose key sorts last is kept
// on both, whichever copy the sync tool kept, the other computer says its
// own doesn't work, and putting the other copy back changes nothing.
func TestSync_RecoveryKeySentAtOnce(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a")
	infoPath := filepath.Join(folder, syncfolder.InfoFile)
	read := func() []byte {
		t.Helper()
		b, err := os.ReadFile(infoPath)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	write := func(b []byte) {
		t.Helper()
		if err := os.WriteFile(infoPath, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	before := read()
	ldb := syncComputer(t, laptop, "laptop")
	lk := madeRecoveryKey(t, ldb, "old-password-1")
	syncSays(t, "laptop", "recovery key goes")
	laptopCopy := read()
	write(before)
	ddb := syncComputer(t, desktop, "desktop")
	dk := madeRecoveryKey(t, ddb, "old-password-1")
	syncSays(t, "desktop", "recovery key goes")
	desktopCopy := read()

	lpub, err := lk.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	dpub, err := dk.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	kept, dropped, loser, losingCopy := lk, dk, desktop, desktopCopy
	if bytes.Compare(dpub, lpub) > 0 {
		kept, dropped, loser, losingCopy = dk, lk, laptop, laptopCopy
	}
	said := map[string]string{}
	for _, c := range []struct{ home, name string }{{laptop, "laptop"}, {desktop, "desktop"}, {laptop, "laptop"}} {
		syncComputer(t, c.home, c.name)
		out, err := runSyncOut(t, "", false)
		if err != nil {
			t.Fatalf("%s sync: %q, %v", c.name, out, err)
		}
		said[c.home] += out
	}
	for _, home := range []string{laptop, desktop} {
		if warned := strings.Contains(said[home], "The recovery key made here doesn't work"); warned != (home == loser) {
			t.Errorf("%s warned its key doesn't work: %v\n%s", home, warned, said[home])
		}
	}
	for _, db := range []string{ldb, ddb} {
		opensVault(t, kept, db)
		opensNot(t, dropped, db)
	}

	write(losingCopy)
	for _, c := range []struct{ home, name string }{{laptop, "laptop"}, {desktop, "desktop"}} {
		syncComputer(t, c.home, c.name)
		if out, err := runSyncOut(t, "", false); err != nil || strings.Contains(out, "now opens this vault") {
			t.Errorf("%s, the other copy put back: %q, %v", c.name, out, err)
		}
	}
	for _, db := range []string{ldb, ddb} {
		opensVault(t, kept, db)
	}
}

// The recovery key goes on opening every computer's vault through a
// master password change, and one made after it reaches the others.
func TestSync_RecoveryKeyThroughPasswordChange(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a")
	ldb := syncComputer(t, laptop, "laptop")
	k := madeRecoveryKey(t, ldb, "old-password-1")
	syncSays(t, "laptop", "recovery key goes")
	ddb := syncComputer(t, desktop, "desktop")
	syncSays(t, "desktop", "now opens this vault here too")

	syncComputer(t, laptop, "laptop")
	if said := changePassword(t, "old-password-1", "new-password-2"); strings.Contains(said, "recovery key record") {
		t.Errorf("the change warned of the recovery key record:\n%s", said)
	}
	syncComputer(t, desktop, "desktop")
	t.Setenv("SESH_MASTER_PASSWORD", "old-password-1")
	stubTerminalPrompt(t, interactivePrompt(t, "new-password-2"))
	if out, err := runSyncOut(t, "", false); err != nil || strings.Contains(out, "recovery key record") {
		t.Fatalf("desktop takes the change: %q, %v", out, err)
	}
	opensVault(t, k, ddb)
	opensVault(t, k, ldb)

	t.Setenv("SESH_MASTER_PASSWORD", "new-password-2")
	next := madeRecoveryKey(t, ddb, "new-password-2")
	syncSays(t, "desktop", "recovery key goes")
	syncComputer(t, laptop, "laptop")
	syncSays(t, "laptop", "made on desktop")
	opensVault(t, next, ldb)
	opensNot(t, k, ldb)
}

// A master password change sent later seals the folder's recovery key
// record again with the new key, quietly, and the key goes on working.
func TestSync_RecoveryKeyThroughOfflineChange(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a")
	ldb := syncComputer(t, laptop, "laptop")
	k := madeRecoveryKey(t, ldb, "old-password-1")
	syncSays(t, "laptop", "recovery key goes")
	if err := os.Rename(folder, folder+"-away"); err != nil {
		t.Fatal(err)
	}
	changePassword(t, "old-password-1", "new-password-2")
	if err := os.Rename(folder+"-away", folder); err != nil {
		t.Fatal(err)
	}
	if out := syncSays(t, "laptop", "Sent this computer's master password change"); strings.Contains(out, "recovery key record") {
		t.Errorf("the change sent warned of the recovery key record: %q", out)
	}
	ddb := syncComputer(t, desktop, "desktop")
	t.Setenv("SESH_MASTER_PASSWORD", "old-password-1")
	stubTerminalPrompt(t, interactivePrompt(t, "new-password-2"))
	if out, err := runSyncOut(t, "", false); err != nil || !strings.Contains(out, "made on laptop") {
		t.Fatalf("desktop takes the change and the key: %q, %v", out, err)
	}
	opensVault(t, k, ddb)
}

// An older sesh-sync.json put back, its recovery key record older, isn't
// taken, and is written over.
func TestSync_RecoveryRecordPutBack(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a")
	ldb := syncComputer(t, laptop, "laptop")
	first := madeRecoveryKey(t, ldb, "old-password-1")
	syncSays(t, "laptop", "recovery key goes")
	infoPath := filepath.Join(folder, syncfolder.InfoFile)
	old, err := os.ReadFile(infoPath)
	if err != nil {
		t.Fatal(err)
	}
	second := madeRecoveryKey(t, ldb, "old-password-1")
	syncSays(t, "laptop", "recovery key goes")
	ddb := syncComputer(t, desktop, "desktop")
	syncSays(t, "desktop", "now opens this vault")
	if err := os.WriteFile(infoPath, old, 0o600); err != nil {
		t.Fatal(err)
	}
	syncSays(t, "desktop", "recovery key record was an older one, put back")
	opensVault(t, second, ddb)
	opensNot(t, first, ddb)
	syncComputer(t, laptop, "laptop")
	syncSays(t, "laptop", "nothing to do")
	opensVault(t, second, ldb)
}

// A recovery key record not sealed with the vault's key now, made without
// it or with an earlier master password's, isn't taken, and is written
// over.
func TestSync_RecoveryRecordForged(t *testing.T) {
	for _, how := range []string{"no key", "earlier key"} {
		t.Run(how, func(t *testing.T) {
			dir := t.TempDir()
			folder := filepath.Join(dir, "sync")
			laptop, desktop := syncedPair(t, dir, folder, "password/a")
			ldb := syncComputer(t, laptop, "laptop")
			before, err := database.ReadUnlockMaterial(ldb)
			if err != nil {
				t.Fatal(err)
			}
			k := madeRecoveryKey(t, ldb, "old-password-1")
			syncSays(t, "laptop", "recovery key goes")
			ddb := syncComputer(t, desktop, "desktop")
			syncSays(t, "desktop", "now opens this vault")
			syncComputer(t, laptop, "laptop")
			if how == "earlier key" {
				changePassword(t, "old-password-1", "new-password-2")
			}
			f := syncfolder.New(folder)
			info, err := f.ReadInfo()
			if err != nil {
				t.Fatal(err)
			}
			theirs, err := recovery.New()
			if err != nil {
				t.Fatal(err)
			}
			pub, err := theirs.PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			sealer, keyID := database.KeySealer(bytes.Repeat([]byte{7}, 32)), database.UnlockID(info.Key.Verify)
			if how == "earlier key" {
				oldKey := database.DeriveKey([]byte("old-password-1"), before.Salt, before.Params)
				sealer, keyID = database.KeySealer(oldKey), database.UnlockID(before.Verify)
			}
			info.Recovery, err = syncfolder.SealRecovery(sealer, info.FolderID, keyID, &syncfolder.Recovery{Count: 99, PublicKey: pub, Computer: "theirs"})
			if err != nil {
				t.Fatal(err)
			}
			if err := f.WriteInfo(info); err != nil {
				t.Fatal(err)
			}
			syncComputer(t, desktop, "desktop")
			t.Setenv("SESH_MASTER_PASSWORD", "old-password-1")
			want := "doesn't open with this vault's key"
			if how == "earlier key" {
				// Taking the change, the desktop sets aside the key it took
				// under the old password, unconfirmed under the new.
				want = "isn't kept"
				stubTerminalPrompt(t, interactivePrompt(t, "new-password-2"))
			}
			out, err := runSyncOut(t, "", false)
			if err != nil || !strings.Contains(out, want) || strings.Contains(out, "made on theirs") {
				t.Fatalf("desktop sync: %q, %v", out, err)
			}
			opensNot(t, theirs, ddb)
			if how == "earlier key" {
				t.Setenv("SESH_MASTER_PASSWORD", "new-password-2")
				syncComputer(t, laptop, "laptop")
				syncSays(t, "laptop", "sealed with the key of an earlier master password")
				syncComputer(t, desktop, "desktop")
				syncSays(t, "desktop again", "made on laptop")
			}
			opensVault(t, k, ddb)
			syncSays(t, "desktop again", "nothing to do")
		})
	}
}

// A vault restored from a backup holding an older recovery key takes the
// one the other computers use, and never sends its own (decided with the
// user).
func TestSync_RestoreKeepsFolderRecoveryKey(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a")
	ldb := syncComputer(t, laptop, "laptop")
	first := madeRecoveryKey(t, ldb, "old-password-1")
	syncSays(t, "laptop", "recovery key goes")
	ddb := syncComputer(t, desktop, "desktop")
	syncSays(t, "desktop", "now opens this vault")
	backup := filepath.Join(dir, "backup.db")
	if err := database.CopyTo(ddb, backup); err != nil {
		t.Fatal(err)
	}
	syncComputer(t, laptop, "laptop")
	second := madeRecoveryKey(t, ldb, "old-password-1")
	syncSays(t, "laptop", "recovery key goes")
	syncComputer(t, desktop, "desktop")
	syncSays(t, "desktop", "now opens this vault")
	if err := database.RestoreInPlace(ddb, backup); err != nil {
		t.Fatal(err)
	}
	opensVault(t, first, ddb)
	if out := syncSays(t, "desktop, restored", "The recovery key made on laptop"); strings.Contains(out, "recovery key goes") {
		t.Errorf("the restored vault sent its recovery key: %q", out)
	}
	opensVault(t, second, ddb)
	syncComputer(t, laptop, "laptop")
	syncSays(t, "laptop", "nothing to do")
	opensVault(t, second, ldb)
}

// A recovery key used on one computer (sesh recover) stops working on all
// of them.
func TestSync_RecoverRetiresTheKeyEverywhere(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a")
	ldb := syncComputer(t, laptop, "laptop")
	k := madeRecoveryKey(t, ldb, "old-password-1")
	syncSays(t, "laptop", "recovery key goes")
	syncComputer(t, desktop, "desktop")
	syncSays(t, "desktop", "now opens this vault")

	t.Setenv("SESH_MASTER_PASSWORD", "")
	out, err := runRecoverWith(t, []string{strings.ToLower(k.String()), "new-password-2", "new-password-2"}, false)
	if err != nil || !strings.Contains(out, "Sent the change") {
		t.Fatalf("recover: %v\n%s", err, out)
	}
	syncComputer(t, laptop, "laptop")
	t.Setenv("SESH_MASTER_PASSWORD", "old-password-1")
	stubTerminalPrompt(t, interactivePrompt(t, "new-password-2"))
	if out, err := runSyncOut(t, "", false); err != nil || !strings.Contains(out, "The recovery key was removed on desktop") {
		t.Fatalf("laptop sync: %q, %v", out, err)
	}
	hasNoRecovery(t, ldb)
}

// sesh recovery new on a computer that syncs takes the folder's key first,
// then sends its own at once; status says when a change isn't sent yet.
func TestSync_RecoveryNewWhileSyncing(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a")
	ldb := syncComputer(t, laptop, "laptop")
	first := madeRecoveryKey(t, ldb, "old-password-1")
	syncSays(t, "laptop", "recovery key goes")

	ddb := syncComputer(t, desktop, "desktop")
	startTestAgent(t)
	next, last := fixedRecoveryKey(t)
	replace := false
	orig := recoveryPrompt
	recoveryPrompt = func() passwordPromptConfig {
		return withLines(withAnswer(interactivePrompt(t, "old-password-1"), replace), last)
	}
	t.Cleanup(func() { recoveryPrompt = orig })
	run := func(args ...string) string {
		t.Helper()
		app := agentTestApp()
		if err := runRecovery(app, args); err != nil {
			t.Fatalf("recovery %v: %v", args, err)
		}
		return app.Stdout.(*bytes.Buffer).String() + app.Stderr.(*bytes.Buffer).String()
	}
	// Not replaced: the laptop's, taken through the agent, opens the vault.
	if out := run("new"); !strings.Contains(out, "The recovery key made on laptop") || !strings.Contains(out, "The existing recovery key was kept") {
		t.Errorf("recovery new, not replacing:\n%s", out)
	}
	opensVault(t, first, ddb)
	replace = true
	out := run("new")
	for _, want := range []string{"This computer's recovery key goes to the other computers"} {
		if !strings.Contains(out, want) {
			t.Errorf("recovery new, wanting %q:\n%s", want, out)
		}
	}
	opensVault(t, next, ddb)
	if out := run("status"); strings.Contains(out, "isn't sent") {
		t.Errorf("status after it was sent: %q", out)
	}

	syncComputer(t, laptop, "laptop")
	if out := syncSays(t, "laptop", "made on desktop"); strings.Contains(out, "doesn't work") {
		t.Errorf("the laptop said a key doesn't work: %q", out)
	}
	opensVault(t, next, ldb)
	madeRecoveryKey(t, ldb, "old-password-1")
	if out := run("status"); !strings.Contains(out, "It isn't sent to the other computers yet") {
		t.Errorf("status of a key not sent: %q", out)
	}
	if out, err := runSyncOut(t, "", false, "status"); err != nil || !strings.Contains(out, "Recovery key:                  changed here, to send") {
		t.Errorf("sync status of a key not sent: %q, %v", out, err)
	}
	if err := database.RemoveRecovery(ldb); err != nil {
		t.Fatal(err)
	}
	if out := run("status"); !strings.Contains(out, "Its removal isn't sent") {
		t.Errorf("status of a removal not sent: %q", out)
	}
}

// plantRecovery writes, as the sync folder's sesh-sync.json, info with a
// recovery key record of pub sealed with key (the key record's), count.
func plantRecovery(t *testing.T, folder string, info []byte, key []byte, pub []byte, count uint64) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(folder, syncfolder.InfoFile), info, 0o600); err != nil {
		t.Fatal(err)
	}
	f := syncfolder.New(folder)
	in, err := f.ReadInfo()
	if err != nil {
		t.Fatal(err)
	}
	in.Recovery, err = syncfolder.SealRecovery(database.KeySealer(key), in.FolderID, database.UnlockID(in.Key.Verify), &syncfolder.Recovery{Count: count, PublicKey: pub, Computer: "laptop"})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.WriteInfo(in); err != nil {
		t.Fatal(err)
	}
}

// Someone with the folder and an old master password, planting their key
// on a computer still on that password, doesn't keep it there once the
// computer takes the change, nor reach the others, even with the folder's
// record damaged as it takes it.
func TestSync_RecoveryKeyPlantedWithOldPassword(t *testing.T) {
	for _, damaged := range []bool{false, true} {
		t.Run(map[bool]string{false: "as it is", true: "damaged"}[damaged], func(t *testing.T) {
			plantedWithOldPassword(t, damaged)
		})
	}
}

func plantedWithOldPassword(t *testing.T, damaged bool) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a")
	ldb := syncComputer(t, laptop, "laptop")
	m, err := database.ReadUnlockMaterial(ldb)
	if err != nil {
		t.Fatal(err)
	}
	k := madeRecoveryKey(t, ldb, "old-password-1")
	syncSays(t, "laptop", "recovery key goes")
	ddb := syncComputer(t, desktop, "desktop")
	syncSays(t, "desktop", "now opens this vault")
	infoPath := filepath.Join(folder, syncfolder.InfoFile)
	before, err := os.ReadFile(infoPath)
	if err != nil {
		t.Fatal(err)
	}
	syncComputer(t, laptop, "laptop")
	changePassword(t, "old-password-1", "new-password-2")
	after, err := os.ReadFile(infoPath)
	if err != nil {
		t.Fatal(err)
	}

	theirs, err := recovery.New()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := theirs.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	oldKey := database.DeriveKey([]byte("old-password-1"), m.Salt, m.Params)
	plantRecovery(t, folder, before, oldKey, pub, 99)
	syncComputer(t, desktop, "desktop")
	t.Setenv("SESH_MASTER_PASSWORD", "old-password-1")
	if out, err := runSyncOut(t, "", false); err != nil {
		t.Fatalf("desktop, planted: %q, %v", out, err)
	}
	if err := os.WriteFile(infoPath, after, 0o600); err != nil {
		t.Fatal(err)
	}
	if damaged {
		plantRecovery(t, folder, after, bytes.Repeat([]byte{7}, 32), pub, 100)
	}
	stubTerminalPrompt(t, interactivePrompt(t, "new-password-2"))
	if out, err := runSyncOut(t, "", false); err != nil || !strings.Contains(out, "now opens with the new master password") {
		t.Fatalf("desktop takes the change: %q, %v", out, err)
	}
	opensNot(t, theirs, ddb)
	// Again before the laptop mends the folder: nothing is sent.
	t.Setenv("SESH_MASTER_PASSWORD", "new-password-2")
	syncSays(t, "desktop again", "")
	syncComputer(t, laptop, "laptop")
	t.Setenv("SESH_MASTER_PASSWORD", "new-password-2")
	syncSays(t, "laptop", "")
	opensVault(t, k, ldb)
	opensNot(t, theirs, ldb)
	syncComputer(t, desktop, "desktop")
	syncSays(t, "desktop", "")
	opensVault(t, k, ddb)
	opensNot(t, theirs, ddb)
}

// sesh recover on a computer that hasn't seen a key another sent keeps
// that key, newer than the one used, on both, and says so.
func TestSync_RecoverKeepsANewerKey(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := syncedPair(t, dir, folder, "password/a")
	ldb := syncComputer(t, laptop, "laptop")
	used := madeRecoveryKey(t, ldb, "old-password-1")
	syncSays(t, "laptop", "recovery key goes")
	ddb := syncComputer(t, desktop, "desktop")
	syncSays(t, "desktop", "now opens this vault")
	newer := madeRecoveryKey(t, ddb, "old-password-1")
	syncSays(t, "desktop", "recovery key goes")

	syncComputer(t, laptop, "laptop")
	t.Setenv("SESH_MASTER_PASSWORD", "")
	out, err := runRecoverWith(t, []string{strings.ToLower(used.String()), "new-password-2", "new-password-2"}, false)
	if err != nil || !strings.Contains(out, "one made on desktop") {
		t.Fatalf("recover: %v\n%s", err, out)
	}
	opensVault(t, newer, ldb)
	syncComputer(t, desktop, "desktop")
	t.Setenv("SESH_MASTER_PASSWORD", "old-password-1")
	stubTerminalPrompt(t, interactivePrompt(t, "new-password-2"))
	out, err = runSyncOut(t, "", false)
	if err != nil || strings.Contains(out, "doesn't work") || strings.Contains(out, "recovery key record") {
		t.Fatalf("desktop takes the change: %q, %v", out, err)
	}
	opensVault(t, newer, ddb)
}

// A send whose folder write landed but not its record here: the next sync
// finds its own key in the folder, and says nothing of it not working.
func TestSync_RecoverySendCutShort(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, _ := syncedPair(t, dir, folder, "password/a")
	ldb := syncComputer(t, laptop, "laptop")
	k := madeRecoveryKey(t, ldb, "old-password-1")
	syncSays(t, "laptop", "recovery key goes")
	sqlExec(t, ldb, `UPDATE sync_info SET recovery_count = 0, recovery_key = x'', recovery_mine = 0`)
	if out := syncSays(t, "laptop", ""); strings.Contains(out, "doesn't work") {
		t.Errorf("the laptop said its own key doesn't work: %q", out)
	}
	opensVault(t, k, ldb)
}

// A computer joining, with nothing seen, leaves a folder record it can't
// take as it is.
func TestSync_RecoveryJoinLeavesForeignRecord(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	syncedPair(t, dir, folder, "password/a")
	infoPath := filepath.Join(folder, syncfolder.InfoFile)
	b, err := os.ReadFile(infoPath)
	if err != nil {
		t.Fatal(err)
	}
	plantRecovery(t, folder, b, bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{4}, 65), 5)
	planted, err := os.ReadFile(infoPath)
	if err != nil {
		t.Fatal(err)
	}
	syncComputer(t, filepath.Join(dir, "third"), "third")
	t.Setenv("SESH_MASTER_PASSWORD", "old-password-1")
	if out, err := runSyncOut(t, "", false, "join", folder); err != nil || !strings.Contains(out, "doesn't open with this vault's key") {
		t.Fatalf("join: %q, %v", out, err)
	}
	if now, err := os.ReadFile(infoPath); err != nil || !bytes.Equal(now, planted) {
		t.Errorf("the folder's record was written over by a computer that saw none (%v)", err)
	}
}

// A folder record, sealed with the vault's key, whose key isn't a public
// key at all, isn't taken.
func TestSync_RecoveryRecordNotAKey(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, _ := syncedPair(t, dir, folder, "password/a")
	ldb := syncComputer(t, laptop, "laptop")
	m, err := database.ReadUnlockMaterial(ldb)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(folder, syncfolder.InfoFile))
	if err != nil {
		t.Fatal(err)
	}
	plantRecovery(t, folder, b, database.DeriveKey([]byte("old-password-1"), m.Salt, m.Params), []byte("not a key"), 5)
	if out, err := runSyncOut(t, "", false); err != nil || !strings.Contains(out, "the recovery key wasn't synced") {
		t.Errorf("sync: %q, %v", out, err)
	}
	hasNoRecovery(t, ldb)
}

// A sync folder this vault hasn't synced with yet (sync.dir set by hand)
// gets nothing from sesh recovery new before a whole sync.
func TestSync_RecoveryNewOtherFolder(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, _ := syncedPair(t, dir, folder, "password/a")
	ldb := syncComputer(t, laptop, "laptop")
	madeRecoveryKey(t, ldb, "old-password-1")
	syncSays(t, "laptop", "recovery key goes")
	other := filepath.Join(dir, "other")
	info, err := syncfolder.New(folder).ReadInfo()
	if err != nil {
		t.Fatal(err)
	}
	info.FolderID, info.Recovery = "0123456789abcdef", nil
	if err := syncfolder.New(other).WriteInfo(info); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.EnvSyncDir, other)
	startTestAgent(t)
	_, last := fixedRecoveryKey(t)
	orig := recoveryPrompt
	recoveryPrompt = func() passwordPromptConfig {
		return withLines(withAnswer(interactivePrompt(t, "old-password-1"), true), last)
	}
	t.Cleanup(func() { recoveryPrompt = orig })
	if err := runRecovery(agentTestApp(), []string{"new"}); err != nil {
		t.Fatal(err)
	}
	if got, err := syncfolder.New(other).ReadInfo(); err != nil || got.Recovery != nil {
		t.Errorf("the other folder got a recovery key record: %+v, %v", got, err)
	}
}
