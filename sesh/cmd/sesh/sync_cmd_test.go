package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/syncfolder"
	"github.com/bashhack/sesh/internal/vault"
)

// syncComputer makes this test a computer of its own: its own home, vault,
// config and agent socket, named name, with the master password
// SESH_MASTER_PASSWORD gives.
func syncComputer(t *testing.T, home, name string) string {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "data"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	t.Setenv("SESH_AUTH_SOCK", tempAgentSocket(t))
	t.Setenv(config.EnvSyncName, name)
	t.Setenv(config.EnvSyncDir, "")
	t.Setenv(config.EnvDBPath, "")
	db, err := database.DefaultDBPath()
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func runSyncOut(t *testing.T, stdin string, terminal bool, args ...string) (string, error) {
	t.Helper()
	app := agentTestApp()
	app.Stdin = strings.NewReader(stdin)
	app.StdinIsTerminal = func() bool { return terminal }
	err := runSync(app, args)
	return app.Stdout.(*bytes.Buffer).String() + app.Stderr.(*bytes.Buffer).String(), err
}

func putEntry(t *testing.T, id, secret string) {
	t.Helper()
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAuditStore(store)
	k, err := vault.ParseKey(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(k, []byte(secret)); err != nil {
		t.Fatal(err)
	}
}

func getEntry(t *testing.T, id string) string {
	t.Helper()
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAuditStore(store)
	k, err := vault.ParseKey(id)
	if err != nil {
		t.Fatal(err)
	}
	b, err := store.Get(k)
	if err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	return string(b)
}

// A sync folder made from one computer's vault is joined by another, whose
// vault then opens with the same master password and has the entries;
// changes go both ways; status says where and what's waiting; leaving
// stops it, entries kept.
func TestSync_InitJoinSyncLeave(t *testing.T) {
	t.Setenv("SESH_MASTER_PASSWORD", "sync-password-1234")
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := filepath.Join(dir, "laptop"), filepath.Join(dir, "desktop")

	syncComputer(t, laptop, "laptop")
	if got, err := runSyncOut(t, "", false); err == nil || !strings.Contains(err.Error(), "this vault doesn't sync") {
		t.Errorf("sync before init: %q, %v", got, err)
	}
	if got, err := runSyncOut(t, "", false, "init", folder); err == nil || !strings.Contains(err.Error(), "no vault here yet") {
		t.Errorf("init with no vault: %q, %v", got, err)
	}
	putEntry(t, "password/github/alice", "pw-1")
	out, err := runSyncOut(t, "", false, "init", folder)
	if err != nil || !strings.Contains(out, "Made the sync folder") || !strings.Contains(out, "Changed here, sent: 1 entry (password/github/alice)") {
		t.Fatalf("init: %q, %v", out, err)
	}
	if got, err := runSyncOut(t, "", false, "init", folder); err == nil || !strings.Contains(err.Error(), "syncs with") {
		t.Errorf("init twice: %q, %v", got, err)
	}
	if got, err := runSyncOut(t, "", false); err != nil || !strings.Contains(got, "nothing to do") {
		t.Errorf("sync again: %q, %v", got, err)
	}

	syncComputer(t, desktop, "desktop")
	if got, err := runSyncOut(t, "", false, "join", filepath.Join(dir, "elsewhere")); err == nil || !strings.Contains(err.Error(), "not a sesh sync folder") {
		t.Errorf("join a folder that isn't one: %q, %v", got, err)
	}
	out, err = runSyncOut(t, "", false, "join", folder)
	if err != nil || !strings.Contains(out, "Joined the sync folder") || !strings.Contains(out, "Changed elsewhere, taken: 1 entry (password/github/alice)") {
		t.Fatalf("join: %q, %v", out, err)
	}
	if got := getEntry(t, "password/github/alice"); got != "pw-1" {
		t.Errorf("the desktop has %q", got)
	}
	putEntry(t, "password/github/alice", "pw-2")
	out, err = runSyncOut(t, "", false, "status")
	if err != nil || !strings.Contains(out, "This computer: desktop") || !strings.Contains(out, "Changed here, to send:          1") || !strings.Contains(out, "Last synced:") {
		t.Errorf("status: %q, %v", out, err)
	}
	if got, err := runSyncOut(t, "", false); err != nil || !strings.Contains(got, "Changed here, sent: 1 entry") {
		t.Errorf("desktop sync: %q, %v", got, err)
	}

	syncComputer(t, laptop, "laptop")
	if got, err := runSyncOut(t, "", false); err != nil || !strings.Contains(got, "Changed elsewhere, taken: 1 entry") {
		t.Errorf("laptop sync: %q, %v", got, err)
	}
	if got := getEntry(t, "password/github/alice"); got != "pw-2" {
		t.Errorf("the laptop has %q", got)
	}
	out, err = runSyncOut(t, "", false, "leave")
	if err != nil || !strings.Contains(out, "no longer syncs") {
		t.Fatalf("leave: %q, %v", out, err)
	}
	if got, err := runSyncOut(t, "", false); err == nil || !strings.Contains(err.Error(), "doesn't sync") {
		t.Errorf("sync after leaving: %q, %v", got, err)
	}
	if got := getEntry(t, "password/github/alice"); got != "pw-2" {
		t.Errorf("after leaving, the laptop has %q", got)
	}
	if _, err := os.Stat(filepath.Join(folder, "sesh-sync.json")); err != nil {
		t.Errorf("the folder after leaving: %v", err)
	}
}

// A vault that left joins its folder again, what changed on both sides
// meanwhile merged: a deletion elsewhere applied, an edit each way kept.
// Starting another folder, it sends everything there; it can't then join
// another vault's folder with its entries.
func TestSync_LeaveAndRejoin(t *testing.T) {
	t.Setenv("SESH_MASTER_PASSWORD", "sync-password-1234")
	dir := t.TempDir()
	folder, other := filepath.Join(dir, "sync"), filepath.Join(dir, "other")
	laptop, desktop := filepath.Join(dir, "laptop"), filepath.Join(dir, "desktop")

	syncComputer(t, laptop, "laptop")
	putEntry(t, "password/github/alice", "1")
	putEntry(t, "password/gitlab/alice", "2")
	putEntry(t, "password/aws/alice", "3")
	if _, err := runSyncOut(t, "", false, "init", folder); err != nil {
		t.Fatal(err)
	}
	syncComputer(t, desktop, "desktop")
	if _, err := runSyncOut(t, "", false, "join", folder); err != nil {
		t.Fatal(err)
	}

	syncComputer(t, laptop, "laptop")
	if out, err := runSyncOut(t, "", false, "leave"); err != nil || !strings.Contains(out, "joins it again") {
		t.Fatalf("leave: %q, %v", out, err)
	}
	syncComputer(t, desktop, "desktop")
	purgeEntry(t, "password/gitlab/alice")
	putEntry(t, "password/github/alice", "desktop-1")
	if _, err := runSyncOut(t, "", false); err != nil {
		t.Fatal(err)
	}

	syncComputer(t, laptop, "laptop")
	putEntry(t, "password/aws/alice", "laptop-3")
	out, err := runSyncOut(t, "", false, "join", folder)
	if err != nil || !strings.Contains(out, "again") || !strings.Contains(out, "Changed here, sent: 1 entry (password/aws/alice)") {
		t.Fatalf("join again: %q, %v", out, err)
	}
	if got := getEntry(t, "password/github/alice"); got != "desktop-1" {
		t.Errorf("github on the laptop: %q", got)
	}
	if entryExists(t, "password/gitlab/alice") {
		t.Error("gitlab, deleted on the desktop meanwhile, came back")
	}
	syncComputer(t, desktop, "desktop")
	if _, err := runSyncOut(t, "", false); err != nil {
		t.Fatal(err)
	}
	if got := getEntry(t, "password/aws/alice"); got != "laptop-3" {
		t.Errorf("aws on the desktop: %q", got)
	}
	if entryExists(t, "password/gitlab/alice") {
		t.Error("gitlab came back on the desktop")
	}

	// Another folder: everything goes there, as changes.
	syncComputer(t, laptop, "laptop")
	if _, err := runSyncOut(t, "", false, "leave"); err != nil {
		t.Fatal(err)
	}
	out, err = runSyncOut(t, "", false, "init", other)
	if err != nil || !strings.Contains(out, "Changed here, sent: 2 entries") {
		t.Fatalf("init another folder: %q, %v", out, err)
	}
	// The desktop's vault, with its entries, can't join the laptop's new
	// folder: it never synced with it.
	syncComputer(t, desktop, "desktop")
	if _, err := runSyncOut(t, "", false, "leave"); err != nil {
		t.Fatal(err)
	}
	if out, err := runSyncOut(t, "", false, "join", other); err == nil || !strings.Contains(err.Error(), "already has entries") {
		t.Errorf("join another vault's folder with entries: %q, %v", out, err)
	}
	// Nor sync with it through sync.dir set by hand; status says so too.
	t.Setenv(config.EnvSyncDir, other)
	if out, err := runSyncOut(t, "", false); err == nil || !strings.Contains(err.Error(), "synced with another sync folder") {
		t.Errorf("sync with another vault's folder by hand: %q, %v", out, err)
	}
	if out, err := runSyncOut(t, "", false, "status"); err != nil || !strings.Contains(out, "❌ this vault synced with another sync folder") {
		t.Errorf("status with another vault's folder: %q, %v", out, err)
	}
	t.Setenv(config.EnvSyncDir, "")
}

// Joining the folder the vault syncs with already just syncs; without a
// terminal or SESH_MASTER_PASSWORD, join says how to give the password.
func TestSync_JoinCases(t *testing.T) {
	t.Setenv("SESH_MASTER_PASSWORD", "sync-password-1234")
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	syncComputer(t, filepath.Join(dir, "laptop"), "laptop")
	putEntry(t, "password/a", "1")
	if _, err := runSyncOut(t, "", false, "init", folder); err != nil {
		t.Fatal(err)
	}
	if out, err := runSyncOut(t, "", false, "join", folder); err != nil || !strings.Contains(out, "syncs with "+folder+" already") || strings.Contains(out, "Joined") {
		t.Errorf("join the folder it syncs with: %q, %v", out, err)
	}
	syncComputer(t, filepath.Join(dir, "desktop"), "desktop")
	t.Setenv("SESH_MASTER_PASSWORD", "")
	if out, err := runSyncOut(t, "", false, "join", folder); err == nil || !strings.Contains(err.Error(), "run sesh sync join at one, or give it in SESH_MASTER_PASSWORD") {
		t.Errorf("join with no terminal: %q, %v", out, err)
	}
}

func entryExists(t *testing.T, id string) bool {
	t.Helper()
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAuditStore(store)
	k, err := vault.ParseKey(id)
	if err != nil {
		t.Fatal(err)
	}
	return store.Exists(k) == nil
}

// Joining refuses a vault with entries of its own, and a wrong master
// password changes nothing: no vault made, an empty one's key record kept,
// no setting written.
func TestSync_JoinRefuses(t *testing.T) {
	t.Setenv("SESH_MASTER_PASSWORD", "sync-password-1234")
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	syncComputer(t, filepath.Join(dir, "laptop"), "laptop")
	putEntry(t, "password/a", "1")
	if _, err := runSyncOut(t, "", false, "init", folder); err != nil {
		t.Fatal(err)
	}

	syncComputer(t, filepath.Join(dir, "full"), "full")
	putEntry(t, "password/b", "2")
	if out, err := runSyncOut(t, "", false, "init", folder); err == nil || !strings.Contains(err.Error(), "is a sync folder already") {
		t.Errorf("init on another's folder: %q, %v", out, err)
	}
	if out, err := runSyncOut(t, "", false, "join", folder); err == nil || !strings.Contains(err.Error(), "already has entries") || !strings.Contains(err.Error(), "sesh export") || !strings.Contains(err.Error(), "come back, as new ones") {
		t.Errorf("join with entries: %q, %v", out, err)
	}

	db := syncComputer(t, filepath.Join(dir, "wrong"), "wrong")
	t.Setenv("SESH_MASTER_PASSWORD", "not-the-password")
	if out, err := runSyncOut(t, "", false, "join", folder); err == nil || !strings.Contains(err.Error(), "isn't the master password") || strings.Contains(out, "Joined") {
		t.Errorf("join with the wrong password: %q, %v", out, err)
	}
	if !vaultMissing(db) {
		t.Error("a vault made with the wrong password")
	}
	cfg, err := settings()
	if err != nil || cfg.SyncDir.Value != "" {
		t.Errorf("sync.dir after a wrong password: %q, %v", cfg.SyncDir.Value, err)
	}
	t.Setenv("SESH_MASTER_PASSWORD", "sync-password-1234")
	if out, err := runSyncOut(t, "", false, "join", folder); err != nil || !strings.Contains(out, "Joined") {
		t.Errorf("join again, the right password: %q, %v", out, err)
	}

	// An empty vault with its own master password keeps it when the one
	// typed is wrong; joined, it has the folder's.
	t.Setenv("SESH_MASTER_PASSWORD", "own-password-5678")
	db = syncComputer(t, filepath.Join(dir, "own"), "own")
	putEntry(t, "password/c", "3")
	purgeEntry(t, "password/c")
	if out, err := runSyncOut(t, "", false, "join", folder); err == nil || strings.Contains(out, "Joined") {
		t.Errorf("join an empty vault with the wrong password: %q, %v", out, err)
	}
	if !opensWith(t, db, "own-password-5678") {
		t.Error("the empty vault's own master password no longer opens it")
	}
	t.Setenv("SESH_MASTER_PASSWORD", "sync-password-1234")
	if out, err := runSyncOut(t, "", false, "join", folder); err != nil || !strings.Contains(out, "Joined") {
		t.Fatalf("join an empty vault: %q, %v", out, err)
	}
	if !opensWith(t, db, "sync-password-1234") || getEntry(t, "password/a") != "1" {
		t.Error("the joined vault doesn't open with the folder's master password")
	}
}

func purgeEntry(t *testing.T, id string) {
	t.Helper()
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAuditStore(store)
	k, err := vault.ParseKey(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PurgeMany([]vault.Key{k}); err != nil {
		t.Fatal(err)
	}
}

func opensWith(t *testing.T, db, pw string) bool {
	t.Helper()
	m, err := database.ReadUnlockMaterial(db)
	if err != nil {
		t.Fatal(err)
	}
	return database.CheckMasterPassword([]byte(pw), m) == nil
}

// A wrong master password at init makes no folder and sets nothing.
func TestSync_InitWrongPassword(t *testing.T) {
	t.Setenv("SESH_MASTER_PASSWORD", "sync-password-1234")
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	syncComputer(t, filepath.Join(dir, "laptop"), "laptop")
	putEntry(t, "password/a", "1")
	t.Setenv("SESH_MASTER_PASSWORD", "not-the-password")
	if out, err := runSyncOut(t, "", false, "init", folder); err == nil || strings.Contains(out, "Made the sync folder") {
		t.Errorf("init with the wrong password: %q, %v", out, err)
	}
	if _, err := os.Stat(filepath.Join(folder, "sesh-sync.json")); !os.IsNotExist(err) {
		t.Errorf("the folder made: %v", err)
	}
	if cfg, err := settings(); err != nil || cfg.SyncDir.Value != "" {
		t.Errorf("sync.dir set: %q, %v", cfg.SyncDir.Value, err)
	}
}

// Status says what's waiting without making a vault, and counts files
// sealed with another master password's key apart: sync never takes them.
func TestSync_Status(t *testing.T) {
	t.Setenv("SESH_MASTER_PASSWORD", "sync-password-1234")
	dir := t.TempDir()
	folder, other := filepath.Join(dir, "sync"), filepath.Join(dir, "other")
	syncComputer(t, filepath.Join(dir, "laptop"), "laptop")
	putEntry(t, "password/a", "1")
	if _, err := runSyncOut(t, "", false, "init", folder); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SESH_MASTER_PASSWORD", "other-password-5678")
	syncComputer(t, filepath.Join(dir, "elsewhere"), "elsewhere")
	putEntry(t, "password/b", "2")
	if _, err := runSyncOut(t, "", false, "init", other); err != nil {
		t.Fatal(err)
	}
	des, err := os.ReadDir(filepath.Join(other, "entries"))
	if err != nil || len(des) != 1 {
		t.Fatalf("the other folder's files: %v, %v", des, err)
	}
	b, err := os.ReadFile(filepath.Join(other, "entries", des[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, "entries", des[0].Name()), b, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SESH_MASTER_PASSWORD", "sync-password-1234")
	syncComputer(t, filepath.Join(dir, "laptop"), "laptop")
	out, err := runSyncOut(t, "", false, "status")
	if err != nil || !strings.Contains(out, "Changed in the folder, to take: 0") || !strings.Contains(out, "1 entry's file is sealed with another master password's key") {
		t.Errorf("status: %q, %v", out, err)
	}

	db := syncComputer(t, filepath.Join(dir, "new"), "new")
	t.Setenv(config.EnvSyncDir, folder)
	out, err = runSyncOut(t, "", false, "status")
	if err != nil || !strings.Contains(out, "no vault here yet") {
		t.Errorf("status with no vault: %q, %v", out, err)
	}
	if !vaultMissing(db) {
		t.Error("status made a vault")
	}
}

// The subcommands take what they say, and no more.
func TestSync_Arguments(t *testing.T) {
	t.Setenv("SESH_MASTER_PASSWORD", "sync-password-1234")
	dir := t.TempDir()
	syncComputer(t, filepath.Join(dir, "laptop"), "laptop")
	putEntry(t, "password/a", "1")
	t.Chdir(dir)
	for _, args := range [][]string{{"init", "-x"}, {"init", "a", "b"}, {"join"}, {"join", "--force"}, {"status", "extra"}, {"leave", "extra"}, {"frob"}} {
		if out, err := runSyncOut(t, "", false, args...); err == nil {
			t.Errorf("sesh sync %q: %q, want refused", args, out)
		}
	}
	if _, err := os.Stat("-x"); !os.IsNotExist(err) {
		t.Errorf("a folder named -x: %v", err)
	}
}

// A sync folder can't be where the vault is, nor hold it.
func TestSync_InitRefusesTheVaultsFolder(t *testing.T) {
	t.Setenv("SESH_MASTER_PASSWORD", "sync-password-1234")
	dir := t.TempDir()
	db := syncComputer(t, filepath.Join(dir, "laptop"), "laptop")
	putEntry(t, "password/a", "1")
	// Through a link to the vault's folder, too, and named in another
	// case where the file system ignores case.
	link := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Dir(db), link); err != nil {
		t.Fatal(err)
	}
	refused := []string{filepath.Join(filepath.Dir(db), "sync"), filepath.Dir(filepath.Dir(db)), link, filepath.Join(link, "sync")}
	if upper := strings.ToUpper(filepath.Dir(db)); upper != filepath.Dir(db) {
		if _, err := os.Stat(upper); err == nil {
			refused = append(refused, filepath.Join(upper, "sync"))
		}
	}
	for _, f := range refused {
		if out, err := runSyncOut(t, "", false, "init", f); err == nil || !strings.Contains(err.Error(), "vault") {
			t.Errorf("init %s: %q, %v", f, out, err)
		}
	}
	// A vault named through a link is where the link leads.
	real := filepath.Join(dir, "real")
	if err := os.MkdirAll(filepath.Join(real, "v"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(real, "v"), filepath.Join(dir, "vlink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.EnvDBPath, filepath.Join(dir, "vlink", "passwords.db"))
	putEntry(t, "password/b", "2")
	if out, err := runSyncOut(t, "", false, "init", real); err == nil || !strings.Contains(err.Error(), "holds the vault") {
		t.Errorf("init the folder holding the linked vault: %q, %v", out, err)
	}
	t.Setenv(config.EnvDBPath, "")
	// sync.dir set by hand is held to the same, when set and when used.
	if out, _, err := runCLI(agentTestApp(), runConfig, "set", "sync.dir", filepath.Join(link, "sync")); err == nil || !strings.Contains(err.Error(), "vault's own folder") {
		t.Errorf("config set sync.dir in the vault's folder: %q, %v", out, err)
	}
	t.Setenv(config.EnvSyncDir, filepath.Join(link, "sync"))
	if out, err := runSyncOut(t, "", false); err == nil || !strings.Contains(err.Error(), "vault's own folder") {
		t.Errorf("sync with sync.dir in the vault's folder: %q, %v", out, err)
	}
}

// With no folder named, at a terminal, init offers one in iCloud Drive.
func TestSync_InitSuggestsICloudDrive(t *testing.T) {
	t.Setenv("SESH_MASTER_PASSWORD", "sync-password-1234")
	dir := t.TempDir()
	home := filepath.Join(dir, "laptop")
	syncComputer(t, home, "laptop")
	putEntry(t, "password/a", "1")
	if out, err := runSyncOut(t, "", false, "init"); err == nil || !strings.Contains(err.Error(), "name the folder") {
		t.Errorf("no iCloud Drive: %q, %v", out, err)
	}
	icloud := filepath.Join(home, "Library", "Mobile Documents", "com~apple~CloudDocs")
	if err := os.MkdirAll(icloud, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := runSyncOut(t, "n\n", true, "init"); err == nil || !strings.Contains(err.Error(), "name the folder") {
		t.Errorf("declined: %q, %v", out, err)
	}
	out, err := runSyncOut(t, "\n", true, "init")
	if err != nil || !strings.Contains(out, "Make the sync folder in iCloud Drive") || !strings.Contains(out, "sesh sync join ~/'Library/Mobile Documents/com~apple~CloudDocs/sesh-sync'") {
		t.Fatalf("accepted: %q, %v", out, err)
	}
	if _, err := os.Stat(filepath.Join(icloud, "sesh-sync", "sesh-sync.json")); err != nil {
		t.Errorf("the folder in iCloud Drive: %v", err)
	}
}

// A merge is said by what both changed, and what was kept of the older.
func TestMergedSaid(t *testing.T) {
	for conflicts, want := range map[string]string{
		"":                 "changed here and elsewhere, merged",
		"secret":           "changed here and elsewhere, merged; both changed secret, so the newer change was kept (the other password is in its history)",
		"notes,folder":     "changed here and elsewhere, merged; both changed notes, folder, so the newer change was kept (the older notes are below the newer)",
		"restored,secret":  "restored from a backup, merged with the folder's: the restored values kept; both changed secret, so the newer change was kept (the other password is in its history)",
		"field pin,secret": "changed here and elsewhere, merged; both changed field pin, secret, so the newer change was kept (an older secret field's value is kept as another field, named for its computer; the other password is in its history)",
	} {
		var cs []string
		if conflicts != "" {
			cs = strings.Split(conflicts, ",")
		}
		if got := mergedSaid(cs); got != want {
			t.Errorf("%q:\n got %q\nwant %q", conflicts, got, want)
		}
	}
}

// A sync folder that lost its sesh-sync.json can't be made a new one, which
// would cut off every computer syncing through it; a sync from one of them
// writes it again, and the others go on.
func TestSync_LostInfoFile(t *testing.T) {
	t.Setenv("SESH_MASTER_PASSWORD", "sync-password-1234")
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, desktop := filepath.Join(dir, "laptop"), filepath.Join(dir, "desktop")
	syncComputer(t, laptop, "laptop")
	putEntry(t, "password/a", "1")
	if _, err := runSyncOut(t, "", false, "init", folder); err != nil {
		t.Fatal(err)
	}
	syncComputer(t, desktop, "desktop")
	if _, err := runSyncOut(t, "", false, "join", folder); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(folder, "sesh-sync.json")); err != nil {
		t.Fatal(err)
	}

	syncComputer(t, laptop, "laptop")
	if _, err := runSyncOut(t, "", false, "leave"); err != nil {
		t.Fatal(err)
	}
	if out, err := runSyncOut(t, "", false, "init", folder); err == nil || !strings.Contains(err.Error(), "a sync folder that lost it") {
		t.Errorf("init on a folder that lost its info file: %q, %v", out, err)
	}
	if _, err := os.Stat(filepath.Join(folder, "sesh-sync.json")); !os.IsNotExist(err) {
		t.Errorf("init wrote an info file: %v", err)
	}

	syncComputer(t, desktop, "desktop")
	if out, err := runSyncOut(t, "", false, "status"); err != nil || !strings.Contains(out, "⚠️  the sync folder") || !strings.Contains(out, "lost its sesh-sync.json: sesh sync writes it again") {
		t.Errorf("status, the info file lost: %q, %v", out, err)
	}
	putEntry(t, "password/b", "2")
	out, err := runSyncOut(t, "", false)
	if err != nil || !strings.Contains(out, "written again from this vault") || !strings.Contains(out, "Changed here, sent: 1 entry") {
		t.Fatalf("desktop sync: %q, %v", out, err)
	}
	syncComputer(t, laptop, "laptop")
	if out, err := runSyncOut(t, "", false, "join", folder); err != nil || !strings.Contains(out, "again") {
		t.Fatalf("laptop joins again: %q, %v", out, err)
	}
	if got := getEntry(t, "password/b"); got != "2" {
		t.Errorf("the laptop has b = %q", got)
	}

	// Lost while the laptop is away: joining again writes it again.
	if _, err := runSyncOut(t, "", false, "leave"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(folder, "sesh-sync.json")); err != nil {
		t.Fatal(err)
	}
	if out, err := runSyncOut(t, "", false, "join", folder); err != nil || !strings.Contains(out, "again") || !strings.Contains(out, "written again from this vault") {
		t.Fatalf("laptop joins again, the info file lost: %q, %v", out, err)
	}

	// A folder that only shares the key (another the laptop made since,
	// with copies of its entries) isn't written as this one.
	other := filepath.Join(dir, "other")
	if _, err := runSyncOut(t, "", false, "leave"); err != nil {
		t.Fatal(err)
	}
	if _, err := runSyncOut(t, "", false, "init", other); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(folder, "sesh-sync.json")); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.EnvSyncDir, folder)
	if out, err := runSyncOut(t, "", false); err == nil || strings.Contains(out, "written again") || !strings.Contains(err.Error(), "holds no entry file this vault agreed") {
		t.Errorf("a folder that only shares the key: %q, %v", out, err)
	}
	if _, err := os.Stat(filepath.Join(folder, "sesh-sync.json")); !os.IsNotExist(err) {
		t.Errorf("an info file written for a folder this vault doesn't sync with: %v", err)
	}
	t.Setenv(config.EnvSyncDir, "")
}

// A copy of a vault that never synced, with entries of its own, can't sync
// with a folder holding files through sync.dir set by hand, as it can't
// join it; nor can a vault that synced elsewhere, with a folder whose files
// can't even be read.
func TestSync_HandSetFolderRefused(t *testing.T) {
	t.Setenv("SESH_MASTER_PASSWORD", "sync-password-1234")
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	laptop, copied := filepath.Join(dir, "laptop"), filepath.Join(dir, "copy")
	db := syncComputer(t, laptop, "laptop")
	putEntry(t, "password/a", "1")
	putEntry(t, "password/b", "2")
	copyDB := syncComputer(t, copied, "copy")
	if err := os.MkdirAll(filepath.Dir(copyDB), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := database.CopyTo(db, copyDB); err != nil {
		t.Fatal(err)
	}
	syncComputer(t, laptop, "laptop")
	if _, err := runSyncOut(t, "", false, "init", folder); err != nil {
		t.Fatal(err)
	}
	purgeEntry(t, "password/a")
	if _, err := runSyncOut(t, "", false); err != nil {
		t.Fatal(err)
	}

	syncComputer(t, copied, "copy")
	t.Setenv(config.EnvSyncDir, folder)
	if out, err := runSyncOut(t, "", false); err == nil || !strings.Contains(err.Error(), "never synced with this folder") {
		t.Errorf("a never-synced copy by hand: %q, %v", out, err)
	}
	t.Setenv(config.EnvSyncDir, "")

	// The laptop, synced with folder, pointed at another holding only a
	// file it can't read (a link).
	syncComputer(t, laptop, "laptop")
	odd := filepath.Join(dir, "odd")
	if err := os.MkdirAll(filepath.Join(odd, "entries"), 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := syncfolder.NewInfo(syncfolder.KeyRecord{})
	if err != nil {
		t.Fatal(err)
	}
	m, err := database.ReadUnlockMaterial(db)
	if err != nil {
		t.Fatal(err)
	}
	info.Key = syncfolder.KeyRecord{Salt: m.Salt, Verify: m.Verify, Params: m.Params}
	if err := syncfolder.New(odd).WriteInfo(info); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "nowhere"), filepath.Join(odd, "entries", strings.Repeat("ab", 16)+".sesh")); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.EnvSyncDir, odd)
	if out, err := runSyncOut(t, "", false); err == nil || !strings.Contains(err.Error(), "synced with another sync folder") {
		t.Errorf("another folder with only an unreadable file: %q, %v", out, err)
	}
	t.Setenv(config.EnvSyncDir, "")
	// Joining the folder it syncs with, named through a link, just syncs.
	if err := os.Symlink(folder, filepath.Join(dir, "synclink")); err != nil {
		t.Fatal(err)
	}
	if out, err := runSyncOut(t, "", false, "join", filepath.Join(dir, "synclink")); err != nil || !strings.Contains(out, "already") {
		t.Errorf("join the folder it syncs with, through a link: %q, %v", out, err)
	}
}

// A lost sesh-sync.json isn't written again by a vault whose master
// password changed since (its key would lock the others out), nor by one
// behind the folder, which says who can; one up to date writes it.
func TestSync_LostInfoChangedOrBehind(t *testing.T) {
	t.Setenv("SESH_MASTER_PASSWORD", "sync-password-1234")
	dir := t.TempDir()
	folder := filepath.Join(dir, "sync")
	info := filepath.Join(folder, "sesh-sync.json")
	laptop, desktop, third := filepath.Join(dir, "laptop"), filepath.Join(dir, "desktop"), filepath.Join(dir, "third")
	syncComputer(t, laptop, "laptop")
	putEntry(t, "password/a", "1")
	if _, err := runSyncOut(t, "", false, "init", folder); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{desktop, third} {
		syncComputer(t, c, filepath.Base(c))
		if _, err := runSyncOut(t, "", false, "join", folder); err != nil {
			t.Fatal(err)
		}
	}

	// The laptop's master password changed while it was away from the
	// folder.
	syncComputer(t, laptop, "laptop")
	if _, err := runSyncOut(t, "", false, "leave"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SESH_MASTER_PASSWORD", "")
	app, stderr := rekeyTestApp("y\n")
	if err := runRekey(app, nil, rotateTestCfg("sync-password-1234", "new-pw-5678", "new-pw-5678")); err != nil {
		t.Fatalf("passwd: %v\n%s", err, stderr)
	}
	t.Setenv("SESH_MASTER_PASSWORD", "new-pw-5678")
	if err := os.Remove(info); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.EnvSyncDir, folder)
	if out, err := runSyncOut(t, "", false); err == nil || strings.Contains(out, "written again") {
		t.Errorf("sync after a password change: %q, %v", out, err)
	}
	t.Setenv(config.EnvSyncDir, "")
	if out, err := runSyncOut(t, "", false, "join", folder); err == nil || strings.Contains(out, "Joined") {
		t.Errorf("join after a password change: %q, %v", out, err)
	}
	if _, err := os.Stat(info); !os.IsNotExist(err) {
		t.Fatalf("the info file written with another key: %v", err)
	}

	// The third computer is behind: the desktop changed the entry since.
	t.Setenv("SESH_MASTER_PASSWORD", "sync-password-1234")
	syncComputer(t, desktop, "desktop")
	putEntry(t, "password/a", "2")
	if out, err := runSyncOut(t, "", false); err != nil || !strings.Contains(out, "written again") {
		t.Fatalf("desktop sync: %q, %v", out, err)
	}
	if err := os.Remove(info); err != nil {
		t.Fatal(err)
	}
	syncComputer(t, third, "third")
	if out, err := runSyncOut(t, "", false, "status"); err != nil || !strings.Contains(out, "other computers synced since") {
		t.Errorf("status, behind: %q, %v", out, err)
	}
	if out, err := runSyncOut(t, "", false); err == nil || !strings.Contains(err.Error(), "sesh sync on one of them writes it again") {
		t.Errorf("sync, behind: %q, %v", out, err)
	}
	syncComputer(t, desktop, "desktop")
	if out, err := runSyncOut(t, "", false); err != nil || !strings.Contains(out, "written again") {
		t.Errorf("desktop writes it again: %q, %v", out, err)
	}
	syncComputer(t, third, "third")
	if _, err := runSyncOut(t, "", false); err != nil {
		t.Errorf("third after: %v", err)
	}
	if got := getEntry(t, "password/a"); got != "2" {
		t.Errorf("third has a = %q", got)
	}
}

// The app's sync row says what sesh sync status says, and off when the
// vault doesn't sync.
func TestUISyncState(t *testing.T) {
	t.Setenv("SESH_MASTER_PASSWORD", "sync-password-1234")
	dir := t.TempDir()
	syncComputer(t, filepath.Join(dir, "laptop"), "laptop")
	putEntry(t, "password/a", "1")
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	if st, err := uiSyncState(cfg); err != nil || st.On || st.Said != "off" {
		t.Fatalf("not syncing: %+v, %v", st, err)
	}
	if _, err := runSyncOut(t, "", false, "init", filepath.Join(dir, "sync")); err != nil {
		t.Fatal(err)
	}
	putEntry(t, "password/b", "2")
	if cfg, err = settings(); err != nil {
		t.Fatal(err)
	}
	st, err := uiSyncState(cfg)
	if err != nil || !st.On || !strings.HasSuffix(st.Said, "sync") || !slices.Contains(st.Lines, "Changed here, to send:          1") {
		t.Errorf("syncing: %+v, %v", st, err)
	}
}

// A sync folder that can't be read is a line of the app's sync row, not
// an error; one that doesn't answer isn't waited on.
func TestUISyncStateTrouble(t *testing.T) {
	t.Setenv("SESH_MASTER_PASSWORD", "sync-password-1234")
	dir := t.TempDir()
	syncComputer(t, filepath.Join(dir, "laptop"), "laptop")
	putEntry(t, "password/a", "1")
	folder := filepath.Join(dir, "sync")
	if _, err := runSyncOut(t, "", false, "init", folder); err != nil {
		t.Fatal(err)
	}
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	entries := filepath.Join(folder, "entries")
	if err := os.RemoveAll(entries); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entries, []byte("not a folder"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := uiSyncState(cfg)
	if err != nil || !slices.ContainsFunc(st.Lines, func(l string) bool { return strings.HasPrefix(l, "❌") }) {
		t.Errorf("entries not a folder: %+v, %v; want a ❌ line, no error", st, err)
	}
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	origRead, origBudget := readDir, autoSyncBudget
	readDir = func(string) ([]os.DirEntry, error) { <-release; return nil, nil }
	autoSyncBudget = 50 * time.Millisecond
	t.Cleanup(func() { readDir, autoSyncBudget = origRead, origBudget })
	st, err = uiSyncState(cfg)
	if err != nil || !slices.ContainsFunc(st.Lines, func(l string) bool { return strings.Contains(l, "didn't answer in 50ms") }) {
		t.Errorf("the folder stuck: %+v, %v", st, err)
	}
}
