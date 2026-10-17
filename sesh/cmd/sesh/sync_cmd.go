package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/syncfolder"
	"github.com/bashhack/sesh/internal/vaultsync"
)

const syncUsage = `Usage:
  sesh sync                      Sync the vault with its sync folder now
  sesh sync init [folder]        Make a sync folder from this vault and sync with it; with no
                                 folder, sesh offers one in iCloud Drive
  sesh sync join <folder>        Make this computer's vault from a sync folder another
                                 computer made (this vault must be new, or empty)
  sesh sync status               Where the vault syncs, and what's waiting
  sesh sync leave                Stop syncing this vault (its entries and the folder stay)

A sync folder is a folder any tool carries between your computers: iCloud
Drive, Dropbox, Syncthing, a USB stick. Each computer keeps its own vault;
the folder holds one file per entry, encrypted with the vault's key, so it
says nothing without your master password, not even entries' names. Every
computer that syncs through it has the same master password. The vault
itself never goes in the folder.

Changed on one computer, an entry is changed on the others at their next
sync; changed on two, the changes are merged: what only one changed is
taken, and where both changed the same thing the newer change wins, the
older's password kept in the history and its notes and secret fields
kept beside the newer's. An entry edited on one computer and deleted on
another comes back. sesh sync status says what's waiting.`

// runSync is sesh sync and its subcommands.
func runSync(app *App, args []string) error {
	if len(args) > 0 && isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, syncUsage)
		return err
	}
	if len(args) == 0 {
		return syncNow(app)
	}
	switch args[0] {
	case "init":
		if len(args) > 2 {
			return errors.New("sesh sync init takes one folder")
		}
		return syncInit(app, args[1:])
	case "join":
		if len(args) != 2 {
			return errors.New("sesh sync join takes the sync folder: sesh sync join <folder>")
		}
		return syncJoin(app, args[1])
	case "status":
		return syncStatus(app)
	case "leave":
		return syncLeave(app)
	}
	return fmt.Errorf("sesh sync takes init, join, status or leave, or nothing, not %q", strings.Join(args, " "))
}

// errNotSyncing is a vault with no sync folder.
var errNotSyncing = errors.New("this vault doesn't sync: sesh sync init makes a sync folder from it, sesh sync join <folder> joins one")

// syncFolderOf is cfg's sync folder, checked to be one for this vault:
// its key record the vault's.
func syncFolderOf(cfg *config.Config) (syncfolder.Folder, error) {
	if cfg.SyncDir.Value == "" {
		return syncfolder.Folder{}, errNotSyncing
	}
	f := syncfolder.New(cfg.SyncDir.Value)
	info, err := f.ReadInfo()
	if err != nil {
		return f, fmt.Errorf("the sync folder %s: %w", tildePath(f.Dir()), err)
	}
	m, err := database.ReadUnlockMaterial(cfg.DBPath.Value)
	if err != nil {
		return f, err
	}
	if database.UnlockID(info.Key.Verify) != database.UnlockID(m.Verify) {
		return f, fmt.Errorf("the sync folder %s is for another master password than this vault's: changed on another computer, or a folder for other vaults", tildePath(f.Dir()))
	}
	return f, nil
}

// syncNow is sesh sync: the vault synced with its folder.
func syncNow(app *App) error {
	cfg, err := settings()
	if err != nil {
		return err
	}
	return syncWith(app, cfg)
}

// syncWith syncs the vault cfg names with its folder, and says what it did.
func syncWith(app *App, cfg *config.Config) error {
	f, err := syncFolderOf(cfg)
	if err != nil {
		return err
	}
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	return syncStore(app, cfg, f, store)
}

// syncStore syncs store, the vault cfg names, with f, and says what it did.
func syncStore(app *App, cfg *config.Config, f syncfolder.Folder, store *database.Store) error {
	sum, err := vaultsync.Sync(store, f, cfg.SyncComputerName())
	if err != nil {
		return err
	}
	return writeSyncSummary(app, tildePath(f.Dir()), sum)
}

// writeSyncSummary says what a sync did; problems make it an error, after
// they're listed.
func writeSyncSummary(app *App, dir string, s *vaultsync.Summary) error {
	if s.Nothing() {
		_, err := fmt.Fprintf(app.Stdout, "✅ In sync with %s: nothing to do.\n", dir)
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Synced with %s:\n", dir)
	names := func(ns []string) string {
		slices.Sort(ns)
		if len(ns) > 5 {
			return strings.Join(ns[:5], ", ") + fmt.Sprintf(" and %d more", len(ns)-5)
		}
		return strings.Join(ns, ", ")
	}
	line := func(label string, ns []string) {
		if len(ns) > 0 {
			fmt.Fprintf(&b, "  %s: %s (%s)\n", label, nouns(len(ns), "entry", "entries"), names(ns))
		}
	}
	line("Changed elsewhere, taken", s.Received)
	line("Changed here, sent", s.Sent)
	for _, m := range s.Merged {
		fmt.Fprintf(&b, "  %s: %s\n", m.Name, mergedSaid(m.Conflicts))
	}
	for _, r := range s.Renamed {
		fmt.Fprintf(&b, "  %s: made on two computers under one name, with different secrets, so renamed\n", r)
	}
	for _, j := range s.Joined {
		fmt.Fprintf(&b, "  %s: made on two computers with one secret, made one\n", j)
	}
	if s.NotDownloaded > 0 {
		fmt.Fprintf(&b, "  %s for the sync tool to download their files (keep the sync folder downloaded: in iCloud Drive, Control-click it and choose Keep Downloaded)\n", nouns(s.NotDownloaded, "entry waits", "entries wait"))
	}
	if s.OtherKey > 0 {
		fmt.Fprintf(&b, "  %s sealed with another master password's key, left for the computer that wrote them\n", nouns(s.OtherKey, "entry's file is", "entries' files are"))
	}
	if s.Ignored > 0 {
		fmt.Fprintf(&b, "  %s already seen here, ignored (a sync tool, or someone, put back an older one)\n", nouns(s.Ignored, "older copy of a file", "older copies of files"))
	}
	if s.Later > 0 {
		fmt.Fprintf(&b, "  %s changed by another sesh command meanwhile: the next sync takes them\n", nouns(s.Later, "entry", "entries"))
	}
	for _, p := range s.Problems {
		fmt.Fprintf(&b, "  ❌ %s\n", p)
	}
	if _, err := fmt.Fprint(app.Stdout, b.String()); err != nil {
		return err
	}
	if len(s.Problems) > 0 {
		return fmt.Errorf("the sync had %s; the rest synced", nouns(len(s.Problems), "problem", "problems"))
	}
	return nil
}

// mergedSaid says how an entry changed here and elsewhere was merged, from
// what both changed (syncfolder.Merged's Conflicts).
func mergedSaid(conflicts []string) string {
	said := "changed here and elsewhere, merged"
	if slices.Contains(conflicts, "restored") {
		said = "restored from a backup, merged with the folder's: the restored values kept"
	}
	var both, kept []string
	for _, c := range conflicts {
		switch {
		case c == "restored":
		case c == "secret":
			both = append(both, c)
			kept = append(kept, "the other password is in its history")
		case c == "notes":
			both = append(both, c)
			kept = append(kept, "the older notes are below the newer")
		case strings.HasPrefix(c, "field "):
			both = append(both, c)
			kept = append(kept, "an older secret field's value is kept as another field, named for its computer")
		default:
			both = append(both, c)
		}
	}
	if len(both) > 0 {
		said += "; both changed " + strings.Join(both, ", ") + ", so the newer change was kept"
	}
	kept = slices.Compact(kept)
	if len(kept) > 0 {
		said += " (" + strings.Join(kept, "; ") + ")"
	}
	return said
}

// iCloudDrive is iCloud Drive's folder on this Mac, or "" when there's none.
func iCloudDrive() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	dir := filepath.Join(home, "Library", "Mobile Documents", "com~apple~CloudDocs")
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return ""
	}
	return dir
}

// syncDirArg is the sync folder named by arg: ~/ and relative paths made
// whole.
func syncDirArg(arg string) (string, error) {
	if strings.HasPrefix(arg, "~/") || filepath.IsAbs(arg) {
		return config.ResolvePath(arg)
	}
	return filepath.Abs(arg)
}

// checkSyncDir refuses a sync folder in the vault's own folder, or holding
// it: the vault itself never goes where a sync tool copies it.
func checkSyncDir(dir, dbPath string) error {
	within := func(path, folder string) bool {
		rel, err := filepath.Rel(folder, path)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
	}
	vaultDir := filepath.Dir(dbPath)
	switch {
	case within(dbPath, dir):
		return fmt.Errorf("%s holds the vault itself; a sync folder must be somewhere else (a sync tool copying a live vault can damage it)", tildePath(dir))
	case within(dir, vaultDir):
		return fmt.Errorf("%s is inside the vault's own folder; choose a folder elsewhere", tildePath(dir))
	}
	return nil
}

// syncInit is sesh sync init: a sync folder made from this vault, then the
// first sync.
func syncInit(app *App, args []string) error {
	cfg, err := settings()
	if err != nil {
		return err
	}
	if cfg.SyncDir.Value != "" {
		return fmt.Errorf("this vault syncs with %s already (sesh sync leave stops that)", tildePath(cfg.SyncDir.Value))
	}
	m, err := database.ReadUnlockMaterial(cfg.DBPath.Value)
	if errors.Is(err, database.ErrNoVault) {
		return errors.New("there's no vault here yet: add an entry first, or join a sync folder another computer made (sesh sync join <folder>)")
	}
	if err != nil {
		return err
	}
	var dir string
	switch {
	case len(args) == 1:
		if dir, err = syncDirArg(args[0]); err != nil {
			return err
		}
	case iCloudDrive() != "" && app.StdinIsTerminal != nil && app.StdinIsTerminal():
		dir = filepath.Join(iCloudDrive(), "sesh-sync")
		answer, err := ask(app, bufio.NewReader(app.Stdin), fmt.Sprintf("Make the sync folder in iCloud Drive, at %s? [Y/n] ", tildePath(dir)))
		if err != nil {
			return err
		}
		if answer != "" && !strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes") {
			return errors.New("name the folder: sesh sync init <folder>")
		}
	default:
		return errors.New("name the folder to sync through: sesh sync init <folder> (in iCloud Drive, Dropbox, or any folder a tool keeps the same on your computers)")
	}
	if err := checkSyncDir(dir, cfg.DBPath.Value); err != nil {
		return err
	}
	f := syncfolder.New(dir)
	switch _, err := f.ReadInfo(); {
	case err == nil:
		return fmt.Errorf("%s is a sync folder already: sesh sync join %s joins it", tildePath(dir), tildePath(dir))
	case !errors.Is(err, syncfolder.ErrNoInfo):
		return err
	}
	info, err := syncfolder.NewInfo(syncfolder.KeyRecord{Salt: m.Salt, Verify: m.Verify, Params: m.Params})
	if err != nil {
		return err
	}
	if err := f.WriteInfo(info); err != nil {
		return err
	}
	if err := setSyncDir(dir); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(app.Stdout, "Made the sync folder %s. On each other computer: sesh sync join %s\n", tildePath(dir), tildePath(dir)); err != nil {
		return err
	}
	cfg.SyncDir = config.Setting[string]{Value: dir, Source: config.FromFile}
	return syncWith(app, cfg)
}

// setSyncDir writes sync.dir (dir, or "" for none) into the config file.
func setSyncDir(dir string) error {
	path, err := config.Path()
	if err != nil {
		return err
	}
	if dir != "" {
		dir = tildePath(dir)
	}
	return config.Set(path, "sync.dir", dir)
}

// syncJoin is sesh sync join: this computer's vault made from a sync folder
// another computer made, then the first sync.
func syncJoin(app *App, arg string) error {
	cfg, err := settings()
	if err != nil {
		return err
	}
	dir, err := syncDirArg(arg)
	if err != nil {
		return err
	}
	if cfg.SyncDir.Value != "" && cfg.SyncDir.Value != dir {
		return fmt.Errorf("this vault syncs with %s already (sesh sync leave stops that)", tildePath(cfg.SyncDir.Value))
	}
	if err := checkSyncDir(dir, cfg.DBPath.Value); err != nil {
		return err
	}
	f := syncfolder.New(dir)
	info, err := f.ReadInfo()
	if err != nil {
		return fmt.Errorf("%s: %w", tildePath(dir), err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.DBPath.Value), 0o700); err != nil { //nolint:gosec // the vault's folder, from the user's own settings
		return fmt.Errorf("create vault directory: %w", err)
	}
	m := database.UnlockMaterial{Salt: info.Key.Salt, Verify: info.Key.Verify, Params: info.Key.Params}
	if err := database.JoinVault(cfg.DBPath.Value, m); err != nil {
		if errors.Is(err, database.ErrVaultNotEmpty) {
			return fmt.Errorf("%w. To bring its entries along: sesh export --file F, move the vault aside (or sesh init --db-path elsewhere), sesh sync join %s, then sesh import --from sesh F", err, tildePath(dir))
		}
		return err
	}
	// Unlocked first: the master password is checked against the folder's
	// key record before anything says it's joined.
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	if err := setSyncDir(dir); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(app.Stdout, "Joined the sync folder %s: the vault here opens with the same master password as the others.\n", tildePath(dir)); err != nil {
		return err
	}
	cfg.SyncDir = config.Setting[string]{Value: dir, Source: config.FromFile}
	return syncStore(app, cfg, f, store)
}

// syncStatus is sesh sync status: where the vault syncs and what's
// waiting, without unlocking it.
func syncStatus(app *App) error {
	cfg, err := settings()
	if err != nil {
		return err
	}
	if cfg.SyncDir.Value == "" {
		_, err := fmt.Fprintln(app.Stdout, errNotSyncing.Error()+".")
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Sync folder:   %s\n", tildePath(cfg.SyncDir.Value))
	fmt.Fprintf(&b, "This computer: %s\n", cfg.SyncComputerName())
	f, folderErr := syncFolderOf(cfg)
	if folderErr != nil {
		fmt.Fprintf(&b, "❌ %v\n", folderErr)
	}
	store, err := database.Open(cfg.DBPath.Value, nil)
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	items, err := store.SyncItems()
	if err != nil {
		return err
	}
	agreed := map[string]syncfolder.Hash{}
	changed := 0
	for i := range items {
		if items[i].Changed() {
			changed++
		}
		if items[i].Agreed != nil {
			agreed[items[i].UID] = items[i].Agreed.Hash
		}
	}
	if events, err := store.AuditEvents(0); err == nil {
		for _, e := range events {
			if e.EventType == "sync" {
				fmt.Fprintf(&b, "Last synced:   %s (%s)\n", e.CreatedAt.Local().Format("2006-01-02 15:04"), strings.TrimPrefix(e.Detail, "Sync: "))
				break
			}
		}
	}
	fmt.Fprintf(&b, "Changed here, to send:          %d\n", changed)
	if folderErr == nil {
		c, err := f.Scan()
		if err != nil {
			return err
		}
		fresh := 0
		for _, file := range c.Files {
			if h, ok := agreed[file.UIDString()]; !ok || h != file.Hash {
				fresh++
			}
		}
		fmt.Fprintf(&b, "Changed in the folder, to take: %d\n", fresh)
		if len(c.NotDownloaded) > 0 {
			fmt.Fprintf(&b, "⚠️  %s for the sync tool to download their files: keep the sync folder downloaded (in iCloud Drive, Control-click it and choose Keep Downloaded)\n", nouns(len(c.NotDownloaded), "entry waits", "entries wait"))
		}
		for _, p := range c.Problems {
			fmt.Fprintf(&b, "❌ %s: %s\n", filepath.Base(p.Path), p.Why)
		}
	}
	_, err = fmt.Fprint(app.Stdout, b.String())
	return err
}

// syncLeave is sesh sync leave: the vault stops syncing. Its entries and
// the folder stay; joining again starts afresh.
func syncLeave(app *App) error {
	cfg, err := settings()
	if err != nil {
		return err
	}
	if cfg.SyncDir.Value == "" {
		return errNotSyncing
	}
	if cfg.SyncDir.Source == config.FromEnv {
		return fmt.Errorf("sync.dir comes from %s: unset it", cfg.SyncDir.Origin)
	}
	if !vaultMissing(cfg.DBPath.Value) {
		store, err := database.Open(cfg.DBPath.Value, nil)
		if err != nil {
			return err
		}
		err = store.SyncLeave()
		closeAuditStore(store)
		if err != nil {
			return err
		}
	}
	if err := setSyncDir(""); err != nil {
		return err
	}
	_, err = fmt.Fprintf(app.Stdout, "This vault no longer syncs with %s. Its entries are as they were, and so is the folder for the other computers.\n", tildePath(cfg.SyncDir.Value))
	return err
}
