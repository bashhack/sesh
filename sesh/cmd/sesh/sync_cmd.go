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
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/shell"
	"github.com/bashhack/sesh/internal/syncfolder"
	"github.com/bashhack/sesh/internal/touchid"
	"github.com/bashhack/sesh/internal/vaultsync"
)

const syncUsage = `Usage:
  sesh sync                      Sync the vault with its sync folder now
  sesh sync init [folder]        Make a sync folder from this vault and sync with it; with no
                                 folder, sesh offers one in iCloud Drive
  sesh sync join <folder>        Make this computer's vault from a sync folder another
                                 computer made (this vault must be new, or empty), or join
                                 again the folder this vault left
  sesh sync status               Where the vault syncs, and what's waiting
  sesh sync leave                Stop syncing this vault (its entries and the folder stay;
                                 joining the folder again merges what changed meanwhile)

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
		if len(args) > 2 || (len(args) == 2 && strings.HasPrefix(args[1], "-")) {
			return errors.New("sesh sync init takes one folder, or none: sesh sync init [folder]")
		}
		return syncInit(app, args[1:])
	case "join":
		if len(args) != 2 || strings.HasPrefix(args[1], "-") {
			return errors.New("sesh sync join takes the sync folder: sesh sync join <folder>")
		}
		return syncJoin(app, args[1])
	case "status", "leave":
		if len(args) > 1 {
			return fmt.Errorf("sesh sync %s takes nothing more, not %q", args[0], strings.Join(args[1:], " "))
		}
		if args[0] == "status" {
			return syncStatus(app)
		}
		return syncLeave(app)
	}
	return fmt.Errorf("sesh sync takes init, join, status or leave, or nothing, not %q", strings.Join(args, " "))
}

// errNotSyncing is a vault with no sync folder.
var errNotSyncing = errors.New("this vault doesn't sync: sesh sync init makes a sync folder from it, sesh sync join <folder> joins one")

// folderAwayError is a sync folder that isn't there now.
type folderAwayError struct{ dir string }

func (e *folderAwayError) Error() string {
	return fmt.Sprintf("the sync folder %s isn't there now: a drive not connected, or the folder moved", tildePath(e.dir))
}

// syncFolderOf is cfg's sync folder, checked to be one for this vault:
// its key record the vault's.
func syncFolderOf(cfg *config.Config) (syncfolder.Folder, error) {
	if cfg.SyncDir.Value == "" {
		return syncfolder.Folder{}, errNotSyncing
	}
	f := syncfolder.New(cfg.SyncDir.Value)
	// sync.dir set by hand, or in SESH_SYNC_DIR, is held to what init and
	// join hold it to.
	if err := checkSyncDir(f.Dir(), cfg.DBPath.Value); err != nil {
		return f, err
	}
	if _, err := os.Stat(f.Dir()); errors.Is(err, os.ErrNotExist) {
		return f, &folderAwayError{dir: f.Dir()}
	}
	info, err := f.ReadInfo()
	if errors.Is(err, syncfolder.ErrNoInfo) {
		switch lost, state, _ := lostInfo(f.Dir(), cfg.DBPath.Value); { //nolint:errcheck // what can't be told is said as the folder's own error, below
		case lost != nil:
			return f, fmt.Errorf("the sync folder %s lost its %s: %w", tildePath(f.Dir()), syncfolder.InfoFile, errInfoLost)
		case lostSaid(f.Dir(), state) != "":
			return f, errors.New(lostSaid(f.Dir(), state))
		}
	}
	if err != nil {
		return f, fmt.Errorf("the sync folder %s: %w", tildePath(f.Dir()), err)
	}
	m, err := database.ReadUnlockMaterial(cfg.DBPath.Value)
	if err != nil {
		return f, err
	}
	switch k, err := folderKeyOf(cfg.DBPath.Value, info, m); {
	case err != nil:
		return f, err
	case k == keyToSend:
		return f, errKeyToSend
	case k == keyChangedElsewhere:
		return f, errKeyChangedElsewhere
	case k == keyRolledBack:
		return f, errKeyRolledBack
	case k == keyFork:
		return f, errKeyFork
	case k == keyForged:
		return f, errKeyForged
	case k == keyOtherVault:
		return f, fmt.Errorf("the sync folder %s is for another master password than this vault's: a folder for other vaults", tildePath(f.Dir()))
	}
	return f, nil
}

// errInfoLost is a sync folder that lost its InfoFile, which a sync from
// this vault writes again.
var errInfoLost = errors.New("sesh sync writes it again from this vault, which synced with it")

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
	mended, err := mendInfo(cfg)
	if err != nil {
		return err
	}
	if mended {
		if _, err := fmt.Fprintf(app.Stdout, "The sync folder had lost its %s: written again from this vault, which synced with it.\n", syncfolder.InfoFile); err != nil {
			return err
		}
	}
	f, err := syncFolderOf(cfg)
	if errors.Is(err, errKeyRolledBack) {
		if err := mendRolledBack(app, cfg, f); err != nil {
			return err
		}
		f, err = syncFolderOf(cfg)
	}
	switch {
	case errors.Is(err, errKeyToSend):
		return sendPendingChange(app, cfg, f)
	case errors.Is(err, errKeyChangedElsewhere):
		return takeKeyChange(app, cfg, f)
	case errors.Is(err, errKeyFork):
		return settleFork(app, cfg, f)
	case err != nil:
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
	sum, err := syncStoreSum(cfg, f, store, syncRun{})
	if err != nil {
		return err
	}
	return writeSyncSummary(app, tildePath(f.Dir()), sum)
}

// syncStoreSum is syncStore run as run says, giving what the sync did.
func syncStoreSum(cfg *config.Config, f syncfolder.Folder, store *database.Store, run syncRun) (*vaultsync.Summary, error) {
	info, err := f.ReadInfo()
	if err != nil {
		return nil, fmt.Errorf("the sync folder %s: %w", tildePath(f.Dir()), err)
	}
	if err := checkSwitch(store, f, info); err != nil {
		return nil, err
	}
	// A folder other than the one the vault synced with starts afresh:
	// what was agreed with the other is no base for this one.
	if err := store.SyncStartFolder(info.FolderID); err != nil {
		return nil, err
	}
	// A change made here the folder has (its key record written, the
	// sync after it cut short): nothing waits to be sent, and the files
	// still sealed with an older key are sealed again below.
	prev, err := store.SyncKeyChange()
	if err != nil {
		return nil, err
	}
	if prev != "" {
		if err := store.SyncKeyChangeSent(); err != nil {
			return nil, err
		}
	}
	return syncOlderWith(store, cfg, f, prev, run)
}

// errOtherFolder is a vault with entries that synced with another sync
// folder, meeting one with files (sync.dir changed by hand).
var errOtherFolder = errors.New("this vault synced with another sync folder, and has entries this one holds files of too: synced here afresh, entries deleted elsewhere would come back, as edits. Point sync.dir back at the folder it synced with, or join this one with an empty vault (sesh sync join explains)")

// errNeverSynced is a vault with entries of its own, never synced, meeting
// a folder with files: as join refuses it.
var errNeverSynced = errors.New("this vault never synced with this folder and has entries of its own: synced here, any of them deleted elsewhere would come back, as edits. Join the folder with an empty vault instead (sesh sync join explains)")

// checkSwitch refuses to sync store with f, whose info is info, where join
// would refuse: the vault synced with another folder, or never synced, and
// has entries of its own (all but those restored from a backup, whose
// marks keep the folder's deletions), while the folder holds files, even
// unreadable ones. With nothing agreed between them, deletions in either
// would be undone. A new, empty folder starts afresh.
func checkSwitch(store *database.Store, f syncfolder.Folder, info *syncfolder.Info) error {
	have, err := store.SyncFolderID()
	if err != nil || have == info.FolderID {
		return err
	}
	items, err := store.SyncItems()
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(items, func(it database.SyncItem) bool {
		return it.Place != database.SyncGone && (have != "" || !it.Restored)
	}) {
		return nil
	}
	c, err := f.Scan()
	if err != nil {
		return err
	}
	if len(c.Files)+len(c.NotDownloaded)+len(c.Problems) == 0 {
		return nil
	}
	if have == "" {
		return errNeverSynced
	}
	return errOtherFolder
}

// infoState is why lostInfo can't say what a lost InfoFile was.
type infoState int

const (
	infoUnknown infoState = iota
	// infoWaiting: the folder's files aren't downloaded yet.
	infoWaiting
	// infoBehind: its files are sealed with this vault's key, but none is
	// one this vault agreed as it is: other computers synced since.
	infoBehind
)

// lostInfo is the InfoFile the sync folder at dir lost (a sync tool, or
// someone, deleted it), as the vault at dbPath, which synced with it, can
// write it again: the folder's ID it keeps, and its own key record. Only
// when the folder holds a file this vault agreed, as it is (its hash), and
// sealed with its key as it is now: a folder that merely shares the key
// (another vault made it) isn't this one, and a vault whose master
// password changed would lock the others out. When it can't, state says
// why, if it can tell.
func lostInfo(dir, dbPath string) (info *syncfolder.Info, state infoState, err error) {
	f := syncfolder.New(dir)
	if _, err := f.ReadInfo(); !errors.Is(err, syncfolder.ErrNoInfo) {
		return nil, infoUnknown, nil
	}
	if checkSyncDir(dir, dbPath) != nil {
		return nil, infoUnknown, nil
	}
	id, err := database.VaultSyncFolder(dbPath)
	if err != nil || id == "" {
		return nil, infoUnknown, err
	}
	c, err := f.Scan()
	if err != nil {
		return nil, infoUnknown, nil //nolint:nilerr // the caller says why the folder can't be read
	}
	m, err := database.ReadUnlockMaterial(dbPath)
	if err != nil {
		return nil, infoUnknown, err
	}
	store, err := database.Open(dbPath, nil)
	if err != nil {
		return nil, infoUnknown, err
	}
	defer closeAuditStore(store)
	items, err := store.SyncItems()
	if err != nil {
		return nil, infoUnknown, err
	}
	agreed := map[string]syncfolder.Hash{}
	for i := range items {
		if items[i].Agreed != nil {
			agreed[items[i].UID] = items[i].Agreed.Hash
		}
	}
	keyID := database.UnlockID(m.Verify)
	ours := func(file syncfolder.File) bool { return file.KeyIDString() == keyID }
	if !slices.ContainsFunc(c.Files, func(file syncfolder.File) bool {
		h, ok := agreed[file.UIDString()]
		return ok && h == file.Hash && ours(file)
	}) {
		// Files not downloaded yet may be the very ones it agreed: it waits
		// for them before saying it's behind.
		switch {
		case len(c.NotDownloaded) > 0:
			return nil, infoWaiting, nil
		case slices.ContainsFunc(c.Files, ours):
			return nil, infoBehind, nil
		}
		return nil, infoUnknown, nil
	}
	links, err := database.VaultKeyLinks(dbPath)
	if err != nil {
		return nil, infoUnknown, err
	}
	return syncfolder.InfoFor(id, syncfolder.KeyRecord{Salt: m.Salt, Verify: m.Verify, Params: m.Params}, links), infoUnknown, nil
}

// lostSaid says why a sync folder at dir with no InfoFile can't have it
// written again here, for state; "" when it can't tell.
func lostSaid(dir string, state infoState) string {
	switch state {
	case infoWaiting:
		return fmt.Sprintf("the sync folder %s has no %s, and its entry files aren't downloaded yet: keep the folder downloaded (in iCloud Drive, Control-click it and choose Keep Downloaded), then sesh sync can tell whether it's this vault's and write it again", tildePath(dir), syncfolder.InfoFile)
	case infoBehind:
		return fmt.Sprintf("the sync folder %s has no %s, and holds no entry file this vault agreed as it is: if it's the folder this vault synced with, other computers synced since, and sesh sync on one of them writes it again", tildePath(dir), syncfolder.InfoFile)
	}
	return ""
}

// mendInfo writes the sync folder's InfoFile again when it's lost and this
// vault can (lostInfo). It says whether it did.
func mendInfo(cfg *config.Config) (bool, error) {
	info, _, err := lostInfo(cfg.SyncDir.Value, cfg.DBPath.Value)
	if err != nil || info == nil {
		return false, err
	}
	if err := syncfolder.New(cfg.SyncDir.Value).WriteInfo(info); err != nil {
		return false, err
	}
	return true, nil
}

// writeSyncSummary says what a sync did; problems make it an error, after
// they're listed.
func writeSyncSummary(app *App, dir string, s *vaultsync.Summary) error {
	var warned strings.Builder
	for _, w := range s.Warnings {
		fmt.Fprintf(&warned, "  ⚠️  %s\n", w)
	}
	if s.Nothing() {
		_, err := fmt.Fprintf(app.Stdout, "✅ In sync with %s: nothing to do.\n%s", dir, warned.String())
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
	if s.Resealed > 0 {
		fmt.Fprintf(&b, "  %s sealed again with the new master password's key\n", nouns(s.Resealed, "entry's file", "entries' files"))
	}
	if s.Rewritten > 0 {
		fmt.Fprintf(&b, "  %s written again, not changed (lost from the folder, or an older copy put back)\n", nouns(s.Rewritten, "entry's file", "entries' files"))
	}
	for _, n := range s.Notes {
		fmt.Fprintf(&b, "  %s\n", n)
	}
	if s.EarlierKey > 0 {
		fmt.Fprintf(&b, "  ⚠️  %s\n", earlierKeySaid(s.EarlierKey))
	}
	if s.Later > 0 {
		fmt.Fprintf(&b, "  %s changed by another sesh command meanwhile: the next sync takes them\n", nouns(s.Later, "entry", "entries"))
	}
	b.WriteString(warned.String())
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
// it: the vault itself never goes where a sync tool copies it. Folders are
// compared as the file system finds them: through links, and in whatever
// case it ignores.
func checkSyncDir(dir, dbPath string) error {
	switch {
	case within(dbPath, dir):
		return fmt.Errorf("%s holds the vault itself; a sync folder must be somewhere else (a sync tool copying a live vault can damage it)", tildePath(dir))
	case within(dir, filepath.Dir(dbPath)):
		return fmt.Errorf("%s is inside the vault's own folder; choose a folder elsewhere", tildePath(dir))
	}
	return nil
}

// within says whether path is folder, or inside it. A folder that isn't
// there yet is compared by name.
func within(path, folder string) bool {
	path, folder = resolved(path), resolved(folder)
	fi, err := os.Stat(folder) //nolint:gosec // a folder the user named, only looked at
	if err != nil {
		rel, err := filepath.Rel(folder, path)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
	}
	for p := path; ; p = filepath.Dir(p) {
		if pi, err := os.Stat(p); err == nil && os.SameFile(pi, fi) { //nolint:gosec // its parents, only looked at
			return true
		}
		if filepath.Dir(p) == p {
			return false
		}
	}
}

// resolved is path with the links in the part of it that exists followed.
func resolved(path string) string {
	rest := ""
	for p := path; ; p = filepath.Dir(p) {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return filepath.Join(r, rest)
		}
		if filepath.Dir(p) == p {
			return path
		}
		rest = filepath.Join(filepath.Base(p), rest)
	}
}

// shellPath is dir as a command shown to be pasted names it: ~/ for the
// home folder, quoted for the shell.
func shellPath(dir string) string {
	t := tildePath(dir)
	if rest, ok := strings.CutPrefix(t, "~/"); ok {
		return "~/" + shell.Quote(rest)
	}
	return shell.Quote(t)
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
	if _, err := database.ReadUnlockMaterial(cfg.DBPath.Value); errors.Is(err, database.ErrNoVault) {
		return errors.New("there's no vault here yet: add an entry first, or join a sync folder another computer made (sesh sync join <folder>)")
	} else if err != nil {
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
		return fmt.Errorf("%s is a sync folder already: sesh sync join %s joins it", tildePath(dir), shellPath(dir))
	case !errors.Is(err, syncfolder.ErrNoInfo):
		return err
	}
	// Entry files without the info file: a sync folder that lost it, which
	// a new one would cut off from every computer syncing through it.
	if c, err := f.Scan(); err != nil {
		return err
	} else if len(c.Files)+len(c.NotDownloaded)+len(c.Problems) > 0 {
		return fmt.Errorf("%s holds entry files but no %s: a sync folder that lost it. On a computer that synced with it, sesh sync (or sesh sync join, once it has left) writes it again; or make a sync folder elsewhere", tildePath(dir), syncfolder.InfoFile)
	}
	// Unlocked first: a wrong master password leaves no folder made.
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	m, err := database.ReadUnlockMaterial(cfg.DBPath.Value)
	if err != nil {
		return err
	}
	info, err := syncfolder.NewInfo(syncfolder.KeyRecord{Salt: m.Salt, Verify: m.Verify, Params: m.Params})
	if err != nil {
		return err
	}
	if info.Links, err = store.SyncKeyLinks(); err != nil {
		return err
	}
	if err := f.WriteInfo(info); err != nil {
		return err
	}
	if err := setSyncDir(dir); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(app.Stdout, "Made the sync folder %s. On each other computer: sesh sync join %s\n", tildePath(dir), shellPath(dir)); err != nil {
		return err
	}
	cfg.SyncDir = config.Setting[string]{Value: dir, Source: config.FromFile}
	return syncStore(app, cfg, f, store)
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
	same := cfg.SyncDir.Value != "" && within(dir, cfg.SyncDir.Value) && within(cfg.SyncDir.Value, dir)
	if cfg.SyncDir.Value != "" && !same {
		return fmt.Errorf("this vault syncs with %s already (sesh sync leave stops that)", tildePath(cfg.SyncDir.Value))
	}
	if same {
		if _, err := fmt.Fprintf(app.Stdout, "This vault syncs with %s already.\n", tildePath(dir)); err != nil {
			return err
		}
		return syncWith(app, cfg)
	}
	if err := checkSyncDir(dir, cfg.DBPath.Value); err != nil {
		return err
	}
	f := syncfolder.New(dir)
	info, err := f.ReadInfo()
	// The folder this vault left, which lost its InfoFile meanwhile: it's
	// written again once the vault has joined.
	var lost *syncfolder.Info
	if errors.Is(err, syncfolder.ErrNoInfo) {
		var state infoState
		lost, state, _ = lostInfo(dir, cfg.DBPath.Value) //nolint:errcheck // what can't be told is said as the folder's own error
		switch {
		case lost != nil:
			info, err = lost, nil
		case lostSaid(dir, state) != "":
			return errors.New(lostSaid(dir, state))
		}
	}
	if err != nil {
		return fmt.Errorf("%s: %w", tildePath(dir), err)
	}
	m := database.UnlockMaterial{Salt: info.Key.Salt, Verify: info.Key.Verify, Params: info.Key.Params}
	// A vault that left this folder and changed its master password since:
	// it's switched to the folder's (decided with the user), and rejoins.
	_, err = database.CanJoin(cfg.DBPath.Value, m, info.FolderID)
	switchKey := errors.Is(err, database.ErrRejoinOtherKey)
	if err != nil && !switchKey {
		return joinRefused(err, dir)
	}
	// Its own change, made while syncing and not sent before it left: it
	// rejoins, and the change is sent.
	if prev, err := database.VaultKeyChange(cfg.DBPath.Value); err == nil && !switchKey && prev != "" && prev == database.UnlockID(m.Verify) {
		return rejoinSending(app, cfg, dir, f, m, info.FolderID)
	}
	// The password is checked against the folder before the vault is
	// touched: a wrong one changes nothing.
	pc := resolvePasswordPrompt().withKDF(cfg.KDF())
	pw, err := joinPassword(pc, dir, m)
	if err != nil {
		return err
	}
	defer secure.SecureZeroBytes(pw)
	// Only the folder's links that hold are kept: anyone with the folder
	// can add one.
	links := info.Links
	if len(links) > 0 {
		key := database.DeriveKey(pw, m.Salt, m.Params)
		links = database.VerifiedLinks(key, database.UnlockID(m.Verify), links)
		secure.SecureZeroBytes(key)
	}
	var notes []string
	if switchKey {
		said, err := switchToFolderKey(app, cfg, pw, m, links)
		if err != nil {
			return err
		}
		notes = append(notes, said...)
	}
	// An empty vault with a key record of its own is given the folder's:
	// what was set up for its own key stops working, and is said so.
	before, err := database.ReadUnlockMaterial(cfg.DBPath.Value)
	rekeyed := err == nil && database.UnlockID(before.Verify) != database.UnlockID(m.Verify)
	hadRecovery := false
	if rekeyed {
		if r, err := database.ReadRecovery(cfg.DBPath.Value); err == nil && r != nil {
			hadRecovery = true
		}
	}
	if err := os.MkdirAll(filepath.Dir(cfg.DBPath.Value), 0o700); err != nil { //nolint:gosec // the vault's folder, from the user's own settings
		return fmt.Errorf("create vault directory: %w", err)
	}
	prior, err := database.VaultSyncFolder(cfg.DBPath.Value)
	if err != nil {
		return err
	}
	rejoin, err := database.JoinVault(cfg.DBPath.Value, m, info.FolderID, links)
	if err != nil {
		return joinRefused(err, dir)
	}
	if lost != nil {
		if err := f.WriteInfo(lost); err != nil {
			return err
		}
		notes = append(notes, "The sync folder had lost its "+syncfolder.InfoFile+": written again from this vault, which synced with it.")
	}
	if rekeyed {
		if note := lockAgentHoldingOldKey(); note != "" {
			notes = append(notes, note)
		}
		if t, err := touchid.ReadFile(filepath.Dir(cfg.DBPath.Value)); err == nil && t.UnlockID != database.UnlockID(m.Verify) {
			notes = append(notes, "Touch ID unlock was set up for this vault's old master password; turn it on again with: sesh touchid enable")
		}
		if hadRecovery {
			notes = append(notes, "The recovery key made for this vault before doesn't open it now: the sync below says whether the other computers' does, and sesh recovery new makes one.")
		}
	}
	store, err := openSQLiteStoreWithPrompt(cfg, pc.withTypedPassword(pw))
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	if err := setSyncDir(dir); err != nil {
		return err
	}
	var said strings.Builder
	switch {
	case rejoin && prior == info.FolderID:
		fmt.Fprintf(&said, "Joined the sync folder %s again: what changed here and in the folder since this vault left is merged.\n", tildePath(dir))
	case rejoin:
		fmt.Fprintf(&said, "Joined the sync folder %s: the entries restored from a backup are merged with the folder's.\n", tildePath(dir))
	default:
		fmt.Fprintf(&said, "Joined the sync folder %s: the vault here opens with the same master password as the others.\n", tildePath(dir))
	}
	for _, n := range notes {
		said.WriteString(n + "\n")
	}
	if _, err := fmt.Fprint(app.Stdout, said.String()); err != nil {
		return err
	}
	cfg.SyncDir = config.Setting[string]{Value: dir, Source: config.FromFile}
	return syncStore(app, cfg, f, store)
}

// rejoinSending joins again the sync folder dir, f, whose key record is m
// and ID folderID, a vault that left it with a master password change made
// while syncing, not sent: the vault opens with its own, rejoins, and the
// change is sent.
func rejoinSending(app *App, cfg *config.Config, dir string, f syncfolder.Folder, m database.UnlockMaterial, folderID string) error {
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	if _, err := database.JoinVault(cfg.DBPath.Value, m, folderID, nil); err != nil {
		return joinRefused(err, dir)
	}
	if err := setSyncDir(dir); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(app.Stdout, "Joined the sync folder %s again: this computer's master password change, not sent before it left, goes to it now.\n", tildePath(dir)); err != nil {
		return err
	}
	cfg.SyncDir = config.Setting[string]{Value: dir, Source: config.FromFile}
	return sendPendingWith(app, cfg, f, store)
}

// switchToFolderKey switches the vault cfg names, which left the sync
// folder whose key record is m and changed its master password since, to
// m: it asks for the vault's own master password, then re-encrypts it
// under the key pw, the folder's, gives. It says what it did.
func switchToFolderKey(app *App, cfg *config.Config, pw []byte, m database.UnlockMaterial, links []syncfolder.KeyLink) ([]string, error) {
	if _, err := fmt.Fprintln(app.Stderr, "This vault's master password and the folder's differ (one changed while it was away): type this vault's own, to switch it to the folder's."); err != nil {
		return nil, err
	}
	// Opened with the password typed, not the agent: the old key goes in a
	// link to the folder's, so anything sealed with it goes on opening.
	src := resolvePasswordPrompt().withKDF(cfg.KDF()).newSource(cfg.DBPath.Value)
	store, err := openStoreWith(cfg.DBPath.Value, database.NewKeySourceOracle(src))
	if err != nil {
		return nil, fmt.Errorf("%w (without this vault's own master password it can't switch; move its files aside and join with a new vault instead)", err)
	}
	defer closeAuditStore(store)
	ownKey, err := src.GetEncryptionKey()
	if err != nil {
		return nil, err
	}
	defer secure.SecureZeroBytes(ownKey)
	own, err := database.ReadUnlockMaterial(cfg.DBPath.Value)
	if err != nil {
		return nil, err
	}
	ownID, folderID := database.UnlockID(own.Verify), database.UnlockID(m.Verify)
	mine, err := store.SyncKeyLinks()
	if err != nil {
		return nil, err
	}
	key := database.DeriveKey(pw, m.Salt, m.Params)
	defer secure.SecureZeroBytes(key)
	link, err := database.NewKeyLink(ownKey, key, ownID, folderID)
	if err != nil {
		return nil, err
	}
	_, notes, err := rekeyTo(store, cfg.DBPath.Value, ownID, key, m, true, database.RekeyOptions{Sync: database.RekeyAdopt, Links: database.UnionLinks(mine, links), Link: link}, nil)
	if err != nil {
		return nil, err
	}
	// The folder's changes lead from this vault's key: only the folder's
	// changed. Otherwise this vault's own did, and isn't kept.
	said := []string{"This vault opens with the folder's master password now; a change made to its own while it was away isn't kept."}
	if slices.ContainsFunc(links, func(l syncfolder.KeyLink) bool { return l.From == ownID }) {
		said = []string{"The folder's master password changed while this vault was away: it opens with that one now."}
	}
	for _, n := range []string{notes.agent, notes.touch, notes.recovery, notes.file} {
		if n != "" {
			said = append(said, n)
		}
	}
	return said, nil
}

// joinRefused is err from readying the vault to join dir, with what to do
// when it has entries.
func joinRefused(err error, dir string) error {
	if errors.Is(err, database.ErrVaultNotEmpty) {
		return fmt.Errorf("%w. Joining takes a new or empty vault, or one joining again the folder it left. To bring its entries along: sesh export --file F, move the vault's files aside (the vault, any -wal and -shm files beside it, and touchid.key), sesh sync join %s, then sesh import --from sesh F (entries deleted elsewhere since this vault last synced come back, as new ones)", err, shellPath(dir))
	}
	return err
}

// joinPassword asks for the master password of the vaults syncing through
// dir until it opens m, their key record (folderPassword).
func joinPassword(pc passwordPromptConfig, dir string, m database.UnlockMaterial) ([]byte, error) {
	if !pc.fromEnv && !pc.interactive {
		return nil, errors.New("there's no terminal here to type the master password at (the one the vaults syncing through the folder share): run sesh sync join at one, or give it in SESH_MASTER_PASSWORD")
	}
	return folderPassword(pc, fmt.Sprintf("Master password of the vaults syncing through %s: ", tildePath(dir)), m)
}

// folderPassword asks, with ask, for the master password whose key record
// is m until it opens it: three tries at a terminal, one otherwise. The
// caller zeroes it.
func folderPassword(pc passwordPromptConfig, ask string, m database.UnlockMaterial) ([]byte, error) {
	tries := 1
	if pc.interactive {
		tries = interactivePasswordAttempts
	}
	prompt := ask
	for i := 1; ; i++ {
		pw, err := pc.prompt(prompt)
		if err != nil {
			return nil, fmt.Errorf("read password: %w", err)
		}
		err = database.CheckMasterPassword(pw, m)
		if err == nil {
			return pw, nil
		}
		secure.SecureZeroBytes(pw)
		if i == tries {
			return nil, err
		}
		prompt = fmt.Sprintf("Wrong password, try again (%d/%d). %s", i+1, tries, ask)
	}
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
	if vaultMissing(cfg.DBPath.Value) {
		fmt.Fprintf(&b, "❌ There's no vault here yet: sesh sync join %s makes it from the folder\n", shellPath(cfg.SyncDir.Value))
		_, err := fmt.Fprint(app.Stdout, b.String())
		return err
	}
	f, folderErr := syncFolderOf(cfg)
	switch {
	case errors.Is(folderErr, errInfoLost), errors.Is(folderErr, errKeyToSend), errors.Is(folderErr, errKeyChangedElsewhere), errors.Is(folderErr, errKeyRolledBack), errors.Is(folderErr, errKeyFork):
		fmt.Fprintf(&b, "⚠️  %v\n", folderErr)
	case folderErr != nil:
		fmt.Fprintf(&b, "❌ %v\n", folderErr)
	}
	store, err := database.Open(cfg.DBPath.Value, nil)
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	var folder *syncfolder.Folder
	if folderErr == nil {
		folder = &f
	}
	w, err := syncWaitingIn(store, folder)
	if err != nil {
		return err
	}
	if w.last != nil {
		fmt.Fprintf(&b, "Last synced:   %s (%s)\n", w.last.CreatedAt.Local().Format("2006-01-02 15:04"), strings.TrimPrefix(w.last.Detail, "Sync: "))
	}
	fmt.Fprintf(&b, "Changed here, to send:          %d\n", w.toSend)
	if recoveryChanged(cfg) {
		b.WriteString("Recovery key:                  changed here, to send\n")
	}
	if c := w.contents; c != nil {
		fmt.Fprintf(&b, "Changed in the folder, to take: %d\n", w.toTake)
		if info, err := f.ReadInfo(); err != nil {
			fmt.Fprintf(&b, "❌ %v\n", err)
		} else if err := checkSwitch(store, f, info); err != nil {
			fmt.Fprintf(&b, "❌ %v\n", err)
		}
		if w.otherKey > 0 {
			fmt.Fprintf(&b, "⚠️  %s\n", otherKeySaid(w.otherKey))
		}
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

// syncWaiting is what's waiting to sync, read without unlocking the vault.
type syncWaiting struct {
	// last is the last sync, as the audit log has it: nil when it has
	// none (never synced, or pruned since).
	last *database.AuditEntry
	// contents is what the folder holds; nil when it wasn't read.
	contents *syncfolder.Contents
	// toSend are entries changed here; toTake, files changed in the
	// folder; otherKey, files sealed with another master password's key,
	// which sync leaves alone.
	toSend, toTake, otherKey int
	// synced says the vault has agreed entries with a folder before.
	synced bool
}

// syncWaitingIn is what's waiting between store and f; with f nil, only
// what's waiting here.
func syncWaitingIn(store *database.Store, f *syncfolder.Folder) (*syncWaiting, error) {
	w := &syncWaiting{}
	items, err := store.SyncItems()
	if err != nil {
		return nil, err
	}
	agreed := map[string]syncfolder.Hash{}
	for i := range items {
		if items[i].Changed() {
			w.toSend++
		}
		if items[i].Agreed != nil {
			agreed[items[i].UID] = items[i].Agreed.Hash
			w.synced = true
		}
	}
	if w.last, err = store.LastAuditEvent("sync"); err != nil {
		return nil, err
	}
	if f == nil {
		return w, nil
	}
	if w.contents, err = f.Scan(); err != nil {
		return nil, err
	}
	keyID, err := store.SyncKeyID()
	if err != nil {
		return nil, err
	}
	for _, file := range w.contents.Files {
		switch h, ok := agreed[file.UIDString()]; {
		case file.KeyIDString() != keyID:
			w.otherKey++
		case !ok || h != file.Hash:
			w.toTake++
		}
	}
	return w, nil
}

// earlierKeySaid says n entries had a file sealed with an earlier master
// password's key, not the one agreed: not taken.
func earlierKeySaid(n int) string {
	return fmt.Sprintf("%s a file sealed with an earlier master password's key, not the one agreed: not taken, as anyone who knew that password could have written it, and written over, or removed if this computer never had the entry. A computer of yours that changed one before taking the new password sends the change again once it does", nouns(n, "entry had", "entries had"))
}

// otherKeySaid says n files are sealed with another master password's key.
func otherKeySaid(n int) string {
	if n == 1 {
		return "1 entry's file is sealed with another master password's key: sync leaves it for the computer that wrote it"
	}
	return nouns(n, "entry's file is", "entries' files are") + " sealed with another master password's key: sync leaves them for the computers that wrote them"
}

// syncLeave is sesh sync leave: the vault stops syncing. Its entries, what
// it agreed with the folder, and the folder stay, so joining the folder
// again merges what changed meanwhile.
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
	if err := setSyncDir(""); err != nil {
		return err
	}
	said := fmt.Sprintf("This vault no longer syncs with %s. Its entries are as they were, and so is the folder for the other computers; sesh sync join %s joins it again, merging what changed meanwhile.\n", tildePath(cfg.SyncDir.Value), shellPath(cfg.SyncDir.Value))
	if prev, err := database.VaultKeyChange(cfg.DBPath.Value); err == nil && prev != "" {
		said += "This computer's master password change hasn't reached the folder: joining it again sends it.\n"
	}
	_, err = fmt.Fprint(app.Stdout, said)
	return err
}
