package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/syncfolder"
	"github.com/bashhack/sesh/internal/vaultsync"
)

// autoSyncCommands are the commands that sync on their own while sync.auto
// is on (decided with the user): as they open the vault, so they see what
// changed on the other computers, and after they change it. The sync
// commands, a master password change, recovery and restore sync as they
// go, and sesh ui as it runs; the others don't open the vault to use its
// entries.
var autoSyncCommands = map[string]bool{
	"list": true, "search": true, "copy": true, "get": true, "code": true, "show": true, "open": true,
	"add": true, "edit": true, "trash": true, "history": true, "folder": true, "tag": true,
	"import": true, "export": true, "health": true, "run": true, "inject": true, "aws": true,
	"git-credential": true,
}

// autoSyncNext says the next vault this run opens is its command's own, to
// sync as it's opened; run sets it for autoSyncCommands.
var autoSyncNext bool

// autoSyncOut is where an automatic sync says what it did: stderr, so a
// command's own output stays as it is. Tests replace it.
var autoSyncOut io.Writer = os.Stderr

// autoSynced are the vaults opened for their commands and synced, with
// their settings and what the sync said: each syncs again as it's closed,
// if it changed.
var autoSynced = map[*database.Store]*autoSyncState{}

// autoSyncState is a command's vault as its automatic sync left it.
type autoSyncState struct {
	cfg *config.Config
	// said is what was said already, not said again; stuck, that the
	// folder didn't answer as the vault was opened, so it isn't waited
	// for again as it's closed.
	said  map[string]bool
	stuck bool
}

// autoSyncOpened syncs store, the vault cfg names, just opened, when it's
// the command's own and sync.auto is on.
func autoSyncOpened(cfg *config.Config, store *database.Store) {
	if !autoSyncNext {
		return
	}
	autoSyncNext = false
	if cfg.SyncDir.Value == "" || !cfg.SyncAuto.Value {
		return
	}
	st := &autoSyncState{cfg: cfg, said: map[string]bool{}}
	autoSynced[store] = st
	lines, stuck, _ := autoSyncRun(cfg, store)
	st.stuck = stuck
	st.say(freshLines(store, lines))
}

// autoSyncClosing syncs store again as it's closed, when it was synced as
// it was opened and has changes the sync folder doesn't.
func autoSyncClosing(store *database.Store) {
	st, ok := autoSynced[store]
	if !ok {
		return
	}
	delete(autoSynced, store)
	if !st.stuck && vaultHasChanges(st.cfg, store) {
		lines, _, _ := autoSyncRun(st.cfg, store)
		st.say(freshLines(store, lines))
	}
}

// warnAgainAfter is how long a warning an automatic sync said isn't said
// again, unchanged (decided with the user).
const warnAgainAfter = 24 * time.Hour

// freshLines are lines, an automatic sync's for the vault open in store,
// but the warnings and problems (⚠️, ❌) it said in the last
// warnAgainAfter. A folder not answering is said each time: what synced
// waited for it.
func freshLines(store *database.Store, lines []string) []string {
	var out []string
	now := time.Now()
	for _, l := range lines {
		if (strings.HasPrefix(l, "⚠️") || strings.HasPrefix(l, "❌")) && !strings.Contains(l, notAnswering) {
			if fresh, err := store.SyncWarnFresh(l, warnAgainAfter, now); err == nil && !fresh {
				continue
			}
		}
		out = append(out, l)
	}
	return out
}

// say writes lines, but those said already.
func (st *autoSyncState) say(lines []string) {
	for _, l := range lines {
		if !st.said[l] {
			st.said[l] = true
			fmt.Fprintln(autoSyncOut, l) //nolint:errcheck // best-effort note
		}
	}
}

// vaultHasChanges says whether the vault open in store has changes the sync
// folder cfg names doesn't: entries changed here, or its recovery key.
func vaultHasChanges(cfg *config.Config, store *database.Store) bool {
	items, err := store.SyncItems()
	if err != nil {
		return true
	}
	for i := range items {
		if items[i].Changed() {
			return true
		}
	}
	return recoveryChanged(cfg)
}

// autoSyncsRun counts automatic syncs, for tests.
var autoSyncsRun int

// autoSyncBudget is how long an automatic sync may take (decided with the
// user): a folder that doesn't answer in it is left for the next sync, and
// a sync running past it leaves the entries not reached for the next.
var autoSyncBudget = 5 * time.Second

// notAnswering is in what an automatic sync says of a folder that didn't
// answer.
const notAnswering = "didn't answer in"

// autoSyncRun syncs store, the vault cfg names, with its sync folder,
// asking nothing and within autoSyncBudget, and says in a line or two what
// moved, if anything did; a sync that fails never stops the command.
// stuck says the folder didn't answer, ran that entries were synced.
func autoSyncRun(cfg *config.Config, store *database.Store) (lines []string, stuck, ran bool) {
	autoSyncsRun++
	deadline := time.Now().Add(autoSyncBudget)
	switch answered, waited := answers(cfg.SyncDir.Value, autoSyncBudget); {
	case !answered && waited:
		return []string{fmt.Sprintf("⚠️  Sync: the sync folder %s %s %s; nothing synced (sesh sync waits for it).", tildePath(cfg.SyncDir.Value), notAnswering, autoSyncBudget)}, true, false
	case !answered:
		return []string{fmt.Sprintf("⚠️  Sync: the sync folder %s still hasn't answered; nothing synced (sesh sync waits for it).", tildePath(cfg.SyncDir.Value))}, true, false
	}
	lines, ran = autoSyncChecked(cfg, store, deadline)
	return lines, false, ran
}

// autoSyncChecked is autoSyncRun once the folder has answered.
func autoSyncChecked(cfg *config.Config, store *database.Store, deadline time.Time) (lines []string, ran bool) {
	var mended bytes.Buffer
	quiet := &App{Stdin: bytes.NewReader(nil), Stdout: &mended, Stderr: io.Discard, Exit: func(int) {}}
	if lost, err := mendInfo(cfg); err == nil && lost {
		lines = append(lines, "Sync: the sync folder had lost its sesh-sync.json, written again from this vault.")
	}
	f, err := syncFolderOf(cfg)
	if errors.Is(err, errKeyRolledBack) {
		if err := mendRolledBack(quiet, cfg, f); err != nil {
			return append(lines, "⚠️  Sync: "+err.Error()), false
		}
		if said := strings.TrimSpace(mended.String()); said != "" {
			lines = append(lines, "Sync: "+said)
		}
		f, err = syncFolderOf(cfg)
	}
	if errors.Is(err, errKeyFork) {
		// This computer's change kept: settled as sesh sync settles it,
		// asking nothing. The other's: taking it asks for its password.
		kept, ferr := keptOwnFork(cfg, f)
		if ferr != nil {
			return append(lines, "⚠️  Sync: "+ferr.Error()), false
		}
		if !kept {
			return append(lines, "⚠️  Sync: the master password was changed here and on another computer at once, and the other's is kept; nothing syncs until sesh sync takes it."), false
		}
		lines = append(lines, "Sync: "+ownForkKeptSaid)
		f, err = syncFolderOf(cfg)
	}
	var away *folderAwayError
	switch {
	case errors.As(err, &away):
		// A drive not connected: sesh sync status and doctor say so.
		return lines, false
	case errors.Is(err, errKeyChangedElsewhere):
		// Taking it asks for the new password: left to sesh sync.
		return append(lines, "⚠️  Sync: the master password was changed on another computer; nothing syncs until sesh sync takes it."), false
	case errors.Is(err, errKeyToSend):
		info, rerr := f.ReadInfo()
		rec, merr := database.ReadUnlockMaterial(cfg.DBPath.Value)
		if err := errors.Join(rerr, merr); err != nil {
			return append(lines, "⚠️  Sync: "+err.Error()), false
		}
		sum, err := sendWith(store, cfg, f, info, rec)
		if err != nil {
			return append(lines, "⚠️  Sync: "+err.Error()), false
		}
		lines = append(lines, "Sync: sent this computer's master password change; the other computers ask for it at their next sync.")
		return append(lines, autoSummary(sum)...), true
	case err != nil:
		return append(lines, "⚠️  Sync: "+err.Error()), false
	}
	sum, err := syncStoreSum(cfg, f, store, syncRun{deadline: deadline, auto: true})
	if err != nil {
		return append(lines, "⚠️  Sync: "+err.Error()), false
	}
	return append(lines, autoSummary(sum)...), true
}

// keptOwnFork settles the fork in the sync folder f, of the vault cfg
// names, when this vault's change is the one kept, and says whether it is.
func keptOwnFork(cfg *config.Config, f syncfolder.Folder) (bool, error) {
	info, err := f.ReadInfo()
	if err != nil {
		return false, err
	}
	m, err := database.ReadUnlockMaterial(cfg.DBPath.Value)
	if err != nil {
		return false, err
	}
	if forkKept(database.UnlockID(info.Key.Verify), database.UnlockID(m.Verify)) {
		return false, nil
	}
	return true, keepOwnFork(cfg, f, info, m)
}

// probing are the folders an answers is still waiting on.
var probing = struct {
	dirs map[string]bool
	sync.Mutex
}{dirs: map[string]bool{}}

// readDir reads a folder, for answers; tests make one that doesn't answer.
var readDir = os.ReadDir

// answers says whether the folder dir answers within limit: a stuck
// network mount, say, doesn't. What's left waiting for it ends with the
// command.
// waited says it waited for it: not when an earlier look is still
// waiting.
func answers(dir string, limit time.Duration) (answered, waited bool) {
	// One still waiting on it means it isn't answering: no other is
	// started, to wait beside it.
	probing.Lock()
	if probing.dirs[dir] {
		probing.Unlock()
		return false, false
	}
	probing.dirs[dir] = true
	probing.Unlock()
	done, read := make(chan struct{}), readDir
	go func() {
		_, _ = read(dir) //nolint:errcheck // only how long it takes
		probing.Lock()
		delete(probing.dirs, dir)
		probing.Unlock()
		close(done)
	}()
	select {
	case <-done:
		return true, true
	case <-time.After(limit):
		return false, true
	}
}

// autoSummary says what a sync did in a line, its notes, warnings and
// problems after it; nothing when nothing moved.
func autoSummary(s *vaultsync.Summary) []string {
	var parts []string
	count := func(n int, what string) {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, what))
		}
	}
	count(len(s.Received), "taken")
	count(len(s.Sent), "sent")
	count(len(s.Merged), "changed on both, merged")
	// Named: a command naming one of them may now find the other.
	if n := len(s.Renamed); n > 0 {
		parts = append(parts, fmt.Sprintf("%d renamed, made on two computers under one name (%s)", n, strings.Join(s.Renamed, ", ")))
	}
	if n := len(s.Joined); n > 0 {
		parts = append(parts, fmt.Sprintf("%d made on two computers with one secret, made one (%s)", n, strings.Join(s.Joined, ", ")))
	}
	var lines []string
	if len(parts) > 0 {
		lines = append(lines, "Synced: "+strings.Join(parts, ", ")+".")
	}
	if s.EarlierKey > 0 {
		lines = append(lines, "⚠️  Sync: "+earlierKeySaid(s.EarlierKey)+".")
	}
	if n := len(s.SetBack); n > 0 {
		lines = append(lines, "⚠️  Sync: "+setBackSaid(n, strings.Join(s.SetBack, ", "))+".")
	}
	if n := len(s.HeldBack); n > 0 {
		lines = append(lines, "⚠️  Sync: "+heldBackSaid(n, strings.Join(s.HeldBack, ", "))+".")
	}
	if s.Unfinished > 0 {
		lines = append(lines, "Sync: out of time; the next sync finishes it.")
	}
	lines = append(lines, s.Notes...)
	for _, w := range s.Warnings {
		lines = append(lines, "⚠️  "+w)
	}
	// Each said: some (a merge that couldn't keep both notes) are met only
	// once, and sesh sync wouldn't say them again.
	for _, p := range s.Problems {
		lines = append(lines, "❌ Sync: "+p)
	}
	return lines
}
