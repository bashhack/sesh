package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
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
// their settings: each syncs again as it's closed, if it changed.
var autoSynced = map[*database.Store]*config.Config{}

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
	autoSynced[store] = cfg
	autoSync(cfg, store)
}

// autoSyncClosing syncs store again as it's closed, when it was synced as
// it was opened and has changes the sync folder doesn't.
func autoSyncClosing(store *database.Store) {
	cfg, ok := autoSynced[store]
	if !ok {
		return
	}
	delete(autoSynced, store)
	if vaultHasChanges(cfg, store) {
		autoSync(cfg, store)
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

// autoSync syncs store, the vault cfg names, with its sync folder, asking
// nothing, and says in a line or two what moved, if anything did; a sync
// that fails never stops the command.
func autoSync(cfg *config.Config, store *database.Store) {
	for _, l := range autoSyncLines(cfg, store) {
		fmt.Fprintln(autoSyncOut, l) //nolint:errcheck // best-effort note
	}
}

// autoSyncLines is autoSync's sync, and what it says.
func autoSyncLines(cfg *config.Config, store *database.Store) []string {
	var lines []string
	quiet := &App{Stdin: bytes.NewReader(nil), Stdout: io.Discard, Stderr: io.Discard, Exit: func(int) {}}
	if mended, err := mendInfo(cfg); err == nil && mended {
		lines = append(lines, "Sync: the sync folder had lost its sesh-sync.json, written again from this vault.")
	}
	f, err := syncFolderOf(cfg)
	if errors.Is(err, errKeyRolledBack) {
		if err := mendRolledBack(quiet, cfg, f); err != nil {
			return append(lines, "⚠️  Sync: "+err.Error())
		}
		f, err = syncFolderOf(cfg)
	}
	var away *folderAwayError
	switch {
	case errors.As(err, &away):
		// A drive not connected: sesh sync status and doctor say so.
		return lines
	case errors.Is(err, errKeyChangedElsewhere), errors.Is(err, errKeyFork):
		// Taking it asks for the new password: left to sesh sync.
		return append(lines, "⚠️  Sync: the master password was changed on another computer; nothing syncs until sesh sync takes it.")
	case errors.Is(err, errKeyToSend):
		info, rerr := f.ReadInfo()
		rec, merr := database.ReadUnlockMaterial(cfg.DBPath.Value)
		if err := errors.Join(rerr, merr); err != nil {
			return append(lines, "⚠️  Sync: "+err.Error())
		}
		sum, err := sendWith(store, cfg, f, info, rec)
		if err != nil {
			return append(lines, "⚠️  Sync: "+err.Error())
		}
		lines = append(lines, "Sync: sent this computer's master password change; the other computers ask for it at their next sync.")
		return append(lines, autoSummary(sum)...)
	case err != nil:
		return append(lines, "⚠️  Sync: "+err.Error())
	}
	sum, err := syncStoreSum(cfg, f, store)
	if err != nil {
		return append(lines, "⚠️  Sync: "+err.Error())
	}
	return append(lines, autoSummary(sum)...)
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
	count(len(s.Renamed), "renamed (made on two computers under one name)")
	count(len(s.Joined), "made one (made on two computers with one secret)")
	count(s.NotDownloaded, "waiting for the sync tool to download")
	var lines []string
	if len(parts) > 0 {
		lines = append(lines, "Synced: "+strings.Join(parts, ", ")+".")
	}
	lines = append(lines, s.Notes...)
	for _, w := range s.Warnings {
		lines = append(lines, "⚠️  "+w)
	}
	if n := len(s.Problems); n > 0 {
		lines = append(lines, fmt.Sprintf("❌ Sync: %s; sesh sync says what.", nouns(n, "problem", "problems")))
	}
	return lines
}
