package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bashhack/sesh/internal/backup"
	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/tui"
)

// uiBackups is the backups of the vault at dbPath, newest first, as sesh
// restore lists them: another vault's with the same file name included,
// and marked.
func uiBackups(dbPath string) (tui.Backups, error) {
	st, err := settingsOf(dbPath)
	if err != nil {
		return tui.Backups{}, err
	}
	dir := st.BackupFolder()
	all, ids, err := backup.ListAny(dir, dbPath)
	if err != nil {
		return tui.Backups{}, err
	}
	mine, _ := database.VaultID(dbPath) //nolint:errcheck // "" when the vault can't be read; then none is marked
	bs := tui.Backups{Dir: tildePath(dir)}
	for i, b := range all {
		bs.List = append(bs.List, tui.Backup{
			Made: b.Made, Path: b.Path, Name: filepath.Base(b.Path), Size: vaultSize(b.Size),
			Other: mine != "" && !strings.HasPrefix(mine, ids[i]),
		})
	}
	return bs, nil
}

// uiBackUp backs up the vault at dbPath, as sesh backup does: into the
// backups folder when to is "", pruned to backup.keep, or to the file (or
// into the folder) to names, replacing a file there only when replace.
func uiBackUp(dbPath, to string, replace bool) (string, error) {
	st, err := settingsOf(dbPath)
	if err != nil {
		return "", err
	}
	var b backup.Info
	if to == "" {
		s, err := backup.SeriesOf(dbPath, st.BackupFolder())
		if err != nil {
			return "", err
		}
		if b, err = s.Make(dbPath, now()); err != nil {
			return "", err
		}
		if _, err := s.Prune(st.BackupKeep.Value); err != nil {
			return "", err
		}
	} else {
		// ~/ is expanded; a relative path is from where sesh ui started.
		dest, err := config.ResolvePath(to)
		if err != nil {
			if dest, err = filepath.Abs(to); err != nil {
				return "", fmt.Errorf("find %s: %w", to, err)
			}
		}
		b, err = backup.MakeTo(dbPath, dest, replace, now())
		if errors.Is(err, os.ErrExist) {
			return "", tui.Exists(tildePath(dest) + " already exists.")
		}
		if err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("Backed up the vault to %s (%s).", tildePath(b.Path), vaultSize(b.Size)), nil
}

// uiDeleteBackup deletes the backup at path, one listed for the vault at
// dbPath.
func uiDeleteBackup(dbPath, path string) (string, error) {
	st, err := settingsOf(dbPath)
	if err != nil {
		return "", err
	}
	if err := backup.Remove(st.BackupFolder(), dbPath, path); err != nil {
		return "", err
	}
	return "Deleted the backup " + filepath.Base(path) + ".", nil
}

// uiPlanRestore says what restoring the vault at dbPath from the backup at
// path will do, as sesh restore asks.
func uiPlanRestore(dbPath, path string) (string, error) {
	st, err := settingsOf(dbPath)
	if err != nil {
		return "", err
	}
	p, err := planRestore(st, path)
	if err != nil {
		return "", err
	}
	if p.whole {
		return "", errCantRestoreHere
	}
	return strings.TrimSpace(p.question), nil
}

// errCantRestoreHere is a vault missing or damaged, which the app can't
// have open to restore it in place.
var errCantRestoreHere = tui.Refused("the vault can't be read as it is, so it's restored from the command line: sesh restore")

// uiRestore restores the vault at dbPath from the backup at path in place,
// as sesh restore does, backing it up as it is first.
func uiRestore(dbPath, path string) (string, error) {
	st, err := settingsOf(dbPath)
	if err != nil {
		return "", err
	}
	p, err := planRestore(st, path)
	if err != nil {
		return "", err
	}
	if p.whole {
		return "", errCantRestoreHere
	}
	said, err := p.run(st)
	return strings.Join(strings.Fields(strings.ReplaceAll(said, "✅ ", "")), " "), err
}
