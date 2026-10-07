// Package backup keeps copies of the vault: made by name and time in a
// folder, listed newest first, and pruned to a number kept.
package backup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/database"
)

// stamp is the time in a backup's name: UTC, so names sort by time.
const stamp = "2006-01-02T150405Z"

// Info is a backup: its file, when it was made, and its size in bytes.
type Info struct {
	Made time.Time
	Path string
	Size int64
}

// nameParts are what a backup of the vault at vaultPath is named with:
// passwords.db's are passwords-<stamp>.db.
func nameParts(vaultPath string) (prefix, ext string) {
	base := filepath.Base(vaultPath)
	ext = filepath.Ext(base)
	prefix = strings.TrimSuffix(base, ext) + "-"
	if ext == "" {
		ext = ".db"
	}
	return prefix, ext
}

// Name is the file name of the backup of the vault at vaultPath made at t.
func Name(vaultPath string, t time.Time) string {
	prefix, ext := nameParts(vaultPath)
	return prefix + t.UTC().Format(stamp) + ext
}

// List returns the backups of the vault at vaultPath in dir, newest first:
// the files named as Name names them, and nothing else. A missing dir
// holds none.
func List(dir, vaultPath string) ([]Info, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list backups in %s: %w", dir, err)
	}
	prefix, ext := nameParts(vaultPath)
	var out []Info
	for _, e := range entries {
		name := e.Name()
		middle, ok := strings.CutPrefix(name, prefix)
		if !ok || !e.Type().IsRegular() {
			continue
		}
		middle, ok = strings.CutSuffix(middle, ext)
		if !ok {
			continue
		}
		made, err := time.Parse(stamp, middle)
		if err != nil {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, Info{Path: filepath.Join(dir, name), Made: made, Size: info.Size()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Made.After(out[j].Made) })
	return out, nil
}

// Due reports whether the newest backup in dir is everyDays or more old,
// or there's none. everyDays 0 means never.
func Due(dir, vaultPath string, everyDays int, now time.Time) (bool, error) {
	if everyDays <= 0 {
		return false, nil
	}
	all, err := List(dir, vaultPath)
	if err != nil || len(all) == 0 {
		return err == nil, err
	}
	return !all[0].Made.After(now.Add(-time.Duration(everyDays) * 24 * time.Hour)), nil
}

// Make backs up the vault at vaultPath into dir (made private if new),
// named for now. If another sesh made that backup in the same second, its
// copy stands.
func Make(vaultPath, dir string, now time.Time) (Info, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Info{}, fmt.Errorf("create the backups folder %s: %w", dir, err)
	}
	dest := filepath.Join(dir, Name(vaultPath, now))
	if err := write(vaultPath, dest, false); err != nil && !errors.Is(err, os.ErrExist) {
		return Info{}, err
	}
	return stat(dest, now)
}

// MakeTo backs up the vault at vaultPath to the file dest, refusing to
// replace one that exists unless force.
func MakeTo(vaultPath, dest string, force bool, now time.Time) (Info, error) {
	if err := write(vaultPath, dest, force); err != nil {
		if errors.Is(err, os.ErrExist) {
			return Info{}, fmt.Errorf("%s already exists; add --force to replace it", dest)
		}
		return Info{}, err
	}
	return stat(dest, now)
}

// write copies the vault to dest through a file beside it, renamed into
// place, so a copy cut short never stands as a backup. It's an error
// wrapping os.ErrExist when dest exists and replace is false.
func write(vaultPath, dest string, replace bool) error {
	if _, err := os.Lstat(dest); err == nil && !replace {
		return fmt.Errorf("%s: %w", dest, os.ErrExist)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), "."+filepath.Base(dest)+".*.tmp")
	if err != nil {
		return fmt.Errorf("make the backup: %w", err)
	}
	tmpPath := tmp.Name()
	// VACUUM INTO writes a file that doesn't exist yet.
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("make the backup: %w", err)
	}
	if err := os.Remove(tmpPath); err != nil {
		return fmt.Errorf("make the backup: %w", err)
	}
	defer func() { _ = os.Remove(tmpPath) }() //nolint:errcheck // gone once renamed
	if err := database.CopyTo(vaultPath, tmpPath); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("make the backup private: %w", err)
	}
	if !replace {
		// Link refuses an existing name where rename would replace it.
		if err := os.Link(tmpPath, dest); err != nil {
			if errors.Is(err, os.ErrExist) {
				return fmt.Errorf("%s: %w", dest, os.ErrExist)
			}
			return fmt.Errorf("save the backup as %s: %w", dest, err)
		}
		return nil
	}
	if err := os.Rename(tmpPath, dest); err != nil {
		return fmt.Errorf("save the backup as %s: %w", dest, err)
	}
	return nil
}

func stat(path string, made time.Time) (Info, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Info{}, fmt.Errorf("read the backup: %w", err)
	}
	return Info{Path: path, Made: made.UTC().Truncate(time.Second), Size: info.Size()}, nil
}

// Prune removes all but the newest keep backups of the vault at vaultPath
// in dir, returning those removed.
func Prune(dir, vaultPath string, keep int) ([]Info, error) {
	all, err := List(dir, vaultPath)
	if err != nil || len(all) <= keep {
		return nil, err
	}
	var removed []Info
	for _, b := range all[keep:] {
		if err := os.Remove(b.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, fmt.Errorf("remove an old backup: %w", err)
		}
		removed = append(removed, b)
	}
	return removed, nil
}
