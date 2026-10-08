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

// link is os.Link; tests replace it to stand in for a file system without
// links.
var link = os.Link

// staleTemp is how old a temporary file from a backup cut short (by Ctrl-C,
// say) must be before a later backup removes it.
const staleTemp = time.Hour

// Info is a backup: its file, when it was made, and its size in bytes.
type Info struct {
	Made time.Time
	Path string
	Size int64
}

// Series is one vault's backups in a folder: passwords.db's, for the vault
// with id 3f9c…, are passwords-3f9c2a1b-<stamp>.db. The id keeps two
// vaults' backups apart when they share a folder.
type Series struct {
	Dir    string
	prefix string
	ext    string
}

// SeriesOf is the backups in dir of the vault at vaultPath.
func SeriesOf(vaultPath, dir string) (Series, error) {
	id, err := database.VaultID(vaultPath)
	if err != nil {
		return Series{}, err
	}
	base := filepath.Base(vaultPath)
	ext := filepath.Ext(base)
	prefix := strings.TrimSuffix(base, ext) + "-" + id[:min(8, len(id))] + "-"
	if ext == "" {
		ext = ".db"
	}
	return Series{Dir: dir, prefix: prefix, ext: ext}, nil
}

// Name is the file name of the backup made at t.
func (s Series) Name(t time.Time) string {
	return s.prefix + t.UTC().Format(stamp) + s.ext
}

// List returns the series' backups, newest first: the files named as Name
// names them, and nothing else. A missing folder holds none.
func (s Series) List() ([]Info, error) {
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list backups in %s: %w", s.Dir, err)
	}
	var out []Info
	for _, e := range entries {
		name := e.Name()
		middle, ok := strings.CutPrefix(name, s.prefix)
		if !ok || !e.Type().IsRegular() {
			continue
		}
		middle, ok = strings.CutSuffix(middle, s.ext)
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
		out = append(out, Info{Path: filepath.Join(s.Dir, name), Made: made, Size: info.Size()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Made.After(out[j].Made) })
	return out, nil
}

// Newest is the newest backup made by now, ignoring any dated later (a
// clock that was set wrong, or another machine's), and whether there is
// one.
func Newest(all []Info, now time.Time) (Info, bool) {
	for _, b := range all {
		if !b.Made.After(now) {
			return b, true
		}
	}
	return Info{}, false
}

// Due reports whether a backup is due: everyDays or more calendar days
// (local time) since the newest, or none yet. everyDays 0 means never.
// Counting days, not hours, means one a day even when sesh is first used
// a little earlier each day.
func (s Series) Due(everyDays int, now time.Time) (bool, error) {
	if everyDays <= 0 {
		return false, nil
	}
	all, err := s.List()
	if err != nil {
		return false, err
	}
	newest, ok := Newest(all, now)
	if !ok {
		return true, nil
	}
	y, m, d := newest.Made.Local().Date()
	next := time.Date(y, m, d+everyDays, 0, 0, 0, 0, time.Local)
	return !now.Before(next), nil
}

// Make backs up the vault at vaultPath into the series' folder (made
// private if new), named for now. If another sesh made that backup in the
// same second, its copy stands.
func (s Series) Make(vaultPath string, now time.Time) (Info, error) {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return Info{}, fmt.Errorf("create the backups folder %s: %w", s.Dir, err)
	}
	s.removeStaleTemps(now)
	dest := filepath.Join(s.Dir, s.Name(now))
	if err := write(vaultPath, dest, false); err != nil && !errors.Is(err, os.ErrExist) {
		return Info{}, err
	}
	return stat(dest, now)
}

// MakeNew is Make that never takes an existing backup for its own: if one
// was made in the same second, the backup is named for the next free
// second. A restore saves the vault with it, which must be the vault as it
// is now.
func (s Series) MakeNew(vaultPath string, now time.Time) (Info, error) {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return Info{}, fmt.Errorf("create the backups folder %s: %w", s.Dir, err)
	}
	for i := range 60 {
		at := now.Add(time.Duration(i) * time.Second)
		dest := filepath.Join(s.Dir, s.Name(at))
		err := write(vaultPath, dest, false)
		if err == nil {
			return stat(dest, at)
		}
		if !errors.Is(err, os.ErrExist) {
			return Info{}, err
		}
	}
	return Info{}, fmt.Errorf("no free name for a backup in %s", s.Dir)
}

// removeStaleTemps removes the temporary files of this series' backups
// that were cut short long ago. A failure is ignored: they're only clutter.
func (s Series) removeStaleTemps(now time.Time) {
	matches, err := filepath.Glob(filepath.Join(s.Dir, "."+s.prefix+"*.tmp"))
	if err != nil {
		return
	}
	for _, m := range matches {
		if info, err := os.Lstat(m); err == nil && info.Mode().IsRegular() && now.Sub(info.ModTime()) > staleTemp {
			_ = os.Remove(m) //nolint:errcheck // only clutter
		}
	}
}

// MakeTo backs up the vault at vaultPath to dest, refusing to replace a
// file there unless force. When dest is a folder, the backup goes in it,
// named as the series names it.
func MakeTo(vaultPath, dest string, force bool, now time.Time) (Info, error) {
	if info, err := os.Stat(dest); err == nil && info.IsDir() {
		s, err := SeriesOf(vaultPath, dest)
		if err != nil {
			return Info{}, err
		}
		dest = filepath.Join(dest, s.Name(now))
	}
	if err := write(vaultPath, dest, force); err != nil {
		if errors.Is(err, os.ErrExist) {
			return Info{}, fmt.Errorf("%s already exists; add --force to replace it", dest)
		}
		return Info{}, err
	}
	return stat(dest, now)
}

// write copies the vault to dest through a private file beside it, renamed
// into place, so a copy cut short never stands as a backup. It's an error
// wrapping os.ErrExist when dest exists and replace is false.
func write(vaultPath, dest string, replace bool) error {
	if _, err := os.Lstat(dest); err == nil && !replace {
		return fmt.Errorf("%s: %w", dest, os.ErrExist)
	}
	// CreateTemp makes the file 0600, and VACUUM INTO writes into an empty
	// file, keeping that: the copy is never readable by others.
	tmp, err := os.CreateTemp(filepath.Dir(dest), "."+filepath.Base(dest)+".*.tmp")
	if err != nil {
		return fmt.Errorf("make the backup: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() //nolint:errcheck // gone once renamed
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("make the backup: %w", err)
	}
	if err := database.CopyTo(vaultPath, tmpPath); err != nil {
		return err
	}
	if !replace {
		// Link refuses an existing name where rename would replace it.
		err := link(tmpPath, dest)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, os.ErrExist):
			return fmt.Errorf("%s: %w", dest, os.ErrExist)
		}
		// Some file systems (FAT and exFAT, as USB sticks use) have no
		// links: check, then rename.
		if _, lerr := os.Lstat(dest); lerr == nil {
			return fmt.Errorf("%s: %w", dest, os.ErrExist)
		}
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

// Prune removes all but the newest keep backups of the series, returning
// those removed.
func (s Series) Prune(keep int) ([]Info, error) {
	all, err := s.List()
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

// RemoveAll removes every backup of the series, returning those removed.
func (s Series) RemoveAll() ([]Info, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}
	var removed []Info
	for _, b := range all {
		if err := os.Remove(b.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, fmt.Errorf("remove a backup: %w", err)
		}
		removed = append(removed, b)
	}
	return removed, nil
}

// ListAny returns the backups in dir of any vault named as the one at
// vaultPath, newest first, with the id each was made from: for listing
// when the vault itself can't be read, to say whose each backup is.
func ListAny(dir, vaultPath string) ([]Info, []string, error) {
	base := filepath.Base(vaultPath)
	ext := filepath.Ext(base)
	prefix := strings.TrimSuffix(base, ext) + "-"
	if ext == "" {
		ext = ".db"
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("list backups in %s: %w", dir, err)
	}
	type found struct {
		id   string
		info Info
	}
	var all []found
	for _, e := range entries {
		middle, ok := strings.CutPrefix(e.Name(), prefix)
		if !ok || !e.Type().IsRegular() {
			continue
		}
		middle, ok = strings.CutSuffix(middle, ext)
		id, when, ok2 := strings.Cut(middle, "-")
		if !ok || !ok2 || len(id) != 8 {
			continue
		}
		made, err := time.Parse(stamp, when)
		if err != nil {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		all = append(all, found{id, Info{Path: filepath.Join(dir, e.Name()), Made: made, Size: info.Size()}})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].info.Made.After(all[j].info.Made) })
	infos, ids := make([]Info, len(all)), make([]string, len(all))
	for i, f := range all {
		infos[i], ids[i] = f.info, f.id
	}
	return infos, ids, nil
}
