// Package atomicfile replaces a file so that readers see either the old
// contents or the new, and a crash or power loss just afterwards can't
// leave it empty or lose the change. sesh uses it for files whose loss
// would lock a vault: the Touch ID and recovery files, and the config.
package atomicfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Write replaces path with data, with mode perm. It writes a temporary file
// in the same directory and syncs it to disk, renames it over path, then
// syncs the directory so the rename itself survives a crash. A rename alone
// is atomic for readers but not durable: after a power loss the file can
// come back empty, or the old one can reappear.
func Write(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() {
		if err != nil {
			if rerr := os.Remove(name); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
				err = fmt.Errorf("%w (removing %s also failed: %v)", err, name, rerr)
			}
		}
	}()
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(perm)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return syncDir(dir)
}

// syncDir flushes a directory's entries, so a rename in it is on disk.
func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // the directory of a file sesh is writing
	if err != nil {
		return err
	}
	serr := d.Sync()
	if cerr := d.Close(); serr == nil {
		serr = cerr
	}
	return serr
}
