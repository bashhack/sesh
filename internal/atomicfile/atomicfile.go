// Package atomicfile replaces a file so that readers see either the old
// contents or the new, and a crash or power loss just afterwards can't
// leave it empty or lose the change. sesh uses it for files whose loss
// would lock a vault: the Touch ID file and the config.
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
func Write(path string, data []byte, perm os.FileMode) error {
	p, err := Create(path, perm)
	if err != nil {
		return err
	}
	if _, err := p.Write(data); err != nil {
		p.Abort()
		return err
	}
	return p.Commit()
}

// Pending is a file being written that replaces path once committed, as
// Write replaces it; until then path is as it was.
type Pending struct {
	f    *os.File
	path string
	perm os.FileMode
	done bool
}

// Create starts a file to replace path, with mode perm once committed: a
// temporary file in path's directory, made now, so a directory it can't be
// made in fails before anything is written.
func Create(path string, perm os.FileMode) (*Pending, error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return nil, err
	}
	return &Pending{f: f, path: path, perm: perm}, nil
}

func (p *Pending) Write(b []byte) (int, error) { return p.f.Write(b) }

// Commit syncs the file and renames it over path, then syncs the
// directory. On an error the temporary file is removed and path is as it
// was.
func (p *Pending) Commit() (err error) {
	if p.done {
		return errors.New("already committed or abandoned")
	}
	p.done = true
	name := p.f.Name()
	defer func() {
		if err != nil {
			if rerr := os.Remove(name); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
				err = fmt.Errorf("%w (removing %s also failed: %v)", err, name, rerr)
			}
		}
	}()
	err = p.f.Chmod(p.perm)
	if err == nil {
		err = p.f.Sync()
	}
	if cerr := p.f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(name, p.path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(p.path))
}

// Abort removes the temporary file, leaving path as it was. It may run
// while Commit does (a signal's handler, say): the file is removed unless
// it has been renamed to path already, which Abort then leaves.
func (p *Pending) Abort() {
	p.f.Close()           //nolint:errcheck,gosec // it's being thrown away
	os.Remove(p.f.Name()) //nolint:errcheck,gosec // gone already once renamed
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
