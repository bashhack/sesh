// Package exportfile is the file an export is written to: one replaced
// only once the export is whole, through a temporary file made after its
// password is asked; or a device or pipe written as it goes.
package exportfile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/bashhack/sesh/internal/atomicfile"
)

// File is where an export to a file goes: a file that replaces the
// one there once the export is whole, made once the password has been
// asked; or a device or pipe (/dev/stdout, a shell's >(…)), written as it
// goes.
type File struct {
	pending *atomicfile.Pending
	device  *os.File
	target  string
}

func (e *File) Write(b []byte) (int, error) {
	switch {
	case e.pending != nil:
		return e.pending.Write(b)
	case e.device == nil:
		// Not made non-blocking, as os.OpenFile makes a terminal: the
		// terminal the password was read from, and the shell after.
		// Appended to: a file a shell's >> redirected stdout to keeps
		// what it had.
		fd, err := syscall.Open(e.target, syscall.O_WRONLY|syscall.O_APPEND|syscall.O_CLOEXEC, 0)
		if err != nil {
			return 0, &os.PathError{Op: "open", Path: e.target, Err: err}
		}
		e.device = os.NewFile(uintptr(fd), e.target)
	}
	return e.device.Write(b)
}

// Start makes the file a regular target is written to, once the password
// has been asked: a Ctrl-C at the prompt leaves nothing behind.
func (e *File) Start() error {
	if e.device != nil || !e.regular() {
		return nil
	}
	p, err := atomicfile.Create(e.target, 0o600)
	if err != nil {
		return err
	}
	e.pending = p
	return nil
}

// regular says whether the target is a file replaced whole, not a device.
func (e *File) regular() bool { return !IsDevice(e.target) }

func (e *File) Finish() error {
	if e.pending != nil {
		return e.pending.Commit()
	}
	if e.device != nil {
		return e.device.Close()
	}
	return nil
}

func (e *File) Abort() {
	if e.pending != nil {
		e.pending.Abort()
	}
	if e.device != nil {
		e.device.Close() //nolint:errcheck,gosec // nothing more to do with it
	}
}

// IsDevice says whether path is a device or pipe, written as it is: a
// name for a process's own output (/dev/stdout is whatever it's
// redirected to, which isn't replaced), or a file that isn't a regular
// file or folder.
func IsDevice(path string) bool {
	switch {
	case path == "/dev/stdout", path == "/dev/stderr", path == "/dev/tty",
		strings.HasPrefix(path, "/dev/fd/"), strings.HasPrefix(path, "/proc/self/fd/"):
		return true
	}
	info, err := os.Stat(path)
	return err == nil && !info.Mode().IsRegular() && !info.IsDir()
}

// Open checks path for an export, before the password is asked: a
// link is followed to its file, a folder is refused, an existing file is
// replaced only when force, and the file's folder must take a new file.
func Open(path string, force bool) (*File, error) {
	// A device as named: /dev/stdout is a link to the file it's redirected
	// to on Linux, which is written to through it, not replaced.
	if IsDevice(path) {
		return &File{target: path}, nil
	}
	target, err := followLinks(path)
	if err != nil {
		return nil, err
	}
	if IsDevice(target) {
		return &File{target: target}, nil
	}
	info, err := os.Stat(target)
	switch {
	case err == nil && info.IsDir():
		return nil, fmt.Errorf("%s is a folder: name a file to export to", path)
	case err == nil && !force:
		return nil, &ExistsError{Path: path}
	}
	// The folder is tried now, so one that can't take the file fails
	// before the password is asked; the file itself is made after.
	probe, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".*")
	if err != nil {
		return nil, fmt.Errorf("can't write an export in %s: %w", filepath.Dir(path), err)
	}
	probe.Close()           //nolint:errcheck,gosec // only tried
	os.Remove(probe.Name()) //nolint:errcheck,gosec // only tried
	return &File{target: target}, nil
}

// followLinks is the file path's links lead to, as the system follows
// them: one not there yet when the last link points at it.
func followLinks(path string) (string, error) {
	// Each link's folder is followed through its own links before its
	// name is read, and a .. in a link's target is left for that, not
	// cleaned away first; the last link may point at a file not there yet.
	for range 40 {
		slash := strings.LastIndex(path, "/")
		dir, name := ".", path
		if slash >= 0 {
			dir, name = path[:slash], path[slash+1:]
			if dir == "" {
				dir = "/"
			}
		}
		if followed, err := filepath.EvalSymlinks(dir); err == nil {
			dir = followed
		}
		path = filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			return path, nil
		}
		to, err := os.Readlink(path)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(to) {
			to = dir + "/" + to
		}
		path = to
	}
	return "", fmt.Errorf("%s: too many links", path)
}

// ExistsError is an export refused because a file is where it would go;
// it matches os.ErrExist.
type ExistsError struct{ Path string }

func (e *ExistsError) Error() string { return e.Path + " already exists; add --force to replace it" }
func (e *ExistsError) Unwrap() error { return os.ErrExist }
