package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

// readFileToAdd reads the file at path for a file entry: its content,
// which the caller zeroes, and its name. A folder, an empty file, one over
// the most an entry holds, and a name sesh can't keep are refused.
func readFileToAdd(path string) (content []byte, name string, err error) {
	name = filepath.Base(path)
	if err := vault.CheckFileName(name); err != nil {
		return nil, "", fmt.Errorf("%s: %w", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, "", err
	}
	switch {
	case info.IsDir():
		return nil, "", fmt.Errorf("%s is a folder: a file entry keeps one file", path)
	case info.Size() > database.MaxSecretSize:
		return nil, "", fmt.Errorf("%s is %s bytes; a file entry holds up to %s", path, withCommas(info.Size()), maxFileSaid)
	}
	f, err := os.Open(path) //nolint:gosec // the file the user named
	if err != nil {
		return nil, "", err
	}
	defer f.Close() //nolint:errcheck // read only
	content, err = readAtMost(f, path, int(info.Size()))
	if err != nil {
		return nil, "", err
	}
	return content, name, nil
}

// maxFileSaid is the most a file entry holds, said exactly.
var maxFileSaid = "1 MiB (" + withCommas(database.MaxSecretSize) + " bytes)"

// readAtMost reads r, called what in errors, to its end: up to the most an
// entry holds, and not empty. size is about how much there is (0 when
// that's not known). Each buffer it outgrows is zeroed, so no copy of
// what it read is left behind.
func readAtMost(r io.Reader, what string, size int) ([]byte, error) {
	buf := make([]byte, 0, min(max(size+1, 4096), database.MaxSecretSize+1))
	fail := func(err error) ([]byte, error) {
		secure.SecureZeroBytes(buf[:cap(buf)])
		return nil, err
	}
	for {
		if len(buf) == cap(buf) {
			if len(buf) > database.MaxSecretSize {
				return fail(fmt.Errorf("%s is over %s, the most a file entry holds", what, maxFileSaid))
			}
			bigger := make([]byte, len(buf), min(2*cap(buf), database.MaxSecretSize+1))
			copy(bigger, buf)
			secure.SecureZeroBytes(buf[:cap(buf)])
			buf = bigger
		}
		n, err := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fail(fmt.Errorf("read %s: %w", what, err))
		}
	}
	switch {
	case len(buf) > database.MaxSecretSize:
		return fail(fmt.Errorf("%s is over %s, the most a file entry holds", what, maxFileSaid))
	case len(buf) == 0:
		return nil, errors.New(what + " is empty: a file entry keeps a file with something in it")
	}
	return buf, nil
}

// withCommas is n with commas between its thousands: 1,048,576.
func withCommas(n int64) string {
	s := strconv.FormatInt(n, 10)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// uiReadFile reads a file for a file entry, its path typed in the app.
func uiReadFile(typed string) ([]byte, string, error) {
	path, err := uiPath(typed)
	if err != nil {
		return nil, "", err
	}
	return readFileToAdd(path)
}

// uiSaveFile writes a file entry's content to the path typed in the app,
// readable only by you; a file already there is kept, and it says so. It
// says where it wrote.
func uiSaveFile(typed string, content []byte) (string, error) {
	path, err := uiPath(typed)
	if err != nil {
		return "", err
	}
	if err := writeNew(path, content); err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("there's already a file at %s: give another name, or move that one first", tildePath(path))
		}
		return "", err
	}
	return tildePath(path), nil
}

// writeNew writes b to a new file at path, readable only by its owner,
// whole: written beside it, then linked into place, which fails with
// os.ErrExist rather than replace anything there, however recently it
// came.
func writeNew(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".sesh-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck // the link, if made, holds the file
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close() //nolint:errcheck // already failing
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close() //nolint:errcheck // already failing
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close() //nolint:errcheck // already failing
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Link(tmp.Name(), path)
}
