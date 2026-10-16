package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

// readFileToAdd reads the file at path for a file entry: its content,
// which the caller zeroes, and its name. A folder, an empty file, and one
// over the most an entry holds are refused.
func readFileToAdd(path string) (content []byte, name string, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, "", err
	}
	switch {
	case info.IsDir():
		return nil, "", fmt.Errorf("%s is a folder: a file entry keeps one file", path)
	case info.Size() > database.MaxSecretSize:
		return nil, "", fmt.Errorf("%s is %s; a file entry holds up to %s", path, vault.SizeSaid(info.Size()), vault.SizeSaid(database.MaxSecretSize))
	}
	f, err := os.Open(path) //nolint:gosec // the file the user named
	if err != nil {
		return nil, "", err
	}
	defer f.Close() //nolint:errcheck // read only
	content, err = readAtMost(f, path)
	if err != nil {
		return nil, "", err
	}
	return content, filepath.Base(path), nil
}

// readAtMost reads r, called what in errors, to its end: up to the most an
// entry holds, and not empty.
func readAtMost(r io.Reader, what string) ([]byte, error) {
	content, err := io.ReadAll(io.LimitReader(r, database.MaxSecretSize+1))
	switch {
	case err != nil:
		secure.SecureZeroBytes(content)
		return nil, fmt.Errorf("read %s: %w", what, err)
	case len(content) > database.MaxSecretSize:
		secure.SecureZeroBytes(content)
		return nil, fmt.Errorf("%s is over %s, the most a file entry holds", what, vault.SizeSaid(database.MaxSecretSize))
	case len(content) == 0:
		return nil, errors.New(what + " is empty: a file entry keeps a file with something in it")
	}
	return content, nil
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
	if _, err := os.Lstat(path); err == nil {
		return "", fmt.Errorf("there's already a file at %s: give another name, or move that one first", tildePath(path))
	}
	if err := writePrivate(path, content); err != nil {
		return "", err
	}
	return tildePath(path), nil
}
