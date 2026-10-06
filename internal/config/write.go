package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/bashhack/sesh/internal/atomicfile"
)

// Write creates the config file at path with body, replacing any existing
// one, atomically and owner-only.
func Write(path, body string) error {
	return writeFile(path, body)
}

func writeFile(path, body string) error {
	// Write the file a symlink points at, not over the link: dotfile
	// managers (stow, chezmoi) often link config files into a repo.
	path, err := resolveLinks(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config directory %s: %w", dir, err)
	}
	if err := atomicfile.Write(path, []byte(body), 0o600); err != nil {
		return fmt.Errorf("write config file %s: %w", path, err)
	}
	return nil
}

// maxLinks bounds how many symlinks resolveLinks follows, as the kernel
// does, so a loop of links fails instead of spinning.
const maxLinks = 40

// resolveLinks returns the file path names after following symlinks. When
// the chain ends at a path that doesn't exist yet, it returns that path, so
// the first write creates it rather than replacing a link on the way.
func resolveLinks(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved, nil
	}
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("resolve config file %s: %w", path, err)
	}
	for range maxLinks {
		target, lerr := os.Readlink(path)
		if lerr != nil {
			return path, nil // the end of the chain: no file there yet
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(path), target)
		}
		path = target
	}
	return "", fmt.Errorf("resolve config file %s: too many links", path)
}
