package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// topLevelKey matches a top-level "key = value" line, keeping any trailing
// comment in group 2.
var topLevelKey = regexp.MustCompile(`^\s*([A-Za-z0-9_-]+)\s*=\s*(?:"(?:[^"\\]|\\.)*"|[^#\s]*)\s*(#.*)?$`)

// SetTopLevel sets a top-level string setting in the config file at path,
// keeping every other line, comments included. It replaces the key's line
// if there is one, otherwise adds it before the first [table] header,
// creating the file (and its directory, owner-only) if needed. The file is
// written atomically, mode 0600.
func SetTopLevel(path, key, value string) error {
	var lines []string
	body, err := os.ReadFile(path) //nolint:gosec // the user's own config file
	switch {
	case err == nil:
		lines = strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	case os.IsNotExist(err):
	default:
		return fmt.Errorf("read config file %s: %w", path, err)
	}

	line := key + " = " + strconv.Quote(value)
	insertAt, replaced := len(lines), false
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "[") {
			insertAt = i
			break
		}
		if m := topLevelKey.FindStringSubmatch(l); len(m) == 3 && m[1] == key {
			if m[2] != "" {
				lines[i] = line + " " + m[2]
			} else {
				lines[i] = line
			}
			replaced = true
			break
		}
	}
	if !replaced {
		// A key written in a form this edit doesn't recognize (a quoted key,
		// say) would end up defined twice, which TOML rejects.
		var existing map[string]any
		if md, err := toml.Decode(string(body), &existing); err == nil && md.IsDefined(key) {
			return fmt.Errorf("%s sets %s in a form sesh can't edit safely", path, key)
		}
		// Keep a blank line between the new setting and a table that follows.
		add := []string{line}
		if insertAt < len(lines) {
			add = append(add, "")
		}
		lines = append(lines[:insertAt], append(add, lines[insertAt:]...)...)
	}
	result := strings.Join(lines, "\n") + "\n"
	// Write only a file that still parses and says what was asked.
	var check map[string]any
	if _, err := toml.Decode(result, &check); err != nil || check[key] != value {
		return fmt.Errorf("editing %s in %s didn't produce a valid file; set it there yourself", key, path)
	}
	return writeFile(path, result)
}

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
	tmp, err := os.CreateTemp(dir, ".config.toml.*")
	if err != nil {
		return fmt.Errorf("write config file: %w", err)
	}
	renamed := false
	defer func() {
		if !renamed {
			if err := os.Remove(tmp.Name()); err != nil && !os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "warning: remove temporary config file: %v\n", err) //nolint:errcheck // best-effort warning
			}
		}
	}()
	if _, err := tmp.WriteString(body); err != nil {
		return closeAfter(tmp, fmt.Errorf("write config file: %w", err))
	}
	if err := tmp.Chmod(0o600); err != nil {
		return closeAfter(tmp, fmt.Errorf("write config file: %w", err))
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write config file %s: %w", path, err)
	}
	renamed = true
	return nil
}

// resolveLinks returns the file path names after following symlinks. For a
// link whose target doesn't exist yet, it returns that target, so the
// first write creates it rather than replacing the link.
func resolveLinks(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved, nil
	}
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("resolve config file %s: %w", path, err)
	}
	target, lerr := os.Readlink(path)
	if lerr != nil {
		return path, nil // no file and no link: write a new file at path
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(path), target)
	}
	return target, nil
}

// closeAfter closes f after err, reporting a close failure alongside it.
func closeAfter(f *os.File, err error) error {
	if cerr := f.Close(); cerr != nil {
		return fmt.Errorf("%w (close also failed: %v)", err, cerr)
	}
	return err
}
