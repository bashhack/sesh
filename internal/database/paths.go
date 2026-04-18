package database

import (
	"os"
	"path/filepath"
	"runtime"
)

// DefaultDBPath returns the platform-appropriate path for the sesh database.
//
//   - macOS:   ~/Library/Application Support/sesh/passwords.db
//   - Linux:   $XDG_DATA_HOME/sesh/passwords.db (falls back to ~/.local/share/sesh/passwords.db;
//     a relative $XDG_DATA_HOME is ignored per the XDG Base Directory spec)
//   - Windows: %APPDATA%/sesh/passwords.db (falls back to ~/AppData/Roaming/sesh/passwords.db)
func DefaultDBPath() (string, error) {
	dir, err := defaultDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "passwords.db"), nil
}

func defaultDataDir() (string, error) {
	var base string

	switch runtime.GOOS {
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, "Library", "Application Support")
	case "windows":
		base = os.Getenv("APPDATA")
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			base = filepath.Join(home, "AppData", "Roaming")
		}
	default: // linux, freebsd, etc.
		// XDG spec: ignore a non-absolute $XDG_DATA_HOME and use the default.
		if v := os.Getenv("XDG_DATA_HOME"); v != "" && filepath.IsAbs(v) {
			base = v
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			base = filepath.Join(home, ".local", "share")
		}
	}

	dir := filepath.Join(base, "sesh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}
