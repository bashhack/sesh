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
	// Not fatal if UserHomeDir fails: resolveBaseDir surfaces errNoHomeDir
	// only when the chosen platform branch actually needs a home directory.
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	base, err := resolveBaseDir(runtime.GOOS, os.Getenv("APPDATA"), os.Getenv("XDG_DATA_HOME"), home)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "sesh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// resolveBaseDir picks the platform-appropriate data base directory from
// the given OS and env/home values. Returns an error only when the chosen
// branch needs a home directory and none was provided.
func resolveBaseDir(goos, appdata, xdgDataHome, homeDir string) (string, error) {
	switch goos {
	case "darwin":
		if homeDir == "" {
			return "", errNoHomeDir
		}
		return filepath.Join(homeDir, "Library", "Application Support"), nil
	case "windows":
		if appdata != "" {
			return appdata, nil
		}
		if homeDir == "" {
			return "", errNoHomeDir
		}
		return filepath.Join(homeDir, "AppData", "Roaming"), nil
	default: // linux, freebsd, etc.
		// XDG spec: ignore a non-absolute $XDG_DATA_HOME and use the default.
		if xdgDataHome != "" && filepath.IsAbs(xdgDataHome) {
			return xdgDataHome, nil
		}
		if homeDir == "" {
			return "", errNoHomeDir
		}
		return filepath.Join(homeDir, ".local", "share"), nil
	}
}

var errNoHomeDir = errNoHomeDirMsg("cannot determine user home directory")

type errNoHomeDirMsg string

func (e errNoHomeDirMsg) Error() string { return string(e) }
