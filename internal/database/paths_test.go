package database

import (
	"errors"
	"strings"
	"testing"
)

func TestResolveBaseDir(t *testing.T) {
	tests := map[string]struct {
		goos, appdata, xdgDataHome, homeDir string
		want                                string
		wantErr                             bool
	}{
		"darwin": {
			goos:    "darwin",
			homeDir: "/Users/alice",
			want:    "/Users/alice/Library/Application Support",
		},
		"darwin without home": {
			goos:    "darwin",
			wantErr: true,
		},

		"windows APPDATA set": {
			goos:    "windows",
			appdata: "C:/Users/alice/AppData/Roaming",
			want:    "C:/Users/alice/AppData/Roaming",
		},
		"windows APPDATA empty falls back to home": {
			goos:    "windows",
			homeDir: "C:/Users/alice",
			want:    "C:/Users/alice/AppData/Roaming",
		},
		"windows without APPDATA or home": {
			goos:    "windows",
			wantErr: true,
		},

		"linux without XDG": {
			goos:    "linux",
			homeDir: "/home/alice",
			want:    "/home/alice/.local/share",
		},
		"linux with absolute XDG": {
			goos:        "linux",
			xdgDataHome: "/data/sesh",
			homeDir:     "/home/alice",
			want:        "/data/sesh",
		},
		"linux with relative XDG ignored": {
			// Per the XDG Base Directory spec, a non-absolute value
			// "must be ignored" — otherwise the DB could land in the
			// launching process's CWD.
			goos:        "linux",
			xdgDataHome: "rel/path",
			homeDir:     "/home/alice",
			want:        "/home/alice/.local/share",
		},
		"freebsd defaults like linux": {
			goos:    "freebsd",
			homeDir: "/home/alice",
			want:    "/home/alice/.local/share",
		},
		"linux without home or XDG": {
			goos:    "linux",
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := resolveBaseDir(tc.goos, tc.appdata, tc.xdgDataHome, tc.homeDir)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got base=%q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("base = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDefaultDBPath_EndsInPasswordsDB(t *testing.T) {
	// Redirect every platform branch's base dir to a temp dir so the test
	// creates a sesh/ subdir under t.TempDir() instead of the user's real
	// data directory.
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("APPDATA", tmp)
	t.Setenv("XDG_DATA_HOME", tmp)

	got, err := DefaultDBPath()
	if err != nil {
		t.Fatalf("DefaultDBPath: %v", err)
	}
	if !strings.HasSuffix(got, "sesh/passwords.db") && !strings.HasSuffix(got, `sesh\passwords.db`) {
		t.Errorf("DefaultDBPath = %q, want suffix sesh/passwords.db", got)
	}
}

func TestResolveBaseDir_ErrIsTyped(t *testing.T) {
	_, err := resolveBaseDir("linux", "", "", "")
	if !errors.Is(err, errNoHomeDir) {
		t.Errorf("resolveBaseDir no-home error = %v, want errors.Is(errNoHomeDir)", err)
	}
}
