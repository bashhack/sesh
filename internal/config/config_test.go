package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// isolate points HOME and XDG_CONFIG_HOME at a temp dir, clears every sesh
// setting from the environment, and returns where the config file goes.
func isolate(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "data"))
	for _, k := range []string{EnvBackend, EnvKeySource, EnvDBPath, EnvClipboardTimeout, EnvAgentIdleTimeout, EnvAgentMaxLifetime} {
		t.Setenv(k, "")
	}
	return filepath.Join(home, "xdg", "sesh", "config.toml")
}

func writeConfig(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoad_DefaultsWithoutAFile(t *testing.T) {
	path := isolate(t)
	c, err := Load(Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	if c.FileFound || c.Path != path {
		t.Errorf("Path = %q, FileFound = %v; want %q, false", c.Path, c.FileFound, path)
	}
	if c.Backend.Value != BackendSQLite || c.KeySource.Value != KeySourcePassword || c.Backend.Source != FromDefault {
		t.Errorf("backend %+v, key source %+v; want the sqlite + password defaults", c.Backend, c.KeySource)
	}
	if c.ClipboardTimeout.Value != 30*time.Second || c.AgentIdleTimeout.Value != 10*time.Minute || c.AgentMaxLifetime.Value != 8*time.Hour {
		t.Errorf("durations = %v, %v, %v", c.ClipboardTimeout.Value, c.AgentIdleTimeout.Value, c.AgentMaxLifetime.Value)
	}
	if !strings.HasSuffix(c.DBPath.Value, filepath.Join("sesh", "passwords.db")) {
		t.Errorf("DBPath = %q", c.DBPath.Value)
	}
}

func TestLoad_FileThenEnvThenFlag(t *testing.T) {
	path := isolate(t)
	writeConfig(t, path, `
# a comment
backend = "sqlite"
key_source = "password"
db_path = "~/vaults/sesh.db"
clipboard_timeout = "45s"

[agent]
idle_timeout = "30m"
`)
	c, err := Load(Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if !c.FileFound || c.Backend.Value != "sqlite" || c.Backend.Source != FromFile ||
		c.KeySource.Value != "password" || c.DBPath.Value != filepath.Join(home, "vaults", "sesh.db") ||
		c.ClipboardTimeout.Value != 45*time.Second || c.AgentIdleTimeout.Value != 30*time.Minute ||
		c.AgentMaxLifetime.Source != FromDefault {
		t.Fatalf("file values not applied: %+v", c)
	}

	t.Setenv(EnvKeySource, "keychain")
	t.Setenv(EnvAgentIdleTimeout, "5m")
	c, err = Load(Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	if c.KeySource.Value != "keychain" || c.KeySource.Source != FromEnv || c.KeySource.Origin != EnvKeySource ||
		c.AgentIdleTimeout.Value != 5*time.Minute || c.Backend.Source != FromFile {
		t.Fatalf("env didn't override the file: key source %+v, idle %+v", c.KeySource, c.AgentIdleTimeout)
	}

	c, err = Load(Overrides{KeySource: "password", DBPath: "/tmp/x.db"})
	if err != nil {
		t.Fatal(err)
	}
	if c.KeySource.Value != "password" || c.KeySource.Source != FromFlag || c.DBPath.Value != "/tmp/x.db" {
		t.Fatalf("flags didn't override env and file: %+v %+v", c.KeySource, c.DBPath)
	}
}

func TestLoad_Rejects(t *testing.T) {
	tests := map[string]struct {
		file, wantSub string
		env           map[string]string
		flags         Overrides
	}{
		"unknown file key":       {file: "backend = \"sqlite\"\nbakend = \"x\"\n", wantSub: "unknown setting bakend"},
		"unknown agent key":      {file: "[agent]\nidle = \"1m\"\n", wantSub: "unknown setting agent.idle"},
		"bad backend in file":    {file: `backend = "sqlte"`, wantSub: `backend in `},
		"bad backend in env":     {env: map[string]string{EnvBackend: "sqlte"}, wantSub: `SESH_BACKEND = "sqlte": want "sqlite" or "keychain"`},
		"bad key source in env":  {env: map[string]string{EnvKeySource: "pass"}, wantSub: `SESH_KEY_SOURCE = "pass": want "password" or "keychain"`},
		"bad key source flag":    {flags: Overrides{KeySource: "pass"}, wantSub: `--key-source = "pass"`},
		"relative db path":       {file: `db_path = "vault.db"`, wantSub: "want an absolute path"},
		"bad duration":           {file: `clipboard_timeout = "soon"`, wantSub: "want a duration"},
		"negative duration":      {env: map[string]string{EnvAgentIdleTimeout: "-1m"}, wantSub: "must not be negative"},
		"not TOML":               {file: "backend: sqlite\n", wantSub: "read config file"},
		"wrong type in the file": {file: "clipboard_timeout = 30\n", wantSub: "read config file"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			path := isolate(t)
			if tt.file != "" {
				writeConfig(t, path, tt.file)
			}
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			_, err := Load(tt.flags)
			if err == nil || !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.wantSub)
			}
		})
	}
}

func TestPath_HonorsXDGConfigHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	got, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, ".config", "sesh", "config.toml"); got != want {
		t.Errorf("Path() = %q, want %q", got, want)
	}
	t.Setenv("XDG_CONFIG_HOME", "/somewhere")
	if got, err := Path(); err != nil || got != "/somewhere/sesh/config.toml" {
		t.Errorf("Path() with XDG_CONFIG_HOME = %q", got)
	}
	t.Setenv("XDG_CONFIG_HOME", "relative/dir")
	if got, err := Path(); err != nil || got != filepath.Join(home, ".config", "sesh", "config.toml") {
		t.Errorf("Path() with a relative XDG_CONFIG_HOME = %q, want the ~/.config default", got)
	}
}
