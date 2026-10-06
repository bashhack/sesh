package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/kdf"
)

// isolate points HOME and XDG_CONFIG_HOME at a temp dir, clears every sesh
// setting from the environment, and returns where the config file goes.
func isolate(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "data"))
	for _, k := range []string{EnvDBPath, EnvClipboardTimeout, EnvAgentIdleTimeout, EnvAgentMaxLifetime, EnvAuditRetentionDays, EnvKDFMemory, EnvKDFTime, EnvKDFThreads} {
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
	if c.ClipboardTimeout.Value != 30*time.Second || c.AgentIdleTimeout.Value != 10*time.Minute || c.AgentMaxLifetime.Value != 8*time.Hour {
		t.Errorf("durations = %v, %v, %v", c.ClipboardTimeout.Value, c.AgentIdleTimeout.Value, c.AgentMaxLifetime.Value)
	}
	if c.AuditRetentionDays.Value != 90 || c.AuditRetentionDays.Source != FromDefault {
		t.Errorf("audit retention = %+v, want 90 days by default", c.AuditRetentionDays)
	}
	if !strings.HasSuffix(c.DBPath.Value, filepath.Join("sesh", "passwords.db")) {
		t.Errorf("DBPath = %q", c.DBPath.Value)
	}
	if c.KDF() != kdf.Default() || c.KDFMemory.Source != FromDefault {
		t.Errorf("KDF = %+v (%v), want the defaults", c.KDF(), c.KDFMemory.Source)
	}
}

// The Argon2id settings come from the file, then the environment.
func TestLoad_KDFSettings(t *testing.T) {
	path := isolate(t)
	writeConfig(t, path, "[master_password]\nmemory = \"512MiB\"\ntime = 4\nthreads = 2\n")
	t.Setenv(EnvKDFThreads, "8")
	c, err := Load(Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	want := kdf.Params{Time: 4, Memory: 512 * 1024, Threads: 8, KeyLen: kdf.KeyLen}
	if c.KDF() != want || c.KDFMemory.Source != FromFile || c.KDFThreads.Source != FromEnv {
		t.Errorf("KDF = %+v (memory from %v, threads from %v), want %+v", c.KDF(), c.KDFMemory.Source, c.KDFThreads.Source, want)
	}
	for v, kib := range map[string]uint32{"19MiB": 19 * 1024, "1GiB": 1 << 20, "65536KiB": 65536, " 64 MiB ": 64 * 1024} {
		t.Setenv(EnvKDFMemory, v)
		if c, err := Load(Overrides{}); err != nil || c.KDFMemory.Value != kib {
			t.Errorf("%s = %q: %v; want %d KiB", EnvKDFMemory, v, err, kib)
		}
	}
}

func TestLoad_FileThenEnvThenFlag(t *testing.T) {
	path := isolate(t)
	writeConfig(t, path, `
# a comment
db_path = "~/vaults/sesh.db"
clipboard_timeout = "45s"

[agent]
idle_timeout = "30m"

[audit]
retention_days = 30
`)
	c, err := Load(Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if !c.FileFound || c.DBPath.Source != FromFile || c.DBPath.Value != filepath.Join(home, "vaults", "sesh.db") ||
		c.ClipboardTimeout.Value != 45*time.Second || c.AgentIdleTimeout.Value != 30*time.Minute ||
		c.AgentMaxLifetime.Source != FromDefault || c.AuditRetentionDays.Value != 30 {
		t.Fatalf("file values not applied: %+v", c)
	}

	t.Setenv(EnvAgentIdleTimeout, "5m")
	t.Setenv(EnvAuditRetentionDays, "0")
	c, err = Load(Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	if c.AgentIdleTimeout.Value != 5*time.Minute || c.AgentIdleTimeout.Source != FromEnv || c.DBPath.Source != FromFile {
		t.Fatalf("env didn't override the file: idle %+v, db path %+v", c.AgentIdleTimeout, c.DBPath)
	}
	if c.AuditRetentionDays.Value != 0 || c.AuditRetentionDays.Source != FromEnv || c.AuditRetentionDays.Origin != EnvAuditRetentionDays {
		t.Fatalf("env didn't override the audit retention: %+v", c.AuditRetentionDays)
	}

	t.Setenv(EnvDBPath, "/tmp/env.db")
	c, err = Load(Overrides{DBPath: "/tmp/x.db"})
	if err != nil {
		t.Fatal(err)
	}
	if c.DBPath.Value != "/tmp/x.db" || c.DBPath.Source != FromFlag {
		t.Fatalf("flags didn't override env and file: %+v", c.DBPath)
	}
}

func TestLoad_Rejects(t *testing.T) {
	tests := map[string]struct {
		file, wantSub string
		env           map[string]string
		flags         Overrides
	}{
		"unknown file key":                  {file: "db_path = \"/tmp/x.db\"\ndb_pth = \"x\"\n", wantSub: "unknown setting db_pth"},
		"unknown agent key":                 {file: "[agent]\nidle = \"1m\"\n", wantSub: "unknown setting agent.idle"},
		"backend is no longer a setting":    {file: `backend = "sqlite"`, wantSub: "unknown setting backend (remove it: the vault is the only store now)"},
		"key_source is no longer a setting": {file: `key_source = "password"`, wantSub: "unknown setting key_source (remove it: the master password is the only key source now)"},
		"relative db path":                  {file: `db_path = "vault.db"`, wantSub: "want an absolute path"},
		"vault named touchid.key":           {file: `db_path = "~/vaults/touchid.key"`, wantSub: `"touchid.key" is the name of a file sesh keeps next to the vault, so the vault would be overwritten; choose another name, such as passwords.db`},
		"vault named in other case":         {file: `db_path = "~/vaults/TouchID.Key"`, wantSub: `"TouchID.Key" is the name of a file sesh keeps next to the vault`},
		"vault named touchid.key (env)":     {env: map[string]string{EnvDBPath: "/tmp/v/TOUCHID.KEY"}, wantSub: `SESH_DB_PATH = "/tmp/v/TOUCHID.KEY": "TOUCHID.KEY" is the name`},
		"vault named touchid.key (flag)":    {flags: Overrides{DBPath: "/tmp/v/touchid.KEY"}, wantSub: `--db-path = "/tmp/v/touchid.KEY": "touchid.KEY" is the name`},
		"bad duration":                      {file: `clipboard_timeout = "soon"`, wantSub: "want a duration"},
		"memory below the floor":            {file: "[master_password]\nmemory = \"8MiB\"\n", wantSub: `master_password.memory in`},
		"memory above the ceiling":          {env: map[string]string{EnvKDFMemory: "2GiB"}, wantSub: `SESH_KDF_MEMORY = "2GiB": want an amount of memory from 19MiB (OWASP's minimum for Argon2id) to 1GiB`},
		"memory without a unit":             {env: map[string]string{EnvKDFMemory: "262144"}, wantSub: `SESH_KDF_MEMORY = "262144": want an amount of memory`},
		"memory as a number in the file":    {file: "[master_password]\nmemory = 262144\n", wantSub: "read config file"},
		"one pass":                          {file: "[master_password]\ntime = 1\n", wantSub: `= "1": want a number of passes from 2 (OWASP's minimum for Argon2id) to 10`},
		"too many passes":                   {env: map[string]string{EnvKDFTime: "11"}, wantSub: `SESH_KDF_TIME = "11": want a number of passes`},
		"passes not a number":               {env: map[string]string{EnvKDFTime: "three"}, wantSub: `SESH_KDF_TIME = "three": want a number of passes`},
		"no threads":                        {file: "[master_password]\nthreads = 0\n", wantSub: `= "0": want a number of threads from 1 to 16`},
		"too many threads":                  {env: map[string]string{EnvKDFThreads: "17"}, wantSub: `SESH_KDF_THREADS = "17": want a number of threads`},
		"unknown master_password key":       {file: "[master_password]\nsalt = \"x\"\n", wantSub: "unknown setting master_password.salt"},
		"negative duration":                 {env: map[string]string{EnvAgentIdleTimeout: "-1m"}, wantSub: "must not be negative"},
		"not TOML":                          {file: "db_path: /tmp/x.db\n", wantSub: "read config file"},
		"wrong type in the file":            {file: "clipboard_timeout = 30\n", wantSub: "read config file"},
		"unknown audit key":                 {file: "[audit]\nretention = 30\n", wantSub: "unknown setting audit.retention"},
		"retention as a string":             {file: "[audit]\nretention_days = \"30\"\n", wantSub: "read config file"},
		"negative retention":                {file: "[audit]\nretention_days = -1\n", wantSub: "audit.retention_days in"},
		"retention too long":                {env: map[string]string{EnvAuditRetentionDays: "36501"}, wantSub: `SESH_AUDIT_RETENTION_DAYS = "36501": want a whole number of days from 0 (keep everything) to 36500`},
		"retention not a number":            {env: map[string]string{EnvAuditRetentionDays: "90d"}, wantSub: `SESH_AUDIT_RETENTION_DAYS = "90d": want a whole number of days`},
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
