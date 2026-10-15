package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// setLine changes only the key's line, keeping comments and order, or adds one where it belongs.
func TestSetLine(t *testing.T) {
	file := `# my settings
clipboard_timeout = "30s"   # long enough

[backup]
keep = 7
every_days = 1 # daily

[history]
keep = 10
`
	for _, c := range []struct {
		name, text, key, value, want string
	}{
		{"a key at the top", file, "clipboard_timeout", `"45s"`, strings.Replace(file, `"30s"`, `"45s"`, 1)},
		{"a key in a table, its comment kept", file, "backup.every_days", "3", strings.Replace(file, "every_days = 1 # daily", "every_days = 3 # daily", 1)},
		{"the same name in another table", file, "history.keep", "4", strings.Replace(file, "keep = 10", "keep = 4", 1)},
		{"a new key in a table", file, "backup.dir", `"~/b"`, strings.Replace(file, "every_days = 1 # daily\n", "every_days = 1 # daily\ndir = \"~/b\"\n", 1)},
		{"a new table", file, "trash.keep_days", "7", file + "\n[trash]\nkeep_days = 7\n"},
		{"a new key at the top", file, "db_path", `"~/v.db"`, strings.Replace(file, "\n\n[backup]", "\ndb_path = \"~/v.db\"\n\n[backup]", 1)},
		{"taken out", file, "backup.keep", "", strings.Replace(file, "keep = 7\n", "", 1)},
		{"taken out when not there", file, "trash.keep_days", "", file},
		{"an empty file", "", "clipboard_timeout", `"45s"`, "clipboard_timeout = \"45s\"\n"},
		{"a dotted key at the top", "agent.idle_timeout = \"5m\"\n", "agent.idle_timeout", `"7m"`, "agent.idle_timeout = \"7m\"\n"},
		{"Windows line ends", "[backup]\r\nkeep = 7\r\n", "backup.keep", "9", "[backup]\r\nkeep = 9\r\n"},
		{"a table header with a comment", "[backup]\ndir = \"/b\"\n[history] # earlier secrets\nkeep = 10\n", "history.keep", "4", "[backup]\ndir = \"/b\"\n[history] # earlier secrets\nkeep = 4\n"},
		{"taken out of another table, not this", "[backup]\ndir = \"/b\"\n[history] # x\nkeep = 10\n", "backup.keep", "", "[backup]\ndir = \"/b\"\n[history] # x\nkeep = 10\n"},
		{"no line end at the end", "[backup]\nkeep = 7", "backup.dir", `"/b"`, "[backup]\nkeep = 7\ndir = \"/b\"\n"},
		{"an added line with Windows line ends", "[backup]\r\nkeep = 7\r\n", "backup.dir", `"/b"`, "[backup]\r\nkeep = 7\r\ndir = \"/b\"\r\n"},
		{"a byte order mark", "\uFEFF[backup]\nkeep = 7\n", "backup.keep", "9", "\uFEFF[backup]\nkeep = 9\n"},
		{"a byte order mark before a key", "\uFEFFclipboard_timeout = \"30s\"\n", "clipboard_timeout", `"45s"`, "\uFEFFclipboard_timeout = \"45s\"\n"},
		{"a byte order mark before the first table", "\uFEFF[backup]\nkeep = 7\n", "db_path", `"/v.db"`, "\uFEFFdb_path = \"/v.db\"\n[backup]\nkeep = 7\n"},
		{"below the file's opening comment", "# sesh settings\n# see docs\n\n[backup]\nkeep = 7\n", "db_path", `"/v.db"`, "# sesh settings\n# see docs\n\ndb_path = \"/v.db\"\n[backup]\nkeep = 7\n"},
		{"above the comment that names a table", "clipboard_timeout = \"30s\"\n\n# Backups go here\n[backup]\nkeep = 7\n", "db_path", `"/v.db"`, "clipboard_timeout = \"30s\"\ndb_path = \"/v.db\"\n\n# Backups go here\n[backup]\nkeep = 7\n"},
	} {
		if got := setLine(c.text, c.key, c.value); got != c.want {
			t.Errorf("%s:\ngot\n%s\nwant\n%s", c.name, got, c.want)
		}
	}
}

// Set writes a value sesh then reads; a value it refuses leaves the file as it was.
func TestSet(t *testing.T) {
	path := isolate(t)
	writeConfig(t, path, "# mine\n[agent]\nidle_timeout = \"10m\"\n")
	if err := Set(path, "agent.idle_timeout", "25m"); err != nil {
		t.Fatal(err)
	}
	// A number is written as one: +04 is 4.
	if err := Set(path, "history.keep", "+04"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), "keep = 4\n") { //nolint:errcheck // checked
		t.Errorf("+04 written as:\n%s", b)
	}
	c, err := Load(Overrides{})
	if err != nil || c.AgentIdleTimeout.Value != 25*time.Minute || c.HistoryKeep.Value != 4 {
		t.Fatalf("after setting: %+v, %+v, %v", c.AgentIdleTimeout, c.HistoryKeep, err)
	}
	before, _ := os.ReadFile(path) //nolint:errcheck // checked below
	for key, bad := range map[string]string{"history.keep": "-1", "agent.idle_timeout": "soon", "backup.keep": "seven", "nonsense": "1"} {
		if err := Set(path, key, bad); err == nil {
			t.Errorf("%s = %q was taken", key, bad)
		}
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) || !strings.HasPrefix(string(after), "# mine\n") { //nolint:errcheck // compared
		t.Errorf("the file after refused values:\n%s", after)
	}
	if err := Set(path, "history.keep", ""); err != nil {
		t.Fatal(err)
	}
	if c, err := Load(Overrides{}); err != nil || c.HistoryKeep.Source != FromDefault {
		t.Errorf("taken out: %+v, %v", c.HistoryKeep, err)
	}
	fresh := filepath.Join(t.TempDir(), "new", "config.toml")
	if err := Set(fresh, "clipboard_timeout", "45s"); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(fresh); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("a new file: %v, %v", info, err)
	}
}

func TestDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		30 * time.Second: "30s", 90 * time.Second: "1m30s", 10 * time.Minute: "10m",
		8 * time.Hour: "8h", 90 * time.Minute: "1h30m", 0: "0 (off)",
	} {
		if got := Duration(d); got != want {
			t.Errorf("Duration(%v) = %q, want %q", d, got, want)
		}
	}
}

// A linked config file (a dotfile manager's) is changed where it is, the link kept;
// nothing changed writes nothing; a removal leaves every other setting alone.
func TestSetFilesAndOthers(t *testing.T) {
	path := isolate(t)
	dotfiles := filepath.Join(t.TempDir(), "dotfiles", "sesh.toml")
	writeConfig(t, dotfiles, "[history]\nkeep = 10\n")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dotfiles, path); err != nil {
		t.Fatal(err)
	}
	if err := Set(path, "history.keep", "4"); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the link was replaced: %v, %v", info, err)
	}
	if body, _ := os.ReadFile(dotfiles); string(body) != "[history]\nkeep = 4\n" { //nolint:errcheck // compared
		t.Errorf("the linked file: %q", body)
	}
	empty := filepath.Join(t.TempDir(), "config.toml")
	if err := Set(empty, "history.keep", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(empty); !os.IsNotExist(err) {
		t.Errorf("taking out a setting that isn't there made a file: %v", err)
	}
	if err := os.WriteFile(empty, []byte("[backup]\nkeep = 7\n[history] # x\nkeep = 10\n"), 0o644); err != nil { //nolint:gosec // test
		t.Fatal(err)
	}
	if err := Set(empty, "backup.keep", "3"); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(empty); err != nil || info.Mode().Perm() != 0o644 {
		t.Errorf("the file's mode: %v, %v", info, err)
	}
}

// checkSet refuses a change that would move another setting.
func TestCheckSetOthers(t *testing.T) {
	old := "[backup]\nkeep = 7\n[history]\nkeep = 10\n"
	if err := checkSet("config.toml", old, "[backup]\nkeep = 7\n[history]\n", "backup.keep", true); err == nil || !strings.Contains(err.Error(), "would change history.keep too") {
		t.Errorf("another setting lost: %v", err)
	}
}

// A path under home is shown, and so written back, with ~; each setting says its default.
func TestListRawAndDefaults(t *testing.T) {
	path := isolate(t)
	writeConfig(t, path, "[backup]\ndir = \"~/bk\"\n[history]\nkeep = 4\n")
	c, err := Load(Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Item{}
	for _, it := range c.List() {
		got[it.Key] = it
	}
	if d := got["backup.dir"]; d.Raw != "~/bk" {
		t.Errorf("backup.dir raw = %q", d.Raw)
	}
	if h := got["history.keep"]; h.Raw != "4" || h.Default != "10" {
		t.Errorf("history.keep = %+v", h)
	}
}

// ui.lock_on_quit is on unless turned off; true or false, read from the file or the environment, and written bare.
func TestLockOnQuit(t *testing.T) {
	path := isolate(t)
	if c, err := Load(Overrides{}); err != nil || !c.UILockOnQuit.Value || c.UILockOnQuit.Source != FromDefault {
		t.Fatalf("default: %+v, %v", c.UILockOnQuit, err)
	}
	if err := Set(path, "ui.lock_on_quit", "false"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), "[ui]\nlock_on_quit = false\n") { //nolint:errcheck // compared
		t.Errorf("written:\n%s", b)
	}
	c, err := Load(Overrides{})
	if err != nil || c.UILockOnQuit.Value || c.UILockOnQuit.Source != FromFile {
		t.Fatalf("from the file: %+v, %v", c.UILockOnQuit, err)
	}
	var it Item
	for _, x := range c.List() {
		if x.Key == "ui.lock_on_quit" {
			it = x
		}
	}
	if !it.Switch || it.Raw != "false" || it.Default != "true" || it.Value != "off" {
		t.Errorf("listed: %+v", it)
	}
	if err := Set(path, "ui.lock_on_quit", "yes"); err == nil || !strings.Contains(err.Error(), "want true or false") {
		t.Errorf("yes: %v", err)
	}
	t.Setenv(EnvUILockOnQuit, "true")
	if c, err := Load(Overrides{}); err != nil || !c.UILockOnQuit.Value || c.UILockOnQuit.Source != FromEnv {
		t.Errorf("from the environment: %+v, %v", c.UILockOnQuit, err)
	}
	t.Setenv(EnvUILockOnQuit, "1")
	if _, err := Load(Overrides{}); err == nil || !strings.Contains(err.Error(), "want true or false") {
		t.Errorf("1 from the environment: %v", err)
	}
}

// The agent's lock-on-sleep and lock-on-screen-lock switches are on unless turned off, in the file's [agent]
// table or the environment.
func TestAgentLockSwitches(t *testing.T) {
	path := isolate(t)
	c, err := Load(Overrides{})
	if err != nil || !c.AgentLockOnSleep.Value || !c.AgentLockOnScreenLock.Value {
		t.Fatalf("defaults: %+v %+v, %v", c.AgentLockOnSleep, c.AgentLockOnScreenLock, err)
	}
	for _, key := range []string{"agent.lock_on_sleep", "agent.lock_on_screen_lock"} {
		if err := Set(path, key, "false"); err != nil {
			t.Fatal(err)
		}
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), "[agent]\nlock_on_sleep = false\nlock_on_screen_lock = false\n") { //nolint:errcheck // compared
		t.Errorf("written:\n%s", b)
	}
	c, err = Load(Overrides{})
	if err != nil || c.AgentLockOnSleep.Value || c.AgentLockOnScreenLock.Value || c.AgentLockOnSleep.Source != FromFile {
		t.Fatalf("from the file: %+v %+v, %v", c.AgentLockOnSleep, c.AgentLockOnScreenLock, err)
	}
	t.Setenv(EnvAgentLockOnSleep, "true")
	t.Setenv(EnvAgentLockOnScreen, "true")
	if c, err := Load(Overrides{}); err != nil || !c.AgentLockOnSleep.Value || !c.AgentLockOnScreenLock.Value || c.AgentLockOnScreenLock.Source != FromEnv {
		t.Errorf("from the environment: %+v %+v, %v", c.AgentLockOnSleep, c.AgentLockOnScreenLock, err)
	}
}
