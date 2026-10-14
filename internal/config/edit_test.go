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
	if err := Set(path, "history.keep", "4"); err != nil {
		t.Fatal(err)
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
