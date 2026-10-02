package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestSetTopLevel(t *testing.T) {
	tests := map[string]struct {
		before, want string
	}{
		"replaces the value, keeping comments and other lines": {
			before: "# my settings\nbackend = \"sqlite\"\nkey_source = \"keychain\"   # switched in May\n\n[agent]\nidle_timeout = \"30m\"\n",
			want:   "# my settings\nbackend = \"sqlite\"\nkey_source = \"password\" # switched in May\n\n[agent]\nidle_timeout = \"30m\"\n",
		},
		"adds the key before the first table": {
			before: "# my settings\nbackend = \"sqlite\"\n[agent]\nidle_timeout = \"30m\"\n",
			want:   "# my settings\nbackend = \"sqlite\"\nkey_source = \"password\"\n\n[agent]\nidle_timeout = \"30m\"\n",
		},
		"a key of the same name inside a table is left alone": {
			before: "[agent]\nkey_source = \"x\"\n",
			want:   "key_source = \"password\"\n\n[agent]\nkey_source = \"x\"\n",
		},
		"appends to a file without tables": {
			before: "backend = \"sqlite\"\n",
			want:   "backend = \"sqlite\"\nkey_source = \"password\"\n",
		},
		"creates the file": {
			want: "key_source = \"password\"\n",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sesh", "config.toml")
			if tt.before != "" {
				writeConfig(t, path, tt.before)
			}
			if err := SetTopLevel(path, "key_source", "password"); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("file =\n%s\nwant\n%s", got, tt.want)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Errorf("mode = %o, want 600", info.Mode().Perm())
			}
		})
	}
}

func TestSetTopLevel_ResultParses(t *testing.T) {
	path := isolate(t)
	writeConfig(t, path, "backend = \"sqlite\" # keep\n[agent]\nmax_lifetime = \"2h\"\n")
	if err := SetTopLevel(path, "key_source", "keychain"); err != nil {
		t.Fatal(err)
	}
	c, err := Load(Overrides{})
	if err != nil {
		t.Fatalf("Load after SetTopLevel: %v", err)
	}
	if c.KeySource.Value != "keychain" || c.KeySource.Source != FromFile || c.AgentMaxLifetime.Value.String() != "2h0m0s" {
		t.Errorf("key source %+v, max lifetime %v", c.KeySource, c.AgentMaxLifetime.Value)
	}
}

func TestSetTopLevel_NeverWritesADuplicateKey(t *testing.T) {
	for name, before := range map[string]string{
		"quoted key":           "\"key_source\" = \"keychain\"\n",
		"literal string value": "key_source = 'keychain'\n",
		"no space before #":    "key_source = \"keychain\"#note\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			writeConfig(t, path, before)
			err := SetTopLevel(path, "key_source", "password")
			got, rerr := os.ReadFile(path)
			if rerr != nil {
				t.Fatal(rerr)
			}
			if err == nil {
				// Updated in place: the result must parse with the new value.
				var v struct {
					KeySource string `toml:"key_source"`
				}
				if _, derr := toml.Decode(string(got), &v); derr != nil || v.KeySource != "password" {
					t.Fatalf("file =\n%s\ndecode err %v, key_source %q", got, derr, v.KeySource)
				}
				return
			}
			if string(got) != before {
				t.Errorf("a refused edit changed the file:\n%s", got)
			}
		})
	}
}
