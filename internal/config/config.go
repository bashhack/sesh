// Package config resolves sesh's settings from, in order of precedence,
// command-line flags, environment variables, the config file
// (~/.config/sesh/config.toml), and built-in defaults.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/bashhack/sesh/internal/agent"
	"github.com/bashhack/sesh/internal/database"
)

// Source is where a setting's value came from.
type Source int

const (
	FromDefault Source = iota
	FromFile
	FromEnv
	FromFlag
)

func (s Source) String() string {
	switch s {
	case FromFile:
		return "config file"
	case FromEnv:
		return "environment"
	case FromFlag:
		return "flag"
	default:
		return "default"
	}
}

// Setting is one resolved value and where it came from. Origin names the
// env var or flag for FromEnv and FromFlag.
type Setting[T any] struct {
	Value  T
	Origin string
	Source Source
}

// Backend values.
const (
	BackendKeychain = "keychain"
	BackendSQLite   = "sqlite"
)

// Key source values.
const (
	KeySourceKeychain = "keychain"
	KeySourcePassword = "password"
)

// DefaultClipboardTimeout is how long a copied secret stays on the
// clipboard before sesh clears it.
const DefaultClipboardTimeout = 30 * time.Second

// Config is sesh's resolved settings.
type Config struct {
	// Path is the config file sesh looked for; FileFound says whether it
	// existed.
	Path             string
	Backend          Setting[string]
	KeySource        Setting[string]
	DBPath           Setting[string]
	ClipboardTimeout Setting[time.Duration]
	AgentIdleTimeout Setting[time.Duration]
	AgentMaxLifetime Setting[time.Duration]
	FileFound        bool
}

// Overrides are values given as command-line flags. Empty means unset.
type Overrides struct {
	Backend   string
	KeySource string
	DBPath    string
}

// Env var names.
const (
	EnvBackend          = "SESH_BACKEND"
	EnvKeySource        = "SESH_KEY_SOURCE"
	EnvDBPath           = "SESH_DB_PATH"
	EnvClipboardTimeout = "SESH_CLIPBOARD_TIMEOUT"
	EnvAgentIdleTimeout = "SESH_AGENT_IDLE_TIMEOUT"
	EnvAgentMaxLifetime = "SESH_AGENT_MAX_LIFETIME"
)

// fileConfig is the config file's shape. Durations are strings such as
// "10m", parsed with time.ParseDuration.
type fileConfig struct {
	Backend          string `toml:"backend"`
	KeySource        string `toml:"key_source"`
	DBPath           string `toml:"db_path"`
	ClipboardTimeout string `toml:"clipboard_timeout"`
	Agent            struct {
		IdleTimeout string `toml:"idle_timeout"`
		MaxLifetime string `toml:"max_lifetime"`
	} `toml:"agent"`
}

// Path returns the config file's location: $XDG_CONFIG_HOME/sesh/config.toml
// when XDG_CONFIG_HOME is an absolute path, otherwise
// ~/.config/sesh/config.toml, on macOS as well as Linux. A relative
// XDG_CONFIG_HOME is ignored, as the XDG Base Directory spec requires.
func Path() (string, error) {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" && filepath.IsAbs(dir) {
		return filepath.Join(dir, "sesh", "config.toml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory for the config file: %w", err)
	}
	return filepath.Join(home, ".config", "sesh", "config.toml"), nil
}

// Load resolves every setting. A missing config file is fine; an
// unreadable or invalid one, an unknown key, or an invalid value from any
// source is an error naming the setting and where the value came from.
func Load(o Overrides) (*Config, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}
	dbDefault, err := database.DefaultDBLocation()
	if err != nil {
		return nil, fmt.Errorf("resolve default database path: %w", err)
	}
	c := &Config{
		Path:             path,
		Backend:          Setting[string]{Value: BackendSQLite},
		KeySource:        Setting[string]{Value: KeySourcePassword},
		DBPath:           Setting[string]{Value: dbDefault},
		ClipboardTimeout: Setting[time.Duration]{Value: DefaultClipboardTimeout},
		AgentIdleTimeout: Setting[time.Duration]{Value: agent.DefaultIdleTimeout},
		AgentMaxLifetime: Setting[time.Duration]{Value: agent.DefaultMaxLifetime},
	}
	if err := c.applyFile(); err != nil {
		return nil, err
	}
	if err := c.applyEnv(); err != nil {
		return nil, err
	}
	if err := c.applyFlags(o); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) applyFile() error {
	var f fileConfig
	md, err := toml.DecodeFile(c.Path, &f)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read config file %s: %w", c.Path, err)
	}
	c.FileFound = true
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		sort.Strings(keys)
		return fmt.Errorf("config file %s: unknown setting %s", c.Path, strings.Join(keys, ", "))
	}
	in := func(key string) bool { return md.IsDefined(strings.Split(key, ".")...) }
	from := func(key string) string { return fmt.Sprintf("%s in %s", key, c.Path) }
	if in("backend") {
		if err := setChoice(&c.Backend, f.Backend, FromFile, from("backend"), BackendSQLite, BackendKeychain); err != nil {
			return err
		}
	}
	if in("key_source") {
		if err := setChoice(&c.KeySource, f.KeySource, FromFile, from("key_source"), KeySourcePassword, KeySourceKeychain); err != nil {
			return err
		}
	}
	if in("db_path") {
		if err := setPath(&c.DBPath, f.DBPath, FromFile, from("db_path")); err != nil {
			return err
		}
	}
	for _, d := range []struct {
		dst *Setting[time.Duration]
		key string
		raw string
	}{
		{&c.ClipboardTimeout, "clipboard_timeout", f.ClipboardTimeout},
		{&c.AgentIdleTimeout, "agent.idle_timeout", f.Agent.IdleTimeout},
		{&c.AgentMaxLifetime, "agent.max_lifetime", f.Agent.MaxLifetime},
	} {
		if in(d.key) {
			if err := setDuration(d.dst, d.raw, FromFile, from(d.key)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Config) applyEnv() error {
	if v, ok := os.LookupEnv(EnvBackend); ok && v != "" {
		if err := setChoice(&c.Backend, v, FromEnv, EnvBackend, BackendSQLite, BackendKeychain); err != nil {
			return err
		}
	}
	if v, ok := os.LookupEnv(EnvKeySource); ok && v != "" {
		if err := setChoice(&c.KeySource, v, FromEnv, EnvKeySource, KeySourcePassword, KeySourceKeychain); err != nil {
			return err
		}
	}
	if v, ok := os.LookupEnv(EnvDBPath); ok && v != "" {
		if err := setPath(&c.DBPath, v, FromEnv, EnvDBPath); err != nil {
			return err
		}
	}
	for _, d := range []struct {
		dst *Setting[time.Duration]
		env string
	}{
		{&c.ClipboardTimeout, EnvClipboardTimeout},
		{&c.AgentIdleTimeout, EnvAgentIdleTimeout},
		{&c.AgentMaxLifetime, EnvAgentMaxLifetime},
	} {
		if v, ok := os.LookupEnv(d.env); ok && v != "" {
			if err := setDuration(d.dst, v, FromEnv, d.env); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Config) applyFlags(o Overrides) error {
	if o.Backend != "" {
		if err := setChoice(&c.Backend, o.Backend, FromFlag, "--backend", BackendSQLite, BackendKeychain); err != nil {
			return err
		}
	}
	if o.KeySource != "" {
		if err := setChoice(&c.KeySource, o.KeySource, FromFlag, "--key-source", KeySourcePassword, KeySourceKeychain); err != nil {
			return err
		}
	}
	if o.DBPath != "" {
		if err := setPath(&c.DBPath, o.DBPath, FromFlag, "--db-path"); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks flag values the way Load does, so a bad flag is reported
// even by commands that never load settings.
func (o Overrides) Validate() error {
	var c Config
	return c.applyFlags(o)
}

func setChoice(dst *Setting[string], v string, src Source, origin string, allowed ...string) error {
	if slices.Contains(allowed, v) {
		*dst = Setting[string]{Value: v, Source: src, Origin: origin}
		return nil
	}
	return fmt.Errorf("%s = %q: want %s", origin, v, quoteOr(allowed))
}

// setPath accepts an absolute path or one starting with ~/.
func setPath(dst *Setting[string], v string, src Source, origin string) error {
	p := v
	if rest, ok := strings.CutPrefix(v, "~/"); ok {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("%s = %q: expand ~: %w", origin, v, err)
		}
		p = filepath.Join(home, rest)
	}
	if !filepath.IsAbs(p) {
		return fmt.Errorf("%s = %q: want an absolute path or one starting with ~/", origin, v)
	}
	*dst = Setting[string]{Value: filepath.Clean(p), Source: src, Origin: origin}
	return nil
}

func setDuration(dst *Setting[time.Duration], v string, src Source, origin string) error {
	d, err := time.ParseDuration(v)
	if err != nil {
		return fmt.Errorf("%s = %q: want a duration such as 30s, 10m, or 8h", origin, v)
	}
	if d < 0 {
		return fmt.Errorf("%s = %q: must not be negative", origin, v)
	}
	*dst = Setting[time.Duration]{Value: d, Source: src, Origin: origin}
	return nil
}

func quoteOr(vs []string) string {
	q := make([]string, len(vs))
	for i, v := range vs {
		q[i] = fmt.Sprintf("%q", v)
	}
	return strings.Join(q, " or ")
}
