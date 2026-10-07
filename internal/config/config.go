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
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/bashhack/sesh/internal/agent"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/kdf"
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

// DefaultClipboardTimeout is how long a copied secret stays on the
// clipboard before sesh clears it.
const DefaultClipboardTimeout = 30 * time.Second

// DefaultAuditRetentionDays is how long the vault keeps audit log events;
// MaxAuditRetentionDays is the longest it accepts. 0 keeps everything.
const (
	DefaultAuditRetentionDays = 90
	MaxAuditRetentionDays     = 36500
)

// Backup defaults: one a day, the newest seven kept. MaxBackupKeep is the
// most a setting can keep.
const (
	DefaultBackupEveryDays = 1
	DefaultBackupKeep      = 7
	MaxBackupKeep          = 1000
)

// Config is sesh's resolved settings.
type Config struct {
	// Path is the config file sesh looked for; FileFound says whether it
	// existed.
	Path             string
	DBPath           Setting[string]
	ClipboardTimeout Setting[time.Duration]
	AgentIdleTimeout Setting[time.Duration]
	AgentMaxLifetime Setting[time.Duration]
	// AuditRetentionDays is how many days of audit log events the vault
	// keeps; 0 keeps everything.
	AuditRetentionDays Setting[int]
	// BackupDir is where backups go; "" means a backups folder next to the
	// vault (see BackupFolder).
	BackupDir Setting[string]
	// BackupEveryDays is how old the newest backup can be before a command
	// that unlocks the vault makes another; 0 turns that off.
	BackupEveryDays Setting[int]
	// BackupKeep is how many backups are kept; older ones are removed.
	BackupKeep Setting[int]
	// KDFMemory (KiB), KDFTime and KDFThreads are the Argon2id settings a
	// new master password key, or an encrypted export, is derived with.
	KDFMemory  Setting[uint32]
	KDFTime    Setting[uint32]
	KDFThreads Setting[uint8]
	FileFound  bool
}

// BackupFolder is where backups go: BackupDir, or a backups folder next to
// the vault.
func (c *Config) BackupFolder() string {
	if c.BackupDir.Value != "" {
		return c.BackupDir.Value
	}
	return filepath.Join(filepath.Dir(c.DBPath.Value), "backups")
}

// KDF is the configured Argon2id settings.
func (c *Config) KDF() kdf.Params {
	return kdf.Params{Time: c.KDFTime.Value, Memory: c.KDFMemory.Value, Threads: c.KDFThreads.Value, KeyLen: kdf.KeyLen}
}

// Overrides are values given as command-line flags. Empty means unset.
type Overrides struct {
	DBPath string
}

// Env var names.
const (
	EnvDBPath             = "SESH_DB_PATH"
	EnvClipboardTimeout   = "SESH_CLIPBOARD_TIMEOUT"
	EnvAgentIdleTimeout   = "SESH_AGENT_IDLE_TIMEOUT"
	EnvAgentMaxLifetime   = "SESH_AGENT_MAX_LIFETIME"
	EnvAuditRetentionDays = "SESH_AUDIT_RETENTION_DAYS"
	EnvKDFMemory          = "SESH_KDF_MEMORY"
	EnvKDFTime            = "SESH_KDF_TIME"
	EnvKDFThreads         = "SESH_KDF_THREADS"
	EnvBackupDir          = "SESH_BACKUP_DIR"
	EnvBackupEveryDays    = "SESH_BACKUP_EVERY_DAYS"
	EnvBackupKeep         = "SESH_BACKUP_KEEP"
)

// fileConfig is the config file's shape. Durations are strings such as
// "10m", parsed with time.ParseDuration.
type fileConfig struct {
	Backup struct {
		Dir       string `toml:"dir"`
		EveryDays int64  `toml:"every_days"`
		Keep      int64  `toml:"keep"`
	} `toml:"backup"`
	DBPath           string `toml:"db_path"`
	ClipboardTimeout string `toml:"clipboard_timeout"`
	Agent            struct {
		IdleTimeout string `toml:"idle_timeout"`
		MaxLifetime string `toml:"max_lifetime"`
	} `toml:"agent"`
	MasterPassword struct {
		Memory  string `toml:"memory"`
		Time    int64  `toml:"time"`
		Threads int64  `toml:"threads"`
	} `toml:"master_password"`
	Audit struct {
		RetentionDays int64 `toml:"retention_days"`
	} `toml:"audit"`
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
		Path:               path,
		DBPath:             Setting[string]{Value: dbDefault},
		ClipboardTimeout:   Setting[time.Duration]{Value: DefaultClipboardTimeout},
		AgentIdleTimeout:   Setting[time.Duration]{Value: agent.DefaultIdleTimeout},
		AgentMaxLifetime:   Setting[time.Duration]{Value: agent.DefaultMaxLifetime},
		AuditRetentionDays: Setting[int]{Value: DefaultAuditRetentionDays},
		BackupEveryDays:    Setting[int]{Value: DefaultBackupEveryDays},
		BackupKeep:         Setting[int]{Value: DefaultBackupKeep},
	}
	c.defaultKDF()
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
			switch keys[i] {
			case "backend":
				keys[i] += " (remove it: the vault is the only store now)"
			case "key_source":
				keys[i] += " (remove it: the master password is the only key source now)"
			}
		}
		sort.Strings(keys)
		return fmt.Errorf("config file %s: unknown setting %s", c.Path, strings.Join(keys, ", "))
	}
	in := func(key string) bool { return md.IsDefined(strings.Split(key, ".")...) }
	from := func(key string) string { return fmt.Sprintf("%s in %s", key, c.Path) }
	if in("db_path") {
		if err := setDBPath(&c.DBPath, f.DBPath, FromFile, from("db_path")); err != nil {
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
	if in("audit.retention_days") {
		if err := setRetention(&c.AuditRetentionDays, f.Audit.RetentionDays, strconv.FormatInt(f.Audit.RetentionDays, 10), FromFile, from("audit.retention_days")); err != nil {
			return err
		}
	}
	if in("backup.dir") {
		if err := setPath(&c.BackupDir, f.Backup.Dir, FromFile, from("backup.dir")); err != nil {
			return err
		}
	}
	if in("backup.every_days") {
		if err := setBackupEveryDays(&c.BackupEveryDays, f.Backup.EveryDays, strconv.FormatInt(f.Backup.EveryDays, 10), FromFile, from("backup.every_days")); err != nil {
			return err
		}
	}
	if in("backup.keep") {
		if err := setBackupKeep(&c.BackupKeep, f.Backup.Keep, strconv.FormatInt(f.Backup.Keep, 10), FromFile, from("backup.keep")); err != nil {
			return err
		}
	}
	if in("master_password.memory") {
		if err := setKDFMemory(&c.KDFMemory, f.MasterPassword.Memory, FromFile, from("master_password.memory")); err != nil {
			return err
		}
	}
	if in("master_password.time") {
		if err := setKDFTime(&c.KDFTime, f.MasterPassword.Time, strconv.FormatInt(f.MasterPassword.Time, 10), FromFile, from("master_password.time")); err != nil {
			return err
		}
	}
	if in("master_password.threads") {
		if err := setKDFThreads(&c.KDFThreads, f.MasterPassword.Threads, strconv.FormatInt(f.MasterPassword.Threads, 10), FromFile, from("master_password.threads")); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) applyEnv() error {
	if v, ok := os.LookupEnv(EnvDBPath); ok && v != "" {
		if err := setDBPath(&c.DBPath, v, FromEnv, EnvDBPath); err != nil {
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
	if v, ok := os.LookupEnv(EnvAuditRetentionDays); ok && v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			n = -1 // reported as out of range below, with the value as given
		}
		if err := setRetention(&c.AuditRetentionDays, n, v, FromEnv, EnvAuditRetentionDays); err != nil {
			return err
		}
	}
	if v, ok := os.LookupEnv(EnvBackupDir); ok && v != "" {
		if err := setPath(&c.BackupDir, v, FromEnv, EnvBackupDir); err != nil {
			return err
		}
	}
	for _, d := range []struct {
		set func(*Setting[int], int64, string, Source, string) error
		dst *Setting[int]
		env string
	}{
		{setBackupEveryDays, &c.BackupEveryDays, EnvBackupEveryDays},
		{setBackupKeep, &c.BackupKeep, EnvBackupKeep},
	} {
		if v, ok := os.LookupEnv(d.env); ok && v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				n = -1 // reported as out of range, with the value as given
			}
			if err := d.set(d.dst, n, v, FromEnv, d.env); err != nil {
				return err
			}
		}
	}
	return c.applyKDFEnv()
}

// KDFFromEnv resolves the Argon2id settings from the environment and the
// defaults alone, ignoring any config file: what sesh init, which writes a
// file without them, creates a vault with.
func KDFFromEnv() (kdf.Params, error) {
	var c Config
	c.defaultKDF()
	if err := c.applyKDFEnv(); err != nil {
		return kdf.Params{}, err
	}
	return c.KDF(), nil
}

func (c *Config) defaultKDF() {
	c.KDFMemory = Setting[uint32]{Value: kdf.DefaultMemoryKiB}
	c.KDFTime = Setting[uint32]{Value: kdf.DefaultTime}
	c.KDFThreads = Setting[uint8]{Value: kdf.DefaultThreads}
}

func (c *Config) applyKDFEnv() error {
	if v, ok := os.LookupEnv(EnvKDFMemory); ok && v != "" {
		if err := setKDFMemory(&c.KDFMemory, v, FromEnv, EnvKDFMemory); err != nil {
			return err
		}
	}
	for _, e := range []struct {
		set func(n int64, raw string) error
		env string
	}{
		{func(n int64, raw string) error { return setKDFTime(&c.KDFTime, n, raw, FromEnv, EnvKDFTime) }, EnvKDFTime},
		{func(n int64, raw string) error { return setKDFThreads(&c.KDFThreads, n, raw, FromEnv, EnvKDFThreads) }, EnvKDFThreads},
	} {
		if v, ok := os.LookupEnv(e.env); ok && v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				n = -1 // reported as out of range, with the value as given
			}
			if err := e.set(n, v); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Config) applyFlags(o Overrides) error {
	if o.DBPath != "" {
		if err := setDBPath(&c.DBPath, o.DBPath, FromFlag, "--db-path"); err != nil {
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

// setPath accepts an absolute path or one starting with ~/.
func setPath(dst *Setting[string], v string, src Source, origin string) error {
	p, err := ResolvePath(v)
	if err != nil {
		return fmt.Errorf("%s = %q: %w", origin, v, err)
	}
	*dst = Setting[string]{Value: p, Source: src, Origin: origin}
	return nil
}

// reservedVaultNames are files sesh keeps next to the vault: the Touch ID
// file (internal/touchid). A vault with one of these names would be
// overwritten by one of them.
var reservedVaultNames = []string{"touchid.key"}

// setDBPath is setPath for the vault's location, which also refuses a file
// name sesh uses for its own files next to the vault.
func setDBPath(dst *Setting[string], v string, src Source, origin string) error {
	// Compared ignoring case: macOS file systems usually do, so TouchID.key
	// would be the same file as touchid.key.
	if p, err := ResolvePath(v); err == nil && slices.ContainsFunc(reservedVaultNames, func(r string) bool { return strings.EqualFold(r, filepath.Base(p)) }) {
		return fmt.Errorf("%s = %q: %q is the name of a file sesh keeps next to the vault, so the vault would be overwritten; choose another name, such as passwords.db", origin, v, filepath.Base(p))
	}
	return setPath(dst, v, src, origin)
}

// ResolvePath turns a path setting into a clean absolute path, expanding a
// leading ~/. Relative paths are refused.
func ResolvePath(v string) (string, error) {
	p := v
	if rest, ok := strings.CutPrefix(v, "~/"); ok {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand ~: %w", err)
		}
		p = filepath.Join(home, rest)
	}
	if !filepath.IsAbs(p) {
		return "", errors.New("want an absolute path or one starting with ~/")
	}
	return filepath.Clean(p), nil
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

// setKDFMemory accepts an amount of memory such as 256MiB or 1GiB, from
// kdf.MinMemoryKiB to kdf.MaxMemoryKiB.
func setKDFMemory(dst *Setting[uint32], v string, src Source, origin string) error {
	kib, ok := parseMemory(v)
	if !ok || kib < kdf.MinMemoryKiB || kib > kdf.MaxMemoryKiB {
		return fmt.Errorf("%s = %q: want an amount of memory from %dMiB (OWASP's minimum for Argon2id) to %dGiB, such as 256MiB", origin, v, kdf.MinMemoryKiB/1024, kdf.MaxMemoryKiB/(1024*1024))
	}
	*dst = Setting[uint32]{Value: uint32(kib), Source: src, Origin: origin} //nolint:gosec // bounded by kdf.MaxMemoryKiB above
	return nil
}

// parseMemory reads an amount of memory written with a KiB, MiB or GiB
// unit, as KiB.
func parseMemory(v string) (int64, bool) {
	s := strings.TrimSpace(v)
	for _, u := range []struct {
		suffix string
		kib    int64
	}{{"KiB", 1}, {"MiB", 1024}, {"GiB", 1024 * 1024}} {
		if num, ok := strings.CutSuffix(s, u.suffix); ok {
			n, err := strconv.ParseInt(strings.TrimSpace(num), 10, 64)
			if err != nil || n < 0 || n > kdf.MaxMemoryKiB {
				return 0, false
			}
			return n * u.kib, true
		}
	}
	return 0, false
}

// setKDFTime accepts a number of passes from kdf.MinTime to kdf.MaxTime;
// raw is the value as written, for the error.
func setKDFTime(dst *Setting[uint32], n int64, raw string, src Source, origin string) error {
	if n < kdf.MinTime || n > kdf.MaxTime {
		return fmt.Errorf("%s = %q: want a number of passes from %d (OWASP's minimum for Argon2id) to %d", origin, raw, kdf.MinTime, kdf.MaxTime)
	}
	*dst = Setting[uint32]{Value: uint32(n), Source: src, Origin: origin} //nolint:gosec // bounded by kdf.MaxTime above
	return nil
}

// setKDFThreads accepts a number of threads from kdf.MinThreads to
// kdf.MaxThreads; raw is the value as written, for the error.
func setKDFThreads(dst *Setting[uint8], n int64, raw string, src Source, origin string) error {
	if n < kdf.MinThreads || n > kdf.MaxThreads {
		return fmt.Errorf("%s = %q: want a number of threads from %d to %d", origin, raw, kdf.MinThreads, kdf.MaxThreads)
	}
	*dst = Setting[uint8]{Value: uint8(n), Source: src, Origin: origin} //nolint:gosec // bounded by kdf.MaxThreads above
	return nil
}

// setRetention accepts a whole number of days from 0 to
// MaxAuditRetentionDays; raw is the value as written, for the error.
// setBackupEveryDays sets how many days old the newest backup may get, 0
// (no automatic backups) to MaxAuditRetentionDays.
func setBackupEveryDays(dst *Setting[int], n int64, raw string, src Source, origin string) error {
	if n < 0 || n > MaxAuditRetentionDays {
		return fmt.Errorf("%s = %q: want a whole number of days from 0 (no automatic backups) to %d", origin, raw, MaxAuditRetentionDays)
	}
	*dst = Setting[int]{Value: int(n), Source: src, Origin: origin}
	return nil
}

// setBackupKeep sets how many backups are kept, 1 to MaxBackupKeep.
func setBackupKeep(dst *Setting[int], n int64, raw string, src Source, origin string) error {
	if n < 1 || n > MaxBackupKeep {
		return fmt.Errorf("%s = %q: want a whole number of backups to keep, from 1 to %d", origin, raw, MaxBackupKeep)
	}
	*dst = Setting[int]{Value: int(n), Source: src, Origin: origin}
	return nil
}

func setRetention(dst *Setting[int], n int64, raw string, src Source, origin string) error {
	if n < 0 || n > MaxAuditRetentionDays {
		return fmt.Errorf("%s = %q: want a whole number of days from 0 (keep everything) to %d", origin, raw, MaxAuditRetentionDays)
	}
	*dst = Setting[int]{Value: int(n), Source: src, Origin: origin}
	return nil
}
