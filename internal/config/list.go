package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Item is one setting as sesh shows it: its key in the config file, its
// value as said (Value) and as the file would have it (Raw), where it came
// from, and when a change to it takes effect.
type Item struct {
	Key, Value, Raw string
	Default         string // Raw's default
	Origin          string // the env var or flag, for FromEnv and FromFlag
	Applies         string // when a change takes effect
	Source          Source
	// Editable says whether sesh ui changes it: db_path, where the vault
	// is, isn't changed under an open one.
	Editable bool
	// Switch says it's on or off (Raw true or false), turned over rather
	// than typed.
	Switch bool
}

// List is every setting, in the order sesh shows them, with its default.
func (c *Config) List() []Item {
	out := c.list()
	if d, err := defaults(c.Path); err == nil {
		for i, it := range d.list() {
			out[i].Default = it.Raw
		}
	}
	return out
}

// Keys is the key of every setting sesh changes, in the order sesh shows
// them; it reads nothing.
func Keys() []string {
	var out []string
	for _, it := range (&Config{}).list() {
		if it.Editable {
			out = append(out, it.Key)
		}
	}
	return out
}

func (c *Config) list() []Item {
	var out []Item
	add := func(key, value, raw string, src Source, origin, applies string) {
		out = append(out, Item{Key: key, Value: value, Raw: raw, Source: src, Origin: origin, Applies: applies, Editable: key != "db_path"})
	}
	dur := func(key string, s *Setting[time.Duration], applies string) {
		add(key, Duration(s.Value), DurationRaw(s.Value), s.Source, s.Origin, applies)
	}
	days := func(key string, s *Setting[int], zero, applies string) {
		v := dayCount(s.Value)
		if s.Value == 0 {
			v = zero
		}
		add(key, v, strconv.Itoa(s.Value), s.Source, s.Origin, applies)
	}
	const agentNext = "for sesh's agent when it next starts, and in sesh ui from its next start"
	const kdfNext = "for encrypted exports now, and the vault at its next master password change"
	dur("clipboard_timeout", &c.ClipboardTimeout, "for other commands now, and in sesh ui from its next start")
	dur("agent.idle_timeout", &c.AgentIdleTimeout, agentNext)
	dur("agent.max_lifetime", &c.AgentMaxLifetime, agentNext)
	sw := func(key string, s *Setting[bool], applies string) {
		it := Item{Key: key, Value: "off", Raw: "false", Source: s.Source, Origin: s.Origin, Applies: applies, Editable: true, Switch: true}
		if s.Value {
			it.Value, it.Raw = "on", "true"
		}
		out = append(out, it)
	}
	sw("agent.lock_on_sleep", &c.AgentLockOnSleep, "for sesh's agent when it next starts")
	sw("agent.lock_on_screen_lock", &c.AgentLockOnScreenLock, "for sesh's agent when it next starts (macOS)")
	days("audit.retention_days", &c.AuditRetentionDays, "0 (keep all)", "the next time a command unlocks the vault")
	add("master_password.memory", Memory(c.KDFMemory.Value), Memory(c.KDFMemory.Value), c.KDFMemory.Source, c.KDFMemory.Origin, kdfNext)
	add("master_password.time", strconv.FormatUint(uint64(c.KDFTime.Value), 10), strconv.FormatUint(uint64(c.KDFTime.Value), 10), c.KDFTime.Source, c.KDFTime.Origin, kdfNext)
	add("master_password.threads", strconv.FormatUint(uint64(c.KDFThreads.Value), 10), strconv.FormatUint(uint64(c.KDFThreads.Value), 10), c.KDFThreads.Source, c.KDFThreads.Origin, kdfNext)
	days("backup.every_days", &c.BackupEveryDays, "off", "the next time a command unlocks the vault")
	add("backup.keep", strconv.Itoa(c.BackupKeep.Value), strconv.Itoa(c.BackupKeep.Value), c.BackupKeep.Source, c.BackupKeep.Origin, "at the next backup")
	days("trash.keep_days", &c.TrashKeepDays, "0 (no trash: deleting is for good)", "for other commands now, and in sesh ui from its next start")
	add("history.keep", strconv.Itoa(c.HistoryKeep.Value), strconv.Itoa(c.HistoryKeep.Value), c.HistoryKeep.Source, c.HistoryKeep.Origin, "for other commands now, and in sesh ui from its next start")
	days("health.old_after_days", &c.HealthOldAfterDays, "0 (not checked)", "at the next health check")
	sw("ui.lock_on_quit", &c.UILockOnQuit, "when sesh ui next quits")
	add("db_path", c.DBPath.Value, c.DBPath.Value, c.DBPath.Source, c.DBPath.Origin, "")
	dir := Item{Key: "backup.dir", Value: c.BackupFolder(), Raw: underHome(c.BackupDir.Value), Source: c.BackupDir.Source, Origin: c.BackupDir.Origin, Applies: "at the next backup", Editable: true}
	out = append(out, dir)
	syncDir := Item{Key: "sync.dir", Value: c.SyncDir.Value, Raw: underHome(c.SyncDir.Value), Source: c.SyncDir.Source, Origin: c.SyncDir.Origin, Applies: "at the next sync", Editable: true}
	if syncDir.Value == "" {
		syncDir.Value = "off"
	}
	out = append(out, syncDir, Item{Key: "sync.name", Value: c.SyncComputerName(), Raw: c.SyncName.Value, Source: c.SyncName.Source, Origin: c.SyncName.Origin, Applies: "at the next sync", Editable: true})
	sw("sync.auto", &c.SyncAuto, "from the next command")
	return out
}

// Said is where an item's value came from, in words: "default", "config
// file", "environment: SESH_X".
func (it *Item) Said() string {
	switch it.Source {
	case FromEnv, FromFlag:
		return it.Source.String() + ": " + it.Origin
	case FromDefault:
		switch it.Key {
		case "backup.dir":
			return "default: next to the vault"
		case "sync.name":
			return "default: this computer's name"
		}
	}
	return it.Source.String()
}

// dayCount is n days in words.
func dayCount(n int) string {
	if n == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", n)
}

// Memory is an amount of memory given in KiB in the largest unit that
// divides it: 256MiB, 1GiB, or 65000KiB.
func Memory(kib uint32) string {
	switch {
	case kib%(1024*1024) == 0:
		return fmt.Sprintf("%dGiB", kib/(1024*1024))
	case kib%1024 == 0:
		return fmt.Sprintf("%dMiB", kib/1024)
	}
	return fmt.Sprintf("%dKiB", kib)
}

// DurationRaw is d as the config file has it: 30s, 10m, 8h, 1h30m, 0.
func DurationRaw(d time.Duration) string {
	if d == 0 {
		return "0"
	}
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// Duration is d as said: as the file has it, and 0 as "0 (off)".
func Duration(d time.Duration) string {
	if d == 0 {
		return "0 (off)"
	}
	return DurationRaw(d)
}

// underHome is path with the home folder written ~, as a config file
// shared between computers has it.
func underHome(path string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" || path == "" {
		return path
	}
	if rest, ok := strings.CutPrefix(path, home+string(filepath.Separator)); ok {
		return "~/" + filepath.ToSlash(rest)
	}
	return path
}
