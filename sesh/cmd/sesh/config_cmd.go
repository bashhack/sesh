package main

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/config"
)

// runConfig is `sesh config`: it prints each effective setting and where
// it came from, so a user can see why sesh behaves as it does.
func runConfig(app *App, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("sesh config takes no arguments, got %q", strings.Join(args, " "))
	}
	cfg, err := settings()
	if err != nil {
		if path, perr := config.Path(); perr == nil {
			if _, werr := fmt.Fprintf(app.Stdout, "config file: %s\n", path); werr != nil {
				return werr
			}
		}
		return err
	}
	return writeConfig(app.Stdout, cfg)
}

// writeConfig renders cfg for people: the file it read, then one line per
// setting with its value and source.
func writeConfig(w io.Writer, cfg *config.Config) error {
	var b strings.Builder
	file := cfg.Path
	if !cfg.FileFound {
		file += " (not found; using defaults)"
	}
	fmt.Fprintf(&b, "config file: %s\n\n", file)

	line := func(key, value, source string) {
		fmt.Fprintf(&b, "%-22s%-14s(%s)\n", key, value, source)
	}
	line("backend", cfg.Backend.Value, sourceOf(cfg.Backend.Source, cfg.Backend.Origin))
	line("key_source", cfg.KeySource.Value, sourceOf(cfg.KeySource.Source, cfg.KeySource.Origin))
	line("clipboard_timeout", duration(cfg.ClipboardTimeout.Value), sourceOf(cfg.ClipboardTimeout.Source, cfg.ClipboardTimeout.Origin))
	line("agent.idle_timeout", duration(cfg.AgentIdleTimeout.Value), sourceOf(cfg.AgentIdleTimeout.Source, cfg.AgentIdleTimeout.Origin))
	line("agent.max_lifetime", duration(cfg.AgentMaxLifetime.Value), sourceOf(cfg.AgentMaxLifetime.Source, cfg.AgentMaxLifetime.Origin))
	line("audit.retention_days", retention(cfg.AuditRetentionDays.Value), sourceOf(cfg.AuditRetentionDays.Source, cfg.AuditRetentionDays.Origin))
	// The vault path is usually longer than the value column.
	fmt.Fprintf(&b, "%-22s%s\n%-22s(%s)\n", "db_path", cfg.DBPath.Value, "", sourceOf(cfg.DBPath.Source, cfg.DBPath.Origin))

	_, err := io.WriteString(w, b.String())
	return err
}

// sourceOf names a setting's source, with the env var or flag when there
// is one. A file setting's origin also names the file, which the header
// already shows.
func sourceOf(s config.Source, origin string) string {
	switch s {
	case config.FromEnv, config.FromFlag:
		return s.String() + ": " + origin
	default:
		return s.String()
	}
}

// retention prints the audit retention: "90 days", or "0 (keep all)".
func retention(days int) string {
	if days == 0 {
		return "0 (keep all)"
	}
	return plural(int64(days), "day")
}

// duration prints d as the user would write it: 30s, 10m, 8h, 1h30m.
func duration(d time.Duration) string {
	if d == 0 {
		return "0 (off)"
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
