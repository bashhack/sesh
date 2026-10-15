package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/bashhack/sesh/internal/config"
)

const configUsage = `Usage: sesh config
  Show each setting, its value, and where it comes from: the config file,
  an environment variable, a flag, or the default. sesh ui's settings panel
  changes them; so does editing the file it names.`

// runConfig is `sesh config`: it prints each effective setting and where
// it came from, so a user can see why sesh behaves as it does.
func runConfig(app *App, args []string) error {
	if len(args) > 0 && isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, configUsage)
		return err
	}
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

	for _, it := range cfg.List() {
		if it.Key == "db_path" || it.Key == "backup.dir" {
			// Paths are usually longer than the value column.
			fmt.Fprintf(&b, "%-25s%s\n%-25s(%s)\n", it.Key, it.Value, "", it.Said())
			continue
		}
		fmt.Fprintf(&b, "%-25s%-14s(%s)\n", it.Key, it.Value, it.Said())
	}

	_, err := io.WriteString(w, b.String())
	return err
}
