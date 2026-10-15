package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/bashhack/sesh/internal/config"
)

const configUsage = `Usage:
  sesh config                            Show each setting, its value, and where it comes from:
                                         the config file, an environment variable, a flag, or the default
  sesh config set <key> <value> [--force]  Change a setting in the config file ("" puts its default back)

A setting an environment variable or a flag gives wins over the file, so
it's changed there instead; db_path, where the vault is, is changed with
sesh init. Lowering a setting that keeps things (history.keep,
trash.keep_days, audit.retention_days, backup.keep) deletes what's beyond
it, so it's asked about first; --force changes it without asking.

  sesh config set clipboard_timeout 15s
  sesh config set history.keep ""`

// runConfig is sesh config: each setting, where it came from, and what
// changes one.
func runConfig(app *App, args []string) error {
	if len(args) > 0 && isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, configUsage)
		return err
	}
	if len(args) > 0 && args[0] == "set" {
		return setConfig(app, args[1:])
	}
	if len(args) > 0 {
		return fmt.Errorf("sesh config takes set, or nothing, not %q", strings.Join(args, " "))
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

// addConfigSetFlags defines sesh config set's flag on fs.
func addConfigSetFlags(fs *flag.FlagSet) *bool {
	return fs.Bool("force", false, "Lower a keep setting without asking")
}

// setConfig is sesh config set: one setting changed in the config file,
// as sesh ui's settings panel changes it.
func setConfig(app *App, args []string) error {
	fs := flag.NewFlagSet("config set", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	force := addConfigSetFlags(fs)
	words, err := parseAnywhere(fs, args)
	if err != nil {
		return err
	}
	if len(words) != 2 {
		return errors.New(`name the setting and its value: sesh config set <key> <value> ("" puts its default back)`)
	}
	key, value := words[0], strings.TrimSpace(words[1])
	cfg, err := settings()
	if err != nil {
		return err
	}
	items := cfg.List()
	i := slices.IndexFunc(items, func(it config.Item) bool { return it.Key == key })
	if i < 0 {
		return fmt.Errorf("%s isn't a setting; sesh config lists them", key)
	}
	it := items[i]
	switch {
	case !it.Editable:
		return fmt.Errorf("%s is where the vault is: sesh init moves it", key)
	case it.Source == config.FromEnv || it.Source == config.FromFlag:
		return fmt.Errorf("%s is set by %s, which wins over the config file: change it there", key, it.Origin)
	case value == it.Raw:
		_, err := fmt.Fprintf(app.Stdout, "%s is %s already; nothing changed\n", key, it.Value)
		return err
	}
	to := value
	if to == "" {
		to = it.Default
	}
	if loss := config.Loss(key, it.Raw, to); loss != "" && !*force {
		if app.StdinIsTerminal == nil || !app.StdinIsTerminal() {
			return fmt.Errorf("%s That's asked about first, and there's no terminal to ask at; add --force to change it anyway", loss)
		}
		yes, err := promptYesNo(app.Stdin, app.Stderr, loss+" Change it? [y/N]: ")
		if err != nil {
			return err
		}
		if !yes {
			_, err := fmt.Fprintln(app.Stderr, "Nothing changed.")
			return err
		}
	}
	if err := config.Set(cfg.Path, key, value); err != nil {
		return err
	}
	said := fmt.Sprintf("✅ Set %s to %s in %s; it takes effect %s", key, value, tildePath(cfg.Path), it.Applies)
	if value == "" {
		said = fmt.Sprintf("✅ Took %s out of %s: its default, %s, takes effect %s", key, tildePath(cfg.Path), it.Default, it.Applies)
	}
	_, err = fmt.Fprintln(app.Stdout, said)
	return err
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
