package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/touchid"
)

// initChoices are what `sesh init` sets up.
type initChoices struct {
	// dbPath is the vault location; dbDefault reports whether it's the
	// built-in default, which the config file then leaves out.
	dbPath    string
	dbDefault bool
}

// addInitFlags registers the flags of sesh init and returns its --force.
func addInitFlags(fs *flag.FlagSet) *bool {
	return fs.Bool("force", false, "Replace an existing config file")
}

// runInit is `sesh init`: it sets up the vault where you choose. With
// --db-path it uses that (for scripts); otherwise it asks. It creates (or
// opens) the vault first, and only then writes ~/.config/sesh/config.toml, so a failure leaves no config pointing
// at a vault that doesn't work.
func runInit(app *App, args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	force := addInitFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("sesh init takes no arguments, got %q", strings.Join(fs.Args(), " "))
	}

	path, err := config.Path()
	if err != nil {
		return err
	}
	switch _, err := os.Stat(path); {
	case err == nil && !*force:
		return fmt.Errorf("config already exists at %s. Run sesh config to see it, or sesh init --force to replace it", tildePath(path))
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("check for an existing config file: %w", err)
	}

	choices, err := chooseInit(app)
	if err != nil {
		return err
	}
	cfg := choices.config()

	existed := false
	if _, err := os.Stat(choices.dbPath); err == nil {
		existed = true
		if _, werr := fmt.Fprintf(app.Stdout, "Using the existing vault at %s\n", tildePath(choices.dbPath)); werr != nil {
			return werr
		}
	}
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		return err
	}
	if err := store.Close(); err != nil {
		return fmt.Errorf("close vault: %w", err)
	}
	// A new vault was offered a recovery key and Touch ID as it was
	// created; an existing one gets pointers instead. (Deferred, so the
	// recovery tip, registered last, prints first.)
	if existed && touchIDAvailable() {
		if _, err := os.Stat(filepath.Join(filepath.Dir(choices.dbPath), touchid.FileName)); err != nil {
			defer func() {
				fmt.Fprintln(app.Stdout, "Tip: unlock with Touch ID instead of typing your password: sesh touchid enable") //nolint:errcheck // best-effort tip
			}()
		}
	}
	if existed {
		if _, err := database.ReadRecovery(choices.dbPath); err != nil {
			defer func() {
				fmt.Fprintln(app.Stdout, "Tip: make a recovery key, in case you forget your master password: sesh recovery new") //nolint:errcheck // best-effort tip
			}()
		}
	}

	if err := config.Write(path, choices.file()); err != nil {
		return err
	}
	for _, l := range []string{"Wrote " + tildePath(path), "Ready. Run `sesh config` to see your settings."} {
		if _, err := fmt.Fprintln(app.Stdout, l); err != nil {
			return err
		}
	}
	return nil
}

// chooseInit takes the vault location from --db-path when it was given,
// and otherwise asks.
func chooseInit(app *App) (initChoices, error) {
	dbDefault, err := database.DefaultDBLocation()
	if err != nil {
		return initChoices{}, fmt.Errorf("resolve default vault location: %w", err)
	}
	c := initChoices{dbPath: dbDefault, dbDefault: true}

	if o := cliOverrides; o.DBPath != "" {
		p, err := config.ResolvePath(o.DBPath)
		if err != nil {
			return c, fmt.Errorf("--db-path = %q: %w", o.DBPath, err)
		}
		c.dbPath, c.dbDefault = p, p == dbDefault
		return c, nil
	}

	answer, err := ask(app, bufio.NewReader(app.Stdin), "Vault location ["+tildePath(dbDefault)+"]: ")
	if err != nil {
		return c, err
	}
	if answer != "" {
		p, err := config.ResolvePath(answer)
		if err != nil {
			return c, fmt.Errorf("vault location %q: %w", answer, err)
		}
		c.dbPath, c.dbDefault = p, p == dbDefault
	}
	return c, nil
}

// ask writes prompt to stderr, where the password prompts go too, and
// reads one line. End of input is an empty answer, taking the default.
func ask(app *App, in *bufio.Reader, prompt string) (string, error) {
	if _, err := fmt.Fprint(app.Stderr, prompt); err != nil {
		return "", err
	}
	line, err := in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read answer: %w", err)
	}
	return strings.TrimSpace(line), nil
}

// config is the settings the vault is created or opened with: exactly the
// choices, whatever the environment or an old config file says.
func (c initChoices) config() *config.Config {
	from := func(v string) config.Setting[string] {
		return config.Setting[string]{Value: v, Source: config.FromFlag, Origin: "sesh init"}
	}
	return &config.Config{DBPath: from(c.dbPath)}
}

// file is the config file sesh init writes.
func (c initChoices) file() string {
	var b strings.Builder
	b.WriteString("# sesh settings, written by `sesh init`. Run `sesh config` to see every\n")
	b.WriteString("# setting and where it comes from.\n")
	if !c.dbDefault {
		// ~/ form when it's under home: readable, and it survives a
		// changed home directory.
		fmt.Fprintf(&b, "db_path = %q\n", tildePath(c.dbPath))
	}
	return b.String()
}
