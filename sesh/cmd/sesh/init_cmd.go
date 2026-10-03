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
	backend   string
	keySource string
	// dbPath is the vault location; dbDefault reports whether it's the
	// built-in default, which the config file then leaves out.
	dbPath    string
	dbDefault bool
}

// runInit is `sesh init`: it sets up where sesh keeps secrets. With
// --backend, --key-source, or --db-path it uses those (for scripts);
// otherwise it asks. For a vault it creates (or opens) the vault first, and
// only then writes ~/.config/sesh/config.toml, so a failure leaves no
// config pointing at a vault that doesn't work.
func runInit(app *App, args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	force := fs.Bool("force", false, "Replace an existing config file")
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

	if choices.backend == config.BackendKeychain {
		if err := requireMacOSKeychain(cfg.Backend, "backend"); err != nil {
			return err
		}
	} else {
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
		// A new vault was offered Touch ID as it was created; an existing one
		// gets a pointer instead.
		if existed && choices.keySource == config.KeySourcePassword && touchIDAvailable() {
			if _, err := os.Stat(filepath.Join(filepath.Dir(choices.dbPath), touchid.FileName)); err != nil {
				defer func() {
					fmt.Fprintln(app.Stdout, "Tip: unlock with Touch ID instead of typing your password: sesh touchid enable") //nolint:errcheck // best-effort tip
				}()
			}
		}
	}

	if err := config.Write(path, choices.file()); err != nil {
		return err
	}
	lines := []string{"Wrote " + tildePath(path)}
	if choices.backend == config.BackendKeychain {
		lines = append(lines, "sesh will store secrets in your macOS login Keychain.")
	}
	lines = append(lines, "Ready. Run `sesh config` to see your settings.")
	for _, l := range lines {
		if _, err := fmt.Fprintln(app.Stdout, l); err != nil {
			return err
		}
	}
	return nil
}

// chooseInit takes the choices from the setting flags when any were given,
// and otherwise asks.
func chooseInit(app *App) (initChoices, error) {
	dbDefault, err := database.DefaultDBLocation()
	if err != nil {
		return initChoices{}, fmt.Errorf("resolve default vault location: %w", err)
	}
	c := initChoices{backend: config.BackendSQLite, keySource: config.KeySourcePassword, dbPath: dbDefault, dbDefault: true}

	o := cliOverrides
	if o != (config.Overrides{}) {
		if o.Backend != "" {
			if o.Backend != config.BackendSQLite && o.Backend != config.BackendKeychain {
				return c, fmt.Errorf("--backend = %q: want \"sqlite\" or \"keychain\"", o.Backend)
			}
			c.backend = o.Backend
		}
		if o.KeySource != "" {
			if o.KeySource != config.KeySourcePassword && o.KeySource != config.KeySourceKeychain {
				return c, fmt.Errorf("--key-source = %q: want \"password\" or \"keychain\"", o.KeySource)
			}
			c.keySource = o.KeySource
		}
		if o.DBPath != "" {
			p, err := config.ResolvePath(o.DBPath)
			if err != nil {
				return c, fmt.Errorf("--db-path = %q: %w", o.DBPath, err)
			}
			c.dbPath, c.dbDefault = p, p == dbDefault
		}
		return c, nil
	}

	in := bufio.NewReader(app.Stdin)
	if goos == "darwin" {
		answer, err := ask(app, in, "Where should sesh keep your secrets?\n"+
			"  1) Encrypted vault, unlocked with a master password  (default)\n"+
			"  2) macOS Keychain\n"+
			"Choice [1]: ")
		if err != nil {
			return c, err
		}
		switch answer {
		case "", "1":
		case "2":
			c.backend = config.BackendKeychain
			return c, nil
		default:
			return c, fmt.Errorf("choose 1 or 2, got %q", answer)
		}
	}
	answer, err := ask(app, in, "Vault location ["+tildePath(dbDefault)+"]: ")
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
	return &config.Config{Backend: from(c.backend), KeySource: from(c.keySource), DBPath: from(c.dbPath)}
}

// file is the config file sesh init writes.
func (c initChoices) file() string {
	var b strings.Builder
	b.WriteString("# sesh settings, written by `sesh init`. Run `sesh config` to see every\n")
	b.WriteString("# setting and where it comes from.\n")
	fmt.Fprintf(&b, "backend = %q\n", c.backend)
	if c.backend == config.BackendSQLite {
		fmt.Fprintf(&b, "key_source = %q\n", c.keySource)
		if !c.dbDefault {
			// ~/ form when it's under home: readable, and it survives a
			// changed home directory.
			fmt.Fprintf(&b, "db_path = %q\n", tildePath(c.dbPath))
		}
	}
	return b.String()
}
