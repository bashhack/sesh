package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/backup"
	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/vault"
)

// now is the time backups are named for; tests replace it.
var now = time.Now

// autoBackup backs up the vault store opened when the newest backup is
// backup.every_days old or more, then removes all but the newest
// backup.keep. A vault with no entries isn't backed up. A failure is a
// warning; it never stops the command.
func autoBackup(store *database.Store, cfg *config.Config) {
	dir, vaultPath := cfg.BackupFolder(), cfg.DBPath.Value
	due, err := backup.Due(dir, vaultPath, cfg.BackupEveryDays.Value, now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: automatic backup: %v\n", err) //nolint:errcheck // best-effort warning
		return
	}
	if !due {
		return
	}
	if entries, err := store.List(&vault.Filter{}); err != nil || len(entries) == 0 {
		return
	}
	if _, err := backup.Make(vaultPath, dir, now()); err != nil {
		fmt.Fprintf(os.Stderr, "warning: automatic backup: %v\n", err) //nolint:errcheck // best-effort warning
		return
	}
	if _, err := backup.Prune(dir, vaultPath, cfg.BackupKeep.Value); err != nil {
		fmt.Fprintf(os.Stderr, "warning: automatic backup: %v\n", err) //nolint:errcheck // best-effort warning
	}
}

// addBackupFlags defines sesh backup's flags on fs.
func addBackupFlags(fs *flag.FlagSet) *bool {
	return fs.Bool("force", false, "Replace the file if it exists")
}

// runBackup is `sesh backup [file]`: a copy of the vault now, in the
// backups folder (pruned to backup.keep) or at file. It needs no password:
// the secrets in the copy are encrypted, as in the vault.
func runBackup(app *App, args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	force := addBackupFlags(fs)
	fs.Usage = func() {
		fmt.Fprintln(app.Stderr, "Usage: sesh backup [--force] [file]\n  Copy the vault now: into the backups folder (backup.dir), or to file.\n  No password is needed; the secrets in the copy stay encrypted.") //nolint:errcheck // usage text
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 1 {
		return fmt.Errorf("sesh backup takes at most one file, got %q", strings.Join(fs.Args(), " "))
	}
	cfg, err := settings()
	if err != nil {
		return err
	}
	vaultPath := cfg.DBPath.Value
	if err := requireVault(vaultPath, "there's no vault yet: create it first, by running any sesh command or sesh init"); err != nil {
		return err
	}
	var b backup.Info
	if fs.NArg() == 1 {
		// ~/ is expanded; a relative path is from the working directory.
		dest, err := config.ResolvePath(fs.Arg(0))
		if err != nil {
			if dest, err = filepath.Abs(fs.Arg(0)); err != nil {
				return fmt.Errorf("find %s: %w", fs.Arg(0), err)
			}
		}
		if b, err = backup.MakeTo(vaultPath, dest, *force, now()); err != nil {
			return err
		}
	} else {
		if *force {
			return errors.New("--force replaces a file you name: sesh backup --force <file>")
		}
		dir := cfg.BackupFolder()
		if b, err = backup.Make(vaultPath, dir, now()); err != nil {
			return err
		}
		if _, err := backup.Prune(dir, vaultPath, cfg.BackupKeep.Value); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(app.Stdout, "✅ Backed up the vault to %s (%s)\n", tildePath(b.Path), vaultSize(b.Size))
	return err
}
