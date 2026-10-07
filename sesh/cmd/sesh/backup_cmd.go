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
)

// now is the time backups are named for; tests replace it.
var now = time.Now

// autoBackup backs up the vault store opened when the newest backup is
// backup.every_days old or more, then removes all but the newest
// backup.keep. A vault with no entries isn't backed up. A failure is a
// warning; it never stops the command.
func autoBackup(store *database.Store, cfg *config.Config) {
	if err := autoBackupOnce(store, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "warning: automatic backup: %v\n", err) //nolint:errcheck // best-effort warning
	}
}

func autoBackupOnce(store *database.Store, cfg *config.Config) error {
	if cfg.BackupEveryDays.Value == 0 {
		return nil
	}
	s, err := backup.SeriesOf(cfg.DBPath.Value, cfg.BackupFolder())
	if err != nil {
		return err
	}
	if due, err := s.Due(cfg.BackupEveryDays.Value, now()); err != nil || !due {
		return err
	}
	if has, err := store.HasEntries(); err != nil || !has {
		return err
	}
	if _, err := s.Make(cfg.DBPath.Value, now()); err != nil {
		return err
	}
	_, err = s.Prune(cfg.BackupKeep.Value)
	return err
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
		fmt.Fprintln(app.Stderr, "Usage: sesh backup [--force] [file]\n  Copy the vault now: into the backups folder (backup.dir), or to file (or into a folder).\n  No password is needed; the secrets in the copy stay encrypted.") //nolint:errcheck // usage text
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
		s, err := backup.SeriesOf(vaultPath, cfg.BackupFolder())
		if err != nil {
			return err
		}
		if b, err = s.Make(vaultPath, now()); err != nil {
			return err
		}
		if _, err := s.Prune(cfg.BackupKeep.Value); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(app.Stdout, "✅ Backed up the vault to %s (%s)\n", tildePath(b.Path), vaultSize(b.Size))
	return err
}

// offerToRemoveOldBackups follows a change that leaves the old master
// password or recovery key (what) unable to open the vault: the backups
// made before it still open with the old one, which matters when it may
// have leaked. At a terminal it asks whether to delete them and make a
// fresh backup; otherwise it says where they are. The change has already
// succeeded, so a failure here is a warning.
func offerToRemoveOldBackups(app *App, cfg *config.Config, what string) {
	if err := offerToRemoveOldBackupsOnce(app, cfg, what); err != nil {
		fmt.Fprintf(app.Stderr, "warning: old backups: %v\n", err) //nolint:errcheck // best-effort warning
	}
}

func offerToRemoveOldBackupsOnce(app *App, cfg *config.Config, what string) error {
	vaultPath := cfg.DBPath.Value
	s, err := backup.SeriesOf(vaultPath, cfg.BackupFolder())
	if err != nil {
		return err
	}
	all, err := s.List()
	if err != nil || len(all) == 0 {
		return err
	}
	old, opens, them := countOf(int64(len(all)), "backup"), "open", "them"
	if len(all) == 1 {
		opens, them = "opens", "it"
	}
	if _, err := fmt.Fprintf(app.Stderr, "\n%s made before this change still %s with the old %s, in %s.\n", old, opens, what, tildePath(s.Dir)); err != nil {
		return err
	}
	if app.StdinIsTerminal == nil || !app.StdinIsTerminal() {
		_, err := fmt.Fprintf(app.Stderr, "If the old %s may have leaked, delete %s.\n", what, them)
		return err
	}
	yes, err := promptYesNo(app.Stdin, app.Stderr, fmt.Sprintf("If the old %s may have leaked, delete %s. Delete %s and make a fresh backup? [y/N]: ", what, them, them))
	if err != nil || !yes {
		return err
	}
	removed, err := s.RemoveAll()
	if err != nil {
		return err
	}
	b, err := s.Make(vaultPath, now())
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(app.Stderr, "Deleted %s; made a fresh one: %s\n", countOf(int64(len(removed)), "backup"), tildePath(b.Path))
	return err
}
