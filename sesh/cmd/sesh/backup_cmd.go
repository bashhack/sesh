package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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

const backupUsage = `Usage:
  sesh backup [--force] [file]                 Copy the vault now: into the backups folder (backup.dir),
                                               or to file (or into a folder); --force replaces a file there
  sesh backup list                             List the backups, newest first (as sesh restore does)
  sesh backup delete <backup>… [--force]       Delete backups for good, named as the list names them
  sesh backup delete --all [--force]           Delete all of this vault's backups, and make a fresh one

No password is needed: the secrets in a backup stay encrypted, as in the
vault. A backup still opens with the master password (and recovery key) it
was made under, so after changing one that may have leaked, delete the
old backups. Deleting asks first; --force deletes without asking. (To back
up to a file named list or delete, write ./list.)`

// runBackup is `sesh backup [file]`: a copy of the vault now, in the
// backups folder (pruned to backup.keep) or at file. It needs no password:
// the secrets in the copy are encrypted, as in the vault. sesh backup list
// and delete see to the backups made.
func runBackup(app *App, args []string) error {
	if len(args) > 0 {
		switch {
		case isHelp(args[0]):
			_, err := fmt.Fprintln(app.Stdout, backupUsage)
			return err
		case args[0] == "list":
			if len(args) > 1 {
				return fmt.Errorf("sesh backup list takes nothing more, not %q", strings.Join(args[1:], " "))
			}
			cfg, err := settings()
			if err != nil {
				return err
			}
			return listBackups(app, cfg)
		case args[0] == "delete":
			return deleteBackups(app, args[1:])
		}
	}
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	force := addBackupFlags(fs)
	fs.Usage = func() { fmt.Fprintln(app.Stderr, backupUsage) } //nolint:errcheck // usage text
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 1 {
		return fmt.Errorf("sesh backup takes at most one file, got %q", strings.Join(fs.Args(), " "))
	}
	if a := fs.Arg(0); a == "list" || a == "delete" {
		return fmt.Errorf("sesh backup %s takes no --force; to back up to a file named %s, write ./%s", a, a, a)
	}
	cfg, err := settings()
	if err != nil {
		return err
	}
	vaultPath := cfg.DBPath.Value
	if err := requireVault(vaultPath, "there's no vault yet: sesh add creates it with your first entry (sesh init first chooses where it lives)"); err != nil {
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

// addBackupDeleteFlags defines sesh backup delete's flags on fs.
func addBackupDeleteFlags(fs *flag.FlagSet) (all, force *bool) {
	return fs.Bool("all", false, "Delete all of this vault's backups, and make a fresh one"), fs.Bool("force", false, "Delete without asking")
}

// deleteBackups is sesh backup delete: backups the list names deleted for
// good, or all of the vault's, with a fresh one made, as sesh ui's backups
// panel does. Every backup named is found before any is deleted.
func deleteBackups(app *App, args []string) error {
	fs := flag.NewFlagSet("backup delete", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	all, force := addBackupDeleteFlags(fs)
	names, err := parseAnywhere(fs, args)
	if err != nil {
		return err
	}
	switch {
	case *all && len(names) > 0:
		return errors.New("--all deletes every backup of the vault; name backups, or give --all, not both")
	case !*all && len(names) == 0:
		return errors.New("name the backups to delete (sesh backup list shows them), or give --all")
	}
	terminal := app.StdinIsTerminal != nil && app.StdinIsTerminal()
	if !*force && !terminal {
		return errors.New("deleting backups asks first, and there's no terminal to ask at; add --force to delete without asking")
	}
	cfg, err := settings()
	if err != nil {
		return err
	}
	dir, vaultPath := cfg.BackupFolder(), cfg.DBPath.Value
	if *all {
		if err := requireVault(vaultPath, "there's no vault to back up afresh; delete the backups by name instead"); err != nil {
			return err
		}
		s, err := backup.SeriesOf(vaultPath, dir)
		if err != nil {
			return err
		}
		if !*force {
			yes, err := promptYesNo(app.Stdin, app.Stderr, "Delete this vault's backups in "+tildePath(dir)+" for good, and make a fresh one? [y/N]: ")
			if err != nil || !yes {
				return nothingDeleted(app, err)
			}
		}
		said, err := renewBackups(s, vaultPath)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(app.Stdout, "✅ "+said)
		return err
	}
	listed, _, err := backup.ListAny(dir, vaultPath)
	if err != nil {
		return err
	}
	var paths []string
	for _, name := range names {
		i := slices.IndexFunc(listed, func(b backup.Info) bool { return filepath.Base(b.Path) == name || b.Path == name })
		if i < 0 {
			return fmt.Errorf("no backup named %s in %s; sesh backup list shows them", name, tildePath(dir))
		}
		if !slices.Contains(paths, listed[i].Path) {
			paths = append(paths, listed[i].Path)
		}
	}
	if !*force {
		what := "the backup " + filepath.Base(paths[0])
		if len(paths) > 1 {
			what = countOf(int64(len(paths)), "backup")
		}
		yes, err := promptYesNo(app.Stdin, app.Stderr, "Delete "+what+" for good? [y/N]: ")
		if err != nil || !yes {
			return nothingDeleted(app, err)
		}
	}
	for i, path := range paths {
		if err := backup.Remove(dir, vaultPath, path); err != nil {
			return fmt.Errorf("%w (deleted %d of %d)", err, i, len(paths))
		}
	}
	said := "✅ Deleted the backup " + filepath.Base(paths[0])
	if len(paths) > 1 {
		said = "✅ Deleted " + countOf(int64(len(paths)), "backup")
	}
	_, err = fmt.Fprintln(app.Stdout, said)
	return err
}

// nothingDeleted is err, or, for a no, saying nothing was deleted.
func nothingDeleted(app *App, err error) error {
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(app.Stderr, "Nothing deleted.")
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
	them := "them"
	if len(all) == 1 {
		them = "it"
	}
	if _, err := fmt.Fprintf(app.Stderr, "\n%s\n", oldBackupsSaid(len(all), what, s.Dir)); err != nil {
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
	said, err := renewBackups(s, vaultPath)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(app.Stderr, said)
	return err
}

// oldBackupsSaid says that n backups, in dir, made before a change still
// open with the old what.
func oldBackupsSaid(n int, what, dir string) string {
	opens := "open"
	if n == 1 {
		opens = "opens"
	}
	return fmt.Sprintf("%s made before this change still %s with the old %s, in %s.", countOf(int64(n), "backup"), opens, what, tildePath(dir))
}

// renewBackups makes a fresh backup of the vault at vaultPath, then
// deletes the others in s, and says so: one that can't be made leaves
// them all.
func renewBackups(s backup.Series, vaultPath string) (string, error) {
	old, err := s.List()
	if err != nil {
		return "", err
	}
	b, err := s.Make(vaultPath, now())
	if err != nil {
		return "", fmt.Errorf("%w; the backups there are left as they were", err)
	}
	for i, o := range old {
		if o.Path == b.Path {
			continue
		}
		if err := os.Remove(o.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("made a fresh backup, %s, but deleted only %d of the %d before it: %w", tildePath(b.Path), i, len(old), err)
		}
	}
	return fmt.Sprintf("Deleted %s; made a fresh one: %s", countOf(int64(len(old)), "backup"), tildePath(b.Path)), nil
}
