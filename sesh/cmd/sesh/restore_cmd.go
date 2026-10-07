package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/bashhack/sesh/internal/backup"
	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/touchid"
)

// addRestoreFlags defines sesh restore's flags on fs.
func addRestoreFlags(fs *flag.FlagSet) *bool {
	return fs.Bool("force", false, "Restore without asking")
}

// runRestore is `sesh restore [file]`: with no file, the backups, newest
// first; with one, the vault replaced by it, after checking it, saying
// what will happen, saving the vault as it is, and asking.
func runRestore(app *App, args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	force := addRestoreFlags(fs)
	fs.Usage = func() {
		fmt.Fprintln(app.Stderr, "Usage: sesh restore [--force] [backup]\n  With no backup, list the backups. With one (a file, or a name from the list), replace the vault with it.") //nolint:errcheck // usage text
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 1 {
		return fmt.Errorf("sesh restore takes one backup, got %q", strings.Join(fs.Args(), " "))
	}
	cfg, err := settings()
	if err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return listBackups(app, cfg)
	}
	if !*force && (app.StdinIsTerminal == nil || !app.StdinIsTerminal()) {
		return errors.New("restoring asks first, and there's no terminal to ask at; add --force to restore without asking")
	}
	path, err := findBackup(cfg, fs.Arg(0))
	if err != nil {
		return err
	}
	return restore(app, cfg, path, *force)
}

// listBackups prints the vault's backups, newest first, and any of another
// vault with the same file name in the folder.
func listBackups(app *App, cfg *config.Config) error {
	dir, vaultPath := cfg.BackupFolder(), cfg.DBPath.Value
	all, ids, err := backup.ListAny(dir, vaultPath)
	if err != nil {
		return err
	}
	if len(all) == 0 {
		_, err := fmt.Fprintf(app.Stdout, "No backups in %s yet. Make one with: sesh backup\n", tildePath(dir))
		return err
	}
	mine, _ := database.VaultID(vaultPath) //nolint:errcheck // "" when the vault can't be read; then none is marked
	var b strings.Builder
	fmt.Fprintf(&b, "Backups in %s, newest first:\n", tildePath(dir))
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	other := false
	for i, info := range all {
		note := ""
		if mine != "" && !strings.HasPrefix(mine, ids[i]) {
			note, other = "  (another vault)", true
		}
		if _, err := fmt.Fprintf(tw, "  %s\t%s\t%s%s\n", info.Made.Local().Format("2006-01-02 15:04"), vaultSize(info.Size), filepath.Base(info.Path), note); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if other {
		b.WriteString("Another vault's backups open with that vault's master password.\n")
	}
	b.WriteString("Restore one with: sesh restore <name>\n")
	_, err = fmt.Fprint(app.Stdout, b.String())
	return err
}

// findBackup is the file arg names: a path, or a name in the backups
// folder.
func findBackup(cfg *config.Config, arg string) (string, error) {
	path, err := config.ResolvePath(arg)
	if err != nil {
		if path, err = filepath.Abs(arg); err != nil {
			return "", err
		}
	}
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	if !strings.ContainsRune(arg, os.PathSeparator) {
		inFolder := filepath.Join(cfg.BackupFolder(), arg)
		if _, err := os.Stat(inFolder); err == nil {
			return inFolder, nil
		}
	}
	return "", fmt.Errorf("no backup at %s; see the backups with: sesh restore", arg)
}

// restore replaces the vault with the backup at path.
func restore(app *App, cfg *config.Config, path string, force bool) error {
	vaultPath := cfg.DBPath.Value
	b, err := database.InspectBackup(path)
	if err != nil {
		return err
	}
	made := "an unknown time"
	if info, err := os.Stat(path); err == nil {
		made = info.ModTime().Local().Format("2006-01-02 15:04")
	}
	if all, _, err := backup.ListAny(filepath.Dir(path), vaultPath); err == nil {
		for _, info := range all {
			if info.Path == path {
				made = info.Made.Local().Format("2006-01-02 15:04")
			}
		}
	}

	var plan strings.Builder
	fmt.Fprintf(&plan, "Restore the vault from %s, made %s (%s)?\n", filepath.Base(path), made, entryCount(b.Entries))
	fmt.Fprintf(&plan, "  It opens with the master password, and recovery key, the vault had then.\n")
	current, nowErr := database.VaultSummary(vaultPath)
	switch {
	case nowErr == nil:
		if current.VaultID != b.VaultID {
			fmt.Fprintf(&plan, "  It's a backup of another vault (this one's id is %s, the backup's %s).\n", short(current.VaultID), short(b.VaultID))
		}
		fmt.Fprintf(&plan, "  The vault now (%s) is backed up first.\n", entryCount(current.Entries))
	case errors.Is(nowErr, database.ErrNoVault):
		fmt.Fprintf(&plan, "  There's no vault at %s now; the backup becomes it.\n", tildePath(vaultPath))
	default:
		fmt.Fprintf(&plan, "  The vault now can't be read (%v), so it isn't backed up first: it's replaced whole. Make sure no other sesh command is running.\n", nowErr)
	}
	if _, err := fmt.Fprint(app.Stderr, plan.String()); err != nil {
		return err
	}
	if !force {
		yes, err := promptYesNo(app.Stdin, app.Stderr, "Restore? [y/N]: ")
		if err != nil {
			return err
		}
		if !yes {
			_, err := fmt.Fprintln(app.Stderr, "Restore cancelled; nothing changed.")
			return err
		}
	}
	var saved string
	if nowErr == nil {
		s, err := backup.SeriesOf(vaultPath, cfg.BackupFolder())
		if err != nil {
			return err
		}
		info, err := s.Make(vaultPath, now())
		if err != nil {
			return fmt.Errorf("back up the vault before restoring (nothing changed): %w", err)
		}
		saved = info.Path
	}
	if _, err := database.RestoreFrom(vaultPath, path); err != nil {
		return err
	}

	var out strings.Builder
	fmt.Fprintf(&out, "✅ Restored the vault from %s (%s). It opens with the master password it had on %s.\n", filepath.Base(path), entryCount(b.Entries), made)
	if saved != "" {
		fmt.Fprintf(&out, "The vault as it was is in %s; restore it the same way to undo this.\n", tildePath(saved))
	}
	if note := lockAgentHoldingOldKey(); note != "" {
		out.WriteString(note + "\n")
	}
	if f, err := touchid.ReadFile(filepath.Dir(vaultPath)); err == nil {
		if mat, err := database.ReadUnlockMaterial(vaultPath); err == nil && f.UnlockID != database.UnlockID(mat.Verify) {
			out.WriteString("Touch ID unlock was set up for the vault before; turn it on again with: sesh touchid enable\n")
		}
	}
	_, err = fmt.Fprint(app.Stdout, out.String())
	return err
}

// short is a vault id as backup names show it.
func short(id string) string { return id[:min(8, len(id))] }
