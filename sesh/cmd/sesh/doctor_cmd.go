package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bashhack/sesh/internal/agent"
	"github.com/bashhack/sesh/internal/backup"
	"github.com/bashhack/sesh/internal/clipboard"
	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/kdf"
	"github.com/bashhack/sesh/internal/recovery"
	"github.com/bashhack/sesh/internal/shell"
	"github.com/bashhack/sesh/internal/touchid"
	"github.com/bashhack/sesh/internal/tui"
	"github.com/bashhack/sesh/internal/vault"
)

// structureLinesShown is how many of SQLite's findings doctor prints.
const structureLinesShown = 10

// runDoctor is `sesh doctor`: it checks sesh's setup, then the vault. The
// setup part needs no password: the config loads, the vault exists and
// only its owner can read it, the agent, and the vault's key settings
// against the configured ones. It's printed before the vault part, which
// unlocks the vault and checks that it can all be read: SQLite checks the
// file; every entry's secret is decrypted and its settings and times read;
// the recovery key's record must be shaped to open the vault, Touch ID
// unlock must be this vault's, and AWS entries need the AWS CLI. The vault
// part is skipped when nothing can unlock it without asking and there's
// no terminal to ask at.
//
// Nothing is written while it checks; one audit event records the result,
// if the file is sound. A FAIL row exits 1; warnings don't. The report
// ends with what to do about each.
func runDoctor(app *App, args []string) error {
	if len(args) == 1 && isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, "Usage: sesh doctor\n  Check sesh's setup (config, vault location, agent, key settings), then unlock the vault and check every entry can be read, and that its recovery key and Touch ID unlock still work.")
		return err
	}
	if len(args) > 0 {
		return fmt.Errorf("sesh doctor takes no arguments, got %q", strings.Join(args, " "))
	}
	var c doctorChecks
	c.section("sesh doctor\n\nSetup")
	vaultPart := checkSetup(&c, app)
	// The setup part shows before any password prompt.
	if err := c.flush(app.Stdout); err != nil {
		return err
	}
	if err := vaultPart(app.Stdout); err != nil {
		// The vault part couldn't finish: say so as its row, so the
		// setup's steps and the tally still show.
		if !canAsk(app) {
			c.row(markNone, "Vault", "not checked", err.Error())
			c.unchecked = true
		} else {
			c.row(markFail, "Vault", "not checked", err.Error())
			if errors.Is(err, database.ErrVaultKeyChanged) || strings.Contains(err.Error(), "run sesh doctor again") {
				c.todo("Run it again:", "sesh doctor")
			}
		}
	}
	return c.finish(app.Stdout)
}

// canAsk reports whether unlocking can get the master password without an
// agent: from SESH_MASTER_PASSWORD, or by asking at the terminal.
func canAsk(app *App) bool {
	return resolvePasswordPrompt().fromEnv || (app.StdinIsTerminal != nil && app.StdinIsTerminal())
}

// checkSetup adds the setup rows to c, and returns what checks the vault:
// its rows, or why it isn't checked.
func checkSetup(c *doctorChecks, app *App) func(io.Writer) error {
	return checkSetupOf(c, app, "")
}

// checkSetupOf is checkSetup for the vault at dbPath; "" is the one the
// config names.
func checkSetupOf(c *doctorChecks, app *App, dbPath string) func(io.Writer) error {
	cfg, err := settingsOf(dbPath)
	if err != nil {
		c.row(markFail, "Config", "doesn't load", err.Error())
		c.todo("Fix the config file, or the setting the error names:", "sesh config")
		return skipVault(c, "", "the config doesn't load")
	}
	if cfg.FileFound {
		c.row(markOK, "Config", tildePath(cfg.Path))
	} else {
		c.row(markNone, "Config", "no file yet, so the defaults", "changing a setting makes "+tildePath(cfg.Path))
	}

	dbPath = cfg.DBPath.Value
	mat, matErr := database.ReadUnlockMaterial(dbPath)
	switch {
	case errors.Is(matErr, database.ErrNoVault):
		c.row(markFail, "Vault file", "no vault at "+tildePath(dbPath))
		c.todo("Create the vault, choosing where it lives:", "sesh init")
		return skipVault(c, dbPath, "there's no vault")
	case matErr != nil && !database.IsDamaged(matErr):
		c.row(markFail, "Vault file", "can't be read", matErr.Error())
		c.todo("Check that the vault file and its folder are yours and readable: " + tildePath(dbPath))
		return skipVault(c, dbPath, "it can't be read")
	}
	checkPermissions(c, cfg)
	checkCloudFolder(c, cfg)

	agentUnlocked := checkAgent(c, mat, matErr)
	if matErr == nil {
		checkKeySettings(c, mat.Params, cfg.KDF())
	} else {
		c.row(markNone, "Key settings", "unknown: the key record is damaged")
	}
	checkBackups(c, cfg)
	checkSync(c, cfg, matErr)
	checkClipboard(c)
	return func(w io.Writer) error {
		c.section("\nVault: " + tildePath(dbPath))
		if matErr != nil {
			// Damaged where the key record is: nothing more can be read.
			c.row(markFail, "File", "damaged", matErr.Error())
			c.todo("Restore the vault from a backup, such as an encrypted export.")
			return nil
		}
		if !agentUnlocked && !canAsk(app) {
			c.row(markNone, "Vault", "not checked: unlocking it needs a terminal to ask at, SESH_MASTER_PASSWORD, or an agent unlocked for it and running this sesh build")
			c.unchecked = true
			return nil
		}
		// The header shows before a password prompt.
		if err := c.flush(w); err != nil {
			return err
		}
		return checkVault(c, cfg, dbPath, &mat)
	}
}

// skipVault is the vault part when there's nothing to check: a row saying
// why, under the vault's path when it's known.
func skipVault(c *doctorChecks, dbPath, why string) func(io.Writer) error {
	return func(io.Writer) error {
		title := "\nVault"
		if dbPath != "" {
			title += ": " + tildePath(dbPath)
		}
		c.section(title)
		c.row(markNone, "Vault", "not checked: "+why)
		c.unchecked = true
		return nil
	}
}

// checkPermissions warns when others can read the vault, or replace or
// delete it through its folder. It looks at the file a symlink names.
func checkPermissions(c *doctorChecks, cfg *config.Config) {
	dbPath := cfg.DBPath.Value
	target, err := filepath.EvalSymlinks(dbPath)
	if err != nil {
		c.row(markWarn, "Vault file", "its permissions can't be read", err.Error())
		c.todo("Check the vault file at " + tildePath(dbPath) + "; the row says why its permissions can't be read.")
		return
	}
	file, err := os.Stat(target)
	if err != nil {
		c.row(markWarn, "Vault file", "its permissions can't be read", err.Error())
		c.todo("Check the vault file at " + tildePath(dbPath) + "; the row says why its permissions can't be read.")
		return
	}
	dir := filepath.Dir(target)
	folder, err := os.Stat(dir)
	if err != nil {
		c.row(markWarn, "Vault file", "its folder's permissions can't be read", err.Error())
		c.todo("Check the vault's folder, " + tildePath(dir) + "; the row says why its permissions can't be read.")
		return
	}
	var problems []string
	if file.Mode().Perm()&0o077 != 0 {
		problems = append(problems, "others can read it")
		c.todo("Make the vault file yours alone:", "chmod 600 "+shell.Quote(target))
	}
	if folder.Mode().Perm()&0o022 != 0 {
		problems = append(problems, "others can replace or delete it, through its folder")
		if ownedByMe(folder) && folder.Mode()&os.ModeSticky == 0 {
			c.todo("Stop others writing to the vault's folder:", "chmod go-w "+shell.Quote(dir))
		} else {
			// A shared folder, such as /tmp, isn't yours to change.
			c.todo(moveVaultSteps(cfg, "to a folder only you can write to"))
		}
	}
	if len(problems) == 0 {
		c.row(markOK, "Vault file", "only you can read or change it")
		return
	}
	c.row(markWarn, "Vault file", strings.Join(problems, "; "))
}

// ownedByMe reports whether info is owned by this process's user.
func ownedByMe(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}

// checkAgent reports on the agent, without starting one. It returns
// whether the agent is unlocked for this vault, so the vault part can
// unlock without asking.
func checkAgent(c *doctorChecks, mat database.UnlockMaterial, matErr error) bool {
	conn, err := agent.DialExisting()
	if err != nil {
		if agent.IsNotRunning(err) {
			c.row(markNone, "Agent", "not running; it starts when a command needs it")
			return false
		}
		c.row(markWarn, "Agent", "can't be reached", err.Error())
		if strings.Contains(err.Error(), "SESH_AUTH_SOCK") {
			c.todo("Set SESH_AUTH_SOCK to a shorter path, or unset it to use the default.")
		} else {
			c.todo("Stop the agent; the next command starts a new one:", "sesh agent stop")
		}
		return false
	}
	defer closeAgentConn(conn)
	st, err := agent.Status(conn)
	if err != nil {
		c.row(markWarn, "Agent", "doesn't answer", err.Error())
		c.todo("Stop the agent; the next command starts a new one:", "sesh agent stop")
		return false
	}
	known := matErr == nil
	unlocked := agentUnlocks(&st, known, database.UnlockID(mat.Verify))
	state := "locked"
	switch {
	case unlocked:
		state = "unlocked for this vault"
	case st.Unlocked && !known:
		state = "unlocked (can't tell for which vault: the key record is damaged)"
	case st.Unlocked && st.UnlockID == database.UnlockID(mat.Verify):
		state = "unlocked for this vault"
	case st.Unlocked:
		state = "unlocked for another vault or master password"
	}
	if agent.OtherBuild(st.AgentBuild) {
		state += "; it runs another sesh build, so the next command replaces it"
	}
	c.row(markOK, "Agent", "running, "+state)
	return unlocked
}

// agentUnlocks reports whether the agent st describes can unlock the vault
// whose key record id is id without asking: it's unlocked for that vault
// and runs this build (a command would replace one that doesn't, locked).
// known is false when the vault's id can't be read.
func agentUnlocks(st *agent.StatusResponse, known bool, id string) bool {
	return known && st.Unlocked && st.UnlockID == id && !agent.OtherBuild(st.AgentBuild)
}

// checkKeySettings warns when the vault's key was made with weaker
// Argon2id settings than the ones configured now.
func checkKeySettings(c *doctorChecks, have, want kdf.Params) {
	desc := describeKDF(have)
	// Weaker means no setting higher and one lower; threads don't change
	// what guessing costs. A mix (more memory, fewer passes) isn't weaker,
	// and making the key again would lower one.
	weaker := have.Memory <= want.Memory && have.Time <= want.Time && (have.Memory < want.Memory || have.Time < want.Time)
	if weaker {
		c.row(markWarn, "Key settings", desc+": weaker than configured", "configured: "+describeKDF(want))
		c.todo("Apply the configured settings by changing the master password (it can be the same one):", "sesh passwd")
		return
	}
	if have.Memory != want.Memory || have.Time != want.Time {
		c.row(markOK, "Key settings", desc, "differs from configured: "+describeKDF(want))
		return
	}
	c.row(markOK, "Key settings", desc)
}

// checkBackups reports on the vault's backups: the newest, how many, and
// where. None, a newest older than twice backup.every_days, or one dated
// in the future warns.
func checkBackups(c *doctorChecks, cfg *config.Config) {
	dir := cfg.BackupFolder()
	var all []backup.Info
	s, err := backup.SeriesOf(cfg.DBPath.Value, dir)
	if err == nil {
		all, err = s.List()
	}
	if err != nil {
		c.row(markWarn, "Backups", "can't be listed", err.Error())
		c.todo("Check the backups folder, " + tildePath(dir) + "; the row says why it can't be listed.")
		return
	}
	at := now()
	if len(all) > 0 && all[0].Made.After(at) {
		c.row(markWarn, "Backups", "one is dated in the future: "+all[0].Made.Local().Format("2006-01-02 15:04"), tildePath(all[0].Path))
		c.todo("Check this computer's clock; if it's right, remove the backup dated in the future:", "rm "+shell.Quote(all[0].Path))
	}
	every := cfg.BackupEveryDays.Value
	newest, ok := backup.Newest(all, at)
	if every == 0 {
		what := "automatic backups are off (backup.every_days = 0)"
		if ok {
			what += "; newest " + when(newest.Made, at)
		}
		c.row(markNone, "Backups", what)
		return
	}
	if !ok {
		c.row(markWarn, "Backups", "none yet, in "+tildePath(dir))
		c.todo("Make one now (sesh makes them automatically once the vault has entries):", "sesh backup")
		return
	}
	desc := fmt.Sprintf("newest %s, %d kept, in %s", when(newest.Made, at), len(all), tildePath(dir))
	if at.Sub(newest.Made) > 2*time.Duration(every)*24*time.Hour {
		c.row(markWarn, "Backups", desc+": older than expected")
		c.todo("Make one now:", "sesh backup")
		return
	}
	c.row(markOK, "Backups", desc)
}

// clipboardOS and findClipboard are the system and tool --clip copies
// with; tests replace them.
var (
	clipboardOS   = runtime.GOOS
	findClipboard = clipboard.Find
)

// checkClipboard shows the tool --clip copies with, on Linux only: macOS
// always has one.
func checkClipboard(c *doctorChecks) {
	if clipboardOS != "linux" {
		return
	}
	tool, err := findClipboard()
	var missing *clipboard.MissingToolError
	switch {
	case err == nil:
		c.row(markOK, "Clipboard", tool.Name)
	case errors.Is(err, clipboard.ErrNoDisplay):
		c.row(markNone, "Clipboard", "no desktop session here, as over SSH, so --clip can't copy")
	case errors.As(err, &missing):
		c.row(markWarn, "Clipboard", "no tool found, so --clip can't copy")
		c.todo("Install " + missing.Install + ", so --clip can copy.")
	default:
		c.row(markWarn, "Clipboard", "can't be used", err.Error())
	}
}

// when says when t was, from now: "today 09:12", "yesterday 09:12", or
// "2026-10-05 09:12", in local time.
func when(t, now time.Time) string {
	t, now = t.Local(), now.Local()
	day := func(t time.Time) string { return t.Format("2006-01-02") }
	switch day(t) {
	case day(now):
		return "today " + t.Format("15:04")
	case day(now.AddDate(0, 0, -1)):
		return "yesterday " + t.Format("15:04")
	}
	return t.Format("2006-01-02 15:04")
}

// describeKDF is p in words: "256 MiB, 3 passes, 4 threads".
func describeKDF(p kdf.Params) string {
	count := func(n uint32, one, many string) string {
		if n == 1 {
			return "1 " + one
		}
		return fmt.Sprintf("%d %s", n, many)
	}
	return fmt.Sprintf("%d MiB, %s, %s", p.Memory/1024, count(p.Time, "pass", "passes"), count(uint32(p.Threads), "thread", "threads"))
}

// checkVault unlocks the vault and adds its rows to c.
func checkVault(c *doctorChecks, cfg *config.Config, dbPath string, mat *database.UnlockMaterial) error {
	damaged := func(err error) error {
		if database.IsDamaged(err) {
			c.row(markFail, "File", "damaged", err.Error())
			c.todo("Restore the vault from a backup, such as an encrypted export.")
			return nil
		}
		return err
	}
	// Touch ID is checked as found: unlocking removes a stale setup.
	touchFile, touchErr := touchid.ReadFile(filepath.Dir(dbPath))
	ks, err := buildKeySource(cfg)
	if err != nil {
		return damaged(err)
	}
	// Opened without pruning the audit log: a check writes nothing until
	// it knows the file is sound.
	store, err := openStoreWith(dbPath, ks)
	if err != nil {
		return damaged(err)
	}
	defer closeAuditStore(store)
	return verifyVault(c, store, mat, touchFile, touchErr)
}

// keyChangedError is the master password changed by another command while
// the vault was being checked: ErrVaultKeyChanged, as sesh ui takes it, said
// as sesh doctor says it.
type keyChangedError struct{}

func (keyChangedError) Error() string {
	return "the master password was changed by another sesh command while this one was checking; run sesh doctor again"
}
func (keyChangedError) Unwrap() error { return database.ErrVaultKeyChanged }

// verifyVault checks the open vault store: its file, every entry, the
// trash, the history, the recovery key, and Touch ID (as found, touchFile).
func verifyVault(c *doctorChecks, store *database.Store, mat *database.UnlockMaterial, touchFile *touchid.File, touchErr error) error {
	damaged := func(err error) error {
		if database.IsDamaged(err) {
			c.row(markFail, "File", "damaged", err.Error())
			c.todo("Restore the vault from a backup, such as an encrypted export.")
			return nil
		}
		return err
	}
	report, err := store.Verify()
	switch {
	case errors.Is(err, database.ErrVaultKeyChanged):
		return keyChangedError{}
	case database.IsDamaged(err):
		return damaged(err)
	case err != nil:
		return fmt.Errorf("%w; nothing was concluded, so run sesh doctor again", err)
	}

	if len(report.Structure) == 0 {
		c.row(markOK, "File", "ok")
	} else {
		lines := report.Structure
		if len(lines) > structureLinesShown {
			lines = append(lines[:structureLinesShown:structureLinesShown], fmt.Sprintf("… and %d more", len(report.Structure)-structureLinesShown))
		}
		c.row(markFail, "File", "damaged; SQLite reports:", lines...)
		if len(report.Problems) == 0 {
			c.todo("Your entries all read, so save them now, then start a new vault and import them:", "sesh export --file backup.enc")
		} else {
			c.todo("Restore the vault from a backup, such as an encrypted export.")
		}
	}
	if len(report.Problems) == 0 {
		c.row(markOK, "Entries", entryCount(report.Entries)+", all readable")
	} else {
		var details, ids []string
		var named []vault.Key
		unnamed := false
		for _, p := range report.Problems {
			// A name damaged into something that isn't a valid ID, or is
			// another entry's, can't be given to --delete.
			if k, err := vault.ParseKey(p.Key.String()); err != nil || k != p.Key {
				unnamed = true
				username := "no username"
				if p.Key.Username != "" {
					username = fmt.Sprintf("username %q", p.Key.Username)
				}
				details = append(details, fmt.Sprintf("%s entry with a damaged name (service %q, %s): %s", p.Key.Kind, p.Key.Service, username, problemText(p.Kind)))
				continue
			}
			details = append(details, fmt.Sprintf("%s: %s", p.Key, problemText(p.Kind)))
			ids = append(ids, shell.Quote(p.Key.String()))
			named = append(named, p.Key)
		}
		// Why a secret doesn't decrypt goes under the last one that doesn't.
		for i, p := range slices.Backward(report.Problems) {
			if p.Kind == database.ProblemSecret {
				details = slices.Insert(details, i+1, "(damaged, or encrypted with another key)")
				break
			}
		}
		c.fails += len(report.Problems) - 1
		c.row(markFail, "Entries", fmt.Sprintf("%d of %s can't be read", len(report.Problems), entryCount(report.Entries)), details...)
		if len(report.Structure) == 0 {
			switch len(named) {
			case 0:
			case 1:
				c.todo(fmt.Sprintf("Restore %s from a backup (an encrypted export), or delete it:", named[0]), "sesh trash --purge --force "+ids[0])
			default:
				what := "Restore these entries from a backup (an encrypted export), or delete them:"
				if unnamed {
					what = "Restore the entries named above from a backup (an encrypted export), or delete them:"
				}
				c.todo(what, "sesh trash --purge --force "+strings.Join(ids, " "))
			}
			if unnamed {
				c.todo("Restore the vault from a backup, such as an encrypted export: an entry's name is damaged, so sesh can't name it to delete it.")
			}
		}
	}
	checkTrash(c, &report)
	checkHistory(c, &report)
	checkRecovery(c, &report)
	checkTouchID(c, touchFile, touchErr, database.UnlockID(mat.Verify))
	checkAWSCLI(c, store)

	if len(report.Structure) == 0 {
		result := "ok"
		if c.fails > 0 {
			result = countOf(int64(c.fails), "problem")
		}
		store.LogDoctor(fmt.Sprintf("%s, %s", result, entryCount(report.Entries)))
	}
	return nil
}

// checkAWSCLI warns when there are AWS entries but no AWS CLI to use them
// with.
func checkAWSCLI(c *doctorChecks, store *database.Store) {
	k := vault.AWSKey("")
	entries, err := store.List(&vault.Filter{Kind: k.Kind, Service: k.Service})
	if err != nil {
		c.row(markWarn, "AWS CLI", "can't be checked: the AWS entries can't be listed", err.Error())
		c.todo("The entries can't all be listed; see the rows above, or run sesh doctor again.")
		return
	}
	if len(entries) == 0 {
		c.row(markNone, "AWS CLI", "no AWS entries")
		return
	}
	if path, err := lookPath("aws"); err == nil {
		c.row(markOK, "AWS CLI", tildePath(path))
		return
	}
	c.row(markWarn, "AWS CLI", "not found, so the AWS entries can't be used")
	c.todo("Install the AWS CLI: https://aws.amazon.com/cli/")
}

// lookPath finds a program on PATH; tests replace it.
var lookPath = exec.LookPath

// The marks at the start of each row of the report.
const (
	markOK   = "ok"
	markFail = "FAIL"
	markWarn = "warn"
	markNone = "-"
)

// doctorChecks collects the report's rows, what to do, and the tally:
// as text, and as checks, for sesh ui.
type doctorChecks struct {
	part         string // the section rows go under
	rows         strings.Builder
	todos        [][]string
	checks       []tui.Check
	fails, warns int
	// unchecked is set when the vault part was skipped, so the tally
	// doesn't speak for it.
	unchecked bool
}

// section starts a part of the report under title.
func (c *doctorChecks) section(title string) {
	c.rows.WriteString(title + "\n")
	c.part = strings.TrimSpace(title[strings.LastIndex(title, "\n")+1:])
}

// row adds a check's result, with any details under it.
func (c *doctorChecks) row(mark, label, value string, details ...string) {
	switch mark {
	case markFail:
		c.fails++
	case markWarn:
		c.warns++
	}
	fmt.Fprintf(&c.rows, "  %-6s%-16s%s\n", mark, label, value)
	for _, d := range details {
		fmt.Fprintf(&c.rows, "%24s%s\n", "", d)
	}
	c.checks = append(c.checks, tui.Check{Section: c.part, Mark: mark, Label: label, Value: value, Details: details})
}

// todo adds a step to what to do: what to do, then any commands to run.
func (c *doctorChecks) todo(text string, commands ...string) {
	c.todos = append(c.todos, append([]string{text}, commands...))
}

// flush writes the rows so far to w.
func (c *doctorChecks) flush(w io.Writer) error {
	_, err := io.WriteString(w, c.rows.String())
	c.rows.Reset()
	return err
}

// finish writes the rows left, what to do, and the tally, and returns
// errReported when a check failed.
func (c *doctorChecks) finish(w io.Writer) error {
	if len(c.todos) > 0 {
		c.rows.WriteString("\nWhat to do\n")
		for i, t := range c.todos {
			fmt.Fprintf(&c.rows, "  %d. %s\n", i+1, t[0])
			for _, cmd := range t[1:] {
				fmt.Fprintf(&c.rows, "       %s\n", cmd)
			}
		}
	}
	c.rows.WriteString("\n")
	var tally []string
	if c.fails > 0 {
		tally = append(tally, countOf(int64(c.fails), "problem"))
	}
	if c.warns > 0 {
		tally = append(tally, countOf(int64(c.warns), "warning"))
	}
	unchecked := ""
	if c.unchecked {
		unchecked = "; the vault wasn't checked"
	}
	switch {
	case c.fails > 0:
		fmt.Fprintf(&c.rows, "FAIL: %s%s\n", strings.Join(tally, ", "), unchecked)
	case c.warns > 0:
		fmt.Fprintf(&c.rows, "OK, with %s%s\n", tally[0], unchecked)
	default:
		fmt.Fprintf(&c.rows, "OK: no problems%s\n", unchecked)
	}
	if err := c.flush(w); err != nil {
		return err
	}
	if c.fails > 0 {
		return errReported
	}
	return nil
}

// checkTrash reports the entries in the trash, when there are any, and
// those that can't be read, with the command that deletes them for good.
func checkTrash(c *doctorChecks, r *database.VerifyReport) {
	switch {
	case r.Trashed == 0:
	case len(r.TrashProblems) == 0:
		c.row(markOK, "Trash", entryCount(r.Trashed)+", all readable")
	default:
		// Only damaged tags still restore, without them; the rest can't.
		var details, gone, untagged []string
		for _, p := range r.TrashProblems {
			details = append(details, fmt.Sprintf("trash id %d, %s: %s", p.TrashID, p.Key, problemText(p.Kind)))
			id := strconv.FormatInt(p.TrashID, 10)
			if p.Kind == database.ProblemTags {
				untagged = append(untagged, id)
			} else {
				gone = append(gone, id)
			}
		}
		c.fails += len(r.TrashProblems) - 1
		c.row(markFail, "Trash", fmt.Sprintf("%d of %s %s a problem", len(r.TrashProblems), entryCount(r.Trashed), map[bool]string{true: "has", false: "have"}[len(r.TrashProblems) == 1]), details...)
		if len(gone) > 0 {
			c.todo("Delete them for good, as they can't be restored:", "sesh trash remove "+strings.Join(gone, " "))
		}
		for _, id := range untagged {
			c.todo("Restore it, if you want it back; it comes back without its tags:", "sesh trash restore "+id)
		}
	}
}

// checkHistory reports the entries' earlier secrets, when there are any,
// and those that can't be read: for each entry, one --forget naming all of
// its unreadable versions (resolved together, so the numbers hold); for an
// entry in the trash, restoring it first, or deleting it for good.
func checkHistory(c *doctorChecks, r *database.VerifyReport) {
	switch {
	case r.History == 0:
		return
	case len(r.HistoryProblems) == 0:
		c.row(markOK, "History", countOf(int64(r.History), "earlier secret")+", all readable")
		return
	}
	var details []string
	forget := map[vault.Key][]string{}
	var forgetOrder []vault.Key
	trashed := map[int64]vault.Key{}
	var trashOrder []int64
	// Versions whose time alone doesn't read still read: forgetting them is
	// optional, and said in the entry's one --forget when it has one, so
	// following the advice in order can't renumber what it names.
	timeOnly := map[vault.Key][]string{}
	var timeOrder []vault.Key
	for _, p := range r.HistoryProblems {
		switch {
		case p.TrashID != 0:
			details = append(details, fmt.Sprintf("%s, in the trash (id %d): an %s", p.Key, p.TrashID, historyProblemText(p.Kind)))
			if _, ok := trashed[p.TrashID]; !ok {
				trashed[p.TrashID] = p.Key
				trashOrder = append(trashOrder, p.TrashID)
			}
		case p.Kind == database.ProblemTimes:
			details = append(details, fmt.Sprintf("%s, version %d: %s", p.Key, p.Version, historyProblemText(p.Kind)))
			if _, ok := timeOnly[p.Key]; !ok {
				timeOrder = append(timeOrder, p.Key)
			}
			timeOnly[p.Key] = append(timeOnly[p.Key], strconv.Itoa(p.Version))
		default:
			details = append(details, fmt.Sprintf("%s, version %d: %s", p.Key, p.Version, historyProblemText(p.Kind)))
			if _, ok := forget[p.Key]; !ok {
				forgetOrder = append(forgetOrder, p.Key)
			}
			forget[p.Key] = append(forget[p.Key], strconv.Itoa(p.Version))
		}
	}
	for _, k := range forgetOrder {
		what := fmt.Sprintf("Forget %s's earlier secrets that can't be read:", k)
		if t := timeOnly[k]; len(t) > 0 {
			what = fmt.Sprintf("Forget %s's earlier secrets that can't be read (add %s, whose time alone doesn't read, only if you don't need it):", k, strings.Join(t, ","))
		}
		c.todo(what, fmt.Sprintf("sesh history %s --forget %s", shell.Quote(k.String()), strings.Join(forget[k], ",")))
	}
	for _, k := range timeOrder {
		if _, ok := forget[k]; ok {
			continue
		}
		what := fmt.Sprintf("%s's version %s still reads, so this needs nothing; forget it only if you don't need it:", k, timeOnly[k][0])
		if len(timeOnly[k]) > 1 {
			what = fmt.Sprintf("%s's versions %s still read, so these need nothing; forget them only if you don't need them:", k, strings.Join(timeOnly[k], ", "))
		}
		c.todo(what,
			fmt.Sprintf("sesh history %s --forget %s", shell.Quote(k.String()), strings.Join(timeOnly[k], ",")))
	}
	for _, id := range trashOrder {
		k := trashed[id]
		c.todo(fmt.Sprintf("%s, in the trash, has earlier secrets that can't be read: restore it, then run sesh doctor again to forget them; or delete it for good with sesh trash remove %d:", k, id),
			fmt.Sprintf("sesh trash restore %d", id))
	}
	c.fails += len(r.HistoryProblems) - 1
	c.row(markFail, "History", fmt.Sprintf("%d of %s can't be read", len(r.HistoryProblems), countOf(int64(r.History), "earlier secret")), details...)
}

// historyProblemText says what's wrong with an earlier secret.
func historyProblemText(k database.ProblemKind) string {
	if k == database.ProblemTimes {
		return "when it was replaced doesn't read"
	}
	return "earlier secret doesn't decrypt"
}

// problemText says in plain words what's wrong with an entry.
func problemText(k database.ProblemKind) string {
	switch k {
	case database.ProblemSecret:
		return "secret doesn't decrypt"
	case database.ProblemSettings:
		return "settings don't read"
	case database.ProblemTimes:
		return "times don't read"
	case database.ProblemDetails:
		return "notes or fields don't read"
	case database.ProblemTags:
		return "tags don't read"
	}
	return "can't be read"
}

// checkRecovery checks the vault's recovery key record. None is a
// warning: forgetting the master password would lose the vault.
func checkRecovery(c *doctorChecks, r *database.VerifyReport) {
	switch {
	case r.RecoveryErr != nil:
		c.row(markFail, "Recovery key", "its record can't be read", r.RecoveryErr.Error())
	case r.Recovery == nil:
		c.row(markWarn, "Recovery key", "none: if you forget the master password, the vault can't be opened")
		c.todo("Make a recovery key, in case you forget the master password:", "sesh recovery new")
		return
	case r.Recovery.UnlockID != r.KeyID:
		c.row(markFail, "Recovery key", "made for another vault or key")
	default:
		if err := recovery.CheckRecord(r.Recovery); err != nil {
			c.row(markFail, "Recovery key", "its record is damaged", err.Error())
		} else {
			c.row(markOK, "Recovery key", "set, for this vault's key")
			return
		}
	}
	c.todo("Make a new recovery key:", "sesh recovery new")
}

// checkTouchID checks Touch ID unlock for the vault whose key record id is
// id, from its file as read before unlocking (f, err). A stale setup only
// costs typing the password, so it's a warning, never a failure.
func checkTouchID(c *doctorChecks, f *touchid.File, err error, id string) {
	switch {
	case errors.Is(err, os.ErrNotExist):
		c.row(markNone, "Touch ID", "off")
		return
	case err != nil:
		c.row(markWarn, "Touch ID", "its file can't be read", err.Error())
	case f.UnlockID != id:
		c.row(markWarn, "Touch ID", "set up for another vault or an earlier master password")
	case fingerprintsChanged(f):
		c.row(markWarn, "Touch ID", "your fingerprints changed since it was set up")
	default:
		c.row(markOK, "Touch ID", "on, for this vault")
		return
	}
	c.todo("Optional: turn Touch ID back on:", "sesh touchid enable")
}

// doctorReport is sesh doctor's checks, for sesh ui: the setup's, then the
// vault's on store, which the app has open, so nothing asks for the master
// password. The run is recorded in the audit log, as sesh doctor's is.
func doctorReport(app *App, store *database.Store) (tui.Checks, error) {
	var c doctorChecks
	// The vault checked is the one open, wherever the config says now.
	dbPath := store.Path()
	c.section("Setup")
	checkSetupOf(&c, app, dbPath)
	c.section("Vault: " + tildePath(dbPath))
	mat, err := database.ReadUnlockMaterial(dbPath)
	if err != nil {
		c.row(markFail, "File", "can't be read", err.Error())
		c.todo("Restore the vault from a backup, such as an encrypted export.")
		return c.report(), nil
	}
	touchFile, touchErr := touchid.ReadFile(filepath.Dir(dbPath))
	if err := verifyVault(&c, store, &mat, touchFile, touchErr); err != nil {
		return tui.Checks{}, err
	}
	return c.report(), nil
}

// report is the checks made, what to do, and their sum, as sesh ui shows
// them.
func (c *doctorChecks) report() tui.Checks {
	var tally []string
	if c.fails > 0 {
		tally = append(tally, countOf(int64(c.fails), "problem"))
	}
	if c.warns > 0 {
		tally = append(tally, countOf(int64(c.warns), "warning"))
	}
	summary := "OK: no problems"
	switch {
	case c.fails > 0:
		summary = "FAIL: " + strings.Join(tally, ", ")
	case c.warns > 0:
		summary = "OK, with " + tally[0]
	}
	return tui.Checks{Summary: summary, Checks: c.checks, ToDo: c.todos}
}

// cloudFolders are the folders under the home folder a sync tool keeps the
// same as on other computers: by name, or by the start of it (prefix) for
// tools that add an account's name ("Dropbox (Personal)").
var cloudFolders = []struct {
	dir, tool string
	prefix    bool
}{
	{dir: filepath.Join("Library", "Mobile Documents"), tool: "iCloud Drive"},
	{dir: filepath.Join("Library", "CloudStorage"), tool: "a cloud storage app (Dropbox, Google Drive, OneDrive, Box)"},
	{dir: "Dropbox", tool: "Dropbox"},
	{dir: "Dropbox (", tool: "Dropbox", prefix: true},
	{dir: "Google Drive", tool: "Google Drive"},
	{dir: "OneDrive", tool: "OneDrive"},
	{dir: "OneDrive - ", tool: "OneDrive", prefix: true},
	{dir: "Nextcloud", tool: "Nextcloud"},
}

// cloudTool is the sync tool that keeps path the same on other computers,
// by the folder it's in, or "". Folders are compared as the file system
// finds them (within): through links, the vault's own included, and in
// whatever case it ignores.
func cloudTool(path string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	type place struct{ dir, tool string }
	var places []place
	names, _ := os.ReadDir(home) //nolint:errcheck // none read, none matched by the start of its name
	for _, c := range cloudFolders {
		if !c.prefix {
			places = append(places, place{filepath.Join(home, c.dir), c.tool})
			continue
		}
		for _, n := range names {
			if strings.HasPrefix(n.Name(), c.dir) {
				places = append(places, place{filepath.Join(home, n.Name()), c.tool})
			}
		}
	}
	// iCloud Drive's Desktop & Documents: its Desktop and Documents, links
	// to the home folder's, which it then syncs.
	docs := filepath.Join(home, "Library", "Mobile Documents", "com~apple~CloudDocs")
	for _, name := range []string{"Desktop", "Documents"} {
		link, own := filepath.Join(docs, name), filepath.Join(home, name)
		if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			continue
		}
		if to, err := filepath.EvalSymlinks(link); err == nil && within(to, own) && within(own, to) {
			places = append(places, place{own, "iCloud Drive (Desktop & Documents)"})
		}
	}
	// Syncthing's default folder, which it marks as one it shares.
	if _, err := os.Stat(filepath.Join(home, "Sync", ".stfolder")); err == nil {
		places = append(places, place{filepath.Join(home, "Sync"), "Syncthing"})
	}
	for _, p := range places {
		if within(path, p.dir) {
			return p.tool
		}
	}
	return ""
}

// checkCloudFolder warns of a vault kept in a folder a sync tool copies
// between computers: copying a vault while sesh writes it can damage it,
// and two computers writing it lose each other's changes.
func checkCloudFolder(c *doctorChecks, cfg *config.Config) {
	tool := cloudTool(cfg.DBPath.Value)
	if tool == "" {
		return
	}
	c.row(markWarn, "Vault place", "in a folder "+tool+" syncs", "a sync tool copying the vault while sesh writes it can damage it, and two computers writing it lose each other's changes")
	c.todo(moveVaultSteps(cfg, "out of "+tool+"'s folder")+" Then sync it through a sync folder instead:", "sesh sync init")
}

// moveVaultSteps says how to move cfg's vault where: sesh has no command
// for it.
func moveVaultSteps(cfg *config.Config, where string) string {
	to := "a folder of your own"
	if p, err := database.DefaultDBLocation(); err == nil && p != cfg.DBPath.Value {
		if _, err := os.Lstat(p); err == nil {
			to = "a folder of your own (not " + tildePath(filepath.Dir(p)) + ": a vault is there already)"
		} else {
			to = tildePath(filepath.Dir(p)) + " (sesh's usual place)"
		}
	}
	setting := "db_path in " + tildePath(cfg.Path)
	if cfg.DBPath.Source == config.FromEnv || cfg.DBPath.Source == config.FromFlag {
		setting = cfg.DBPath.Origin
	}
	base := filepath.Base(cfg.DBPath.Value)
	return fmt.Sprintf("Move the vault %s: close sesh ui and any other sesh command, move %s (and any %s-wal and %s-shm and touchid.key beside it) to %s, then change %s to its new place (\"Moving the vault\" in the docs says more).", where, base, base, base, to, setting)
}

// checkSync is the sync row: off; the folder, when it's this vault's and
// readable, with when it last synced and what's waiting each way; what's
// waiting for the sync tool. Nothing is unlocked or written.
func checkSync(c *doctorChecks, cfg *config.Config, matErr error) {
	if cfg.SyncDir.Value == "" {
		c.row(markNone, "Sync", "off", "sesh sync init syncs this vault with your other computers")
		return
	}
	value := "with " + tildePath(cfg.SyncDir.Value)
	if matErr != nil {
		c.row(markNone, "Sync", value, "not checked: the vault's key record is damaged (above)")
		return
	}
	if _, err := os.Stat(cfg.SyncDir.Value); errors.Is(err, os.ErrNotExist) {
		c.row(markWarn, "Sync", value, "the folder isn't there now: a drive not connected, or the folder moved")
		c.todo("Connect the drive the sync folder is on; if the folder moved, point sesh at it:", "sesh config set sync.dir <folder>")
		return
	}
	f, err := syncFolderOf(cfg)
	if err != nil {
		c.row(markFail, "Sync", value, err.Error())
		c.todo("Check the sync folder (sesh sync status); to stop syncing:", "sesh sync leave")
		return
	}
	store, err := database.Open(cfg.DBPath.Value, nil)
	if err != nil {
		c.row(markFail, "Sync", value, err.Error())
		return
	}
	defer closeAuditStore(store)
	w, err := syncWaitingIn(store, &f)
	if err != nil {
		c.row(markFail, "Sync", value, err.Error())
		return
	}
	// What sync would refuse (the vault synced with another folder, or
	// never synced, and has entries of its own) fails here too.
	if info, err := f.ReadInfo(); err == nil {
		if err := checkSwitch(store, f, info); err != nil {
			c.row(markFail, "Sync", value, err.Error())
			c.todo("Point sync.dir back at the folder this vault synced with, or stop syncing:", "sesh sync leave")
			return
		}
	}
	switch {
	case w.last != nil:
		value += ", last synced " + w.last.CreatedAt.Local().Format("2006-01-02 15:04")
	case w.synced:
		value += ", synced before (when isn't recorded)"
	default:
		value += ", never synced yet"
	}
	value += fmt.Sprintf("; %d to send, %d to take", w.toSend, w.toTake)
	var details []string
	if w.otherKey > 0 {
		details = append(details, otherKeySaid(w.otherKey))
	}
	for _, p := range w.contents.Problems {
		details = append(details, filepath.Base(p.Path)+": "+p.Why)
	}
	switch {
	case len(w.contents.NotDownloaded) > 0:
		c.row(markWarn, "Sync", value, append([]string{nouns(len(w.contents.NotDownloaded), "entry waits", "entries wait") + " for the sync tool to download their files"}, details...)...)
		c.todo("Keep the sync folder downloaded: in iCloud Drive, Control-click it in Finder and choose Keep Downloaded (macOS 15 or later).")
	case len(details) > 0:
		c.row(markWarn, "Sync", value, details...)
		c.todo("Some of the sync folder's files can't be taken; the next sync says more:", "sesh sync")
	default:
		c.row(markOK, "Sync", value)
	}
}
