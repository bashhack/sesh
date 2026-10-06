package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bashhack/sesh/internal/agent"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/touchid"
)

// The Touch ID calls the CLI makes itself. Tests replace them, so they
// never create Secure Enclave keys or depend on the machine's sensor.
var (
	touchIDAvailable     = touchid.Available
	touchIDNewKey        = touchid.NewKey
	touchIDBiometryState = touchid.BiometryState
)

// tryTouchID unlocks the agent with a fingerprint when this vault has Touch
// ID unlock turned on. It reports whether the agent is now unlocked; if not,
// the caller asks for the master password, and anything worth knowing has
// been said in one line. An error means the agent connection is no longer
// usable.
func tryTouchID(conn *agent.Conn, dataDir, id string, verify []byte) (bool, error) {
	f, err := touchid.ReadFile(dataDir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			note("warning: ignoring the Touch ID unlock file: %v", err)
		}
		return false, nil
	}
	if f.UnlockID != id {
		return false, nil // made for another vault; not this one's to use
	}
	if overSSH() {
		// The agent may have been started on the desktop, so the Touch ID
		// sheet would appear on the Mac's own screen, not to the person
		// typing over SSH, and this command would wait on it.
		note("Touch ID isn't used over SSH, so enter your master password.")
		return false, nil
	}
	if fingerprintsChanged(f) {
		// The Secure Enclave key no longer works, so don't show a sheet
		// that can't succeed.
		if rerr := touchid.Remove(dataDir); rerr != nil {
			note("warning: remove the out-of-date Touch ID unlock file: %v", rerr)
		}
		note("Your fingerprints changed since Touch ID unlock was turned on, so it no longer works and is now off. Enter your master password; turn it back on afterwards with: sesh touchid enable")
		return false, nil
	}
	err = agent.UnlockTouchID(conn, f, verify)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, touchid.ErrCancelled):
		// The person chose to type the password instead.
	case errors.Is(err, touchid.ErrUnavailable):
		note("Touch ID isn't available here, so enter your master password.")
	case errors.Is(err, touchid.ErrLockedOut):
		note("Touch ID is locked after too many attempts, so enter your master password.")
	case errors.Is(err, touchid.ErrFailed):
		note("Touch ID didn't recognise the fingerprint, so enter your master password.")
	case errors.Is(err, agent.ErrTouchIDStale):
		if rerr := touchid.Remove(dataDir); rerr != nil {
			note("warning: remove the out-of-date Touch ID unlock file: %v", rerr)
		}
		note("Touch ID unlock was out of date for this vault and is now off. Enter your master password; turn it back on afterwards with: sesh touchid enable")
	default:
		pe, ok := errors.AsType[*agent.ProtocolError](err)
		if !ok {
			return false, err
		}
		note("Touch ID unlock didn't work (%v), so enter your master password.", pe)
	}
	return false, nil
}

// overSSH reports whether this command runs in an SSH session, which sshd
// marks in the environment it gives the remote shell.
func overSSH() bool {
	return os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_CLIENT") != ""
}

// fingerprintsChanged reports whether a fingerprint was added or removed
// since f was made, which leaves its Secure Enclave key unusable. Without a
// stored or a current identifier it can't tell, and reports false.
func fingerprintsChanged(f *touchid.File) bool {
	if len(f.BiometryState) == 0 {
		return false
	}
	now, err := touchIDBiometryState()
	return err == nil && len(now) > 0 && !bytes.Equal(now, f.BiometryState)
}

// enableTouchID turns on Touch ID unlock for the vault in dataDir: a new
// Secure Enclave key, the agent's key for the vault wrapped to it, and the
// two written to touchid.key. conn must be an agent unlocked for the vault;
// the key never leaves it.
func enableTouchID(conn *agent.Conn, dataDir string, verify []byte) error {
	id := agent.UnlockID(verify)
	blob, pub, err := touchIDNewKey()
	if err != nil {
		return fmt.Errorf("create the Touch ID key: %w", err)
	}
	w, err := agent.WrapKey(conn, id, agent.WrapForTouchID, pub)
	if err != nil {
		return fmt.Errorf("wrap the vault key for Touch ID: %w", err)
	}
	f := touchid.NewFile(id, blob, pub, w)
	// Unreadable, it stays empty and the check before each unlock is skipped.
	f.BiometryState, _ = touchIDBiometryState() //nolint:errcheck // optional
	return f.Write(dataDir)
}

// offerTouchID asks once, right after a vault is created at a terminal,
// whether to unlock it with Touch ID from now on. The agent must already
// hold the new vault's key.
func offerTouchID(cfg passwordPromptConfig, dbPath string) {
	dataDir := filepath.Dir(dbPath)
	if !cfg.interactive || cfg.confirm == nil || !touchIDAvailable() {
		return
	}
	mat, err := database.ReadUnlockMaterial(dbPath)
	if err != nil {
		note("warning: couldn't turn on Touch ID unlock (%v); try later with: sesh touchid enable", err)
		return
	}
	if f, err := touchid.ReadFile(dataDir); err == nil && f.UnlockID != agent.UnlockID(mat.Verify) {
		note("Touch ID unlock isn't offered for this vault: %s in this folder is another vault's. Keep each vault in its own folder.", touchid.FileName)
		return
	}
	yes, err := cfg.confirm("Unlock with Touch ID instead of typing your password? [Y/n] ")
	if err != nil || !yes {
		return
	}
	conn, err := agent.DialExisting()
	if err != nil {
		note("warning: couldn't turn on Touch ID unlock (%v); try later with: sesh touchid enable", err)
		return
	}
	defer closeAgentConn(conn)
	if err := enableTouchID(conn, dataDir, mat.Verify); err != nil {
		note("warning: couldn't turn on Touch ID unlock (%v); try later with: sesh touchid enable", err)
		return
	}
	note("Touch ID unlock is on. When the agent has locked itself, sesh asks for your fingerprint first; your master password still works.")
}

// touchIDCommands are the commands of `sesh touchid`.
var touchIDCommands = []candidate{
	{"enable", "Unlock this vault with Touch ID"},
	{"disable", "Turn Touch ID unlock off"},
	{"status", "Show whether Touch ID unlock is on and usable here"},
}

// runTouchID is `sesh touchid enable|disable|status`.
func runTouchID(app *App, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: sesh touchid enable|disable|status")
	}
	cfg, err := settings()
	if err != nil {
		return err
	}
	dataDir := filepath.Dir(cfg.DBPath.Value)

	out := func(format string, a ...any) error {
		_, err := fmt.Fprintf(app.Stdout, format+"\n", a...)
		return err
	}
	switch args[0] {
	case "status":
		state := "off"
		if f, err := touchid.ReadFile(dataDir); err == nil {
			state = "on"
			if mat, merr := database.ReadUnlockMaterial(cfg.DBPath.Value); merr == nil && f.UnlockID != agent.UnlockID(mat.Verify) {
				state = "out of date (turn it back on with: sesh touchid enable)"
			} else if fingerprintsChanged(f) {
				state = "out of date: your fingerprints changed (turn it back on with: sesh touchid enable)"
			}
		}
		here := "available"
		if !touchIDAvailable() {
			here = "not available (no sensor, no enrolled fingerprint, or no GUI session, e.g. over SSH)"
		}
		if err := out("Touch ID unlock: %s", state); err != nil {
			return err
		}
		return out("Touch ID on this Mac: %s", here)
	case "disable":
		if f, err := touchid.ReadFile(dataDir); err == nil && anotherVaults(f.UnlockID, cfg.DBPath.Value) {
			return out("Touch ID unlock isn't on for this vault; %s in this folder is another vault's, so it was left alone.", touchid.FileName)
		}
		if err := touchid.Remove(dataDir); err != nil {
			return err
		}
		return out("Touch ID unlock is off; sesh will ask for your master password.")
	case "enable":
		if !touchIDAvailable() {
			return errors.New("touch ID isn't available here: this Mac needs a Touch ID sensor with an enrolled fingerprint, and sesh must run in your desktop session (not over SSH)")
		}
		if err := requireVault(cfg.DBPath.Value, "there's no vault yet: create it first, by running any sesh command or sesh init"); err != nil {
			return err
		}
		p := resolvePasswordPrompt()
		if f, err := touchid.ReadFile(dataDir); err == nil && anotherVaults(f.UnlockID, cfg.DBPath.Value) {
			if !p.interactive || p.readLine == nil {
				return fmt.Errorf("%s in this folder is another vault's; turning Touch ID unlock on for this vault would take it away from that one, so run this at a terminal to confirm", touchid.FileName)
			}
			yes, err := askNo(p.readLine, fmt.Sprintf("%s in this folder is another vault's, which would then need its password. Turn Touch ID unlock on for this vault instead? [y/N] ", touchid.FileName))
			if err != nil {
				return err
			}
			if !yes {
				return out("Touch ID unlock was left with the other vault.")
			}
		}
		// Unlock the agent for this vault, asking for the password if needed.
		oracle, typed, err := keySourceFromAgent(cfg.DBPath.Value, p)
		secure.SecureZeroBytes(typed)
		if err != nil {
			return err
		}
		if oracle == nil {
			return errors.New("touch ID unlock needs the sesh agent, which isn't available (see the warning above)")
		}
		if c, ok := oracle.(interface{ Close() }); ok {
			c.Close()
		}
		mat, err := database.ReadUnlockMaterial(cfg.DBPath.Value)
		if err != nil {
			return err
		}
		conn, err := agent.DialExisting()
		if err != nil {
			return err
		}
		defer closeAgentConn(conn)
		if err := enableTouchID(conn, dataDir, mat.Verify); err != nil {
			return err
		}
		return out("Touch ID unlock is on. When the agent has locked itself, sesh asks for your fingerprint first; your master password still works.")
	default:
		return fmt.Errorf("unknown touchid command %q (use enable, disable, or status)", args[0])
	}
}

// anotherVaults reports whether a Touch ID file whose unlock id
// is fileID was made for a vault other than the one at dbPath.
func anotherVaults(fileID, dbPath string) bool {
	mat, err := database.ReadUnlockMaterial(dbPath)
	return err == nil && fileID != agent.UnlockID(mat.Verify)
}

// askNo asks a [y/N] question with readLine: only y or yes is a yes, and
// end of input is a no.
func askNo(readLine func(string) (string, error), prompt string) (bool, error) {
	answer, err := readLine(prompt)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

// rewrapTouchID keeps Touch ID unlock working after the master password
// changes: the new key is wrapped to the same Secure Enclave key, which
// needs only its public half, so there's no prompt. It returns a line to
// show, or "" when Touch ID unlock wasn't on for the vault whose key record
// had the id oldID.
func rewrapTouchID(dbPath, oldID string, newKey []byte) string {
	dataDir := filepath.Dir(dbPath)
	f, err := touchid.ReadFile(dataDir)
	if errors.Is(err, os.ErrNotExist) || (err == nil && f.UnlockID != oldID) {
		return ""
	}
	if err == nil && len(newKey) == 0 {
		err = errors.New("the new key wasn't available")
	}
	if err == nil {
		mat, merr := database.ReadUnlockMaterial(dbPath)
		err = merr
		if err == nil {
			id := agent.UnlockID(mat.Verify)
			var w touchid.Wrapped
			if w, err = touchid.Wrap(f.PublicKey, newKey, []byte(id)); err == nil {
				nf := touchid.NewFile(id, f.KeyBlob, f.PublicKey, w)
				nf.BiometryState = f.BiometryState // same Secure Enclave key
				if err = nf.Write(dataDir); err == nil {
					return "Touch ID unlock now opens the vault with the new master password."
				}
			}
		}
	}
	if rerr := touchid.Remove(dataDir); rerr != nil {
		return fmt.Sprintf("warning: Touch ID unlock is out of date (%v) and couldn't be removed (%v); run: sesh touchid disable", err, rerr)
	}
	return fmt.Sprintf("Touch ID unlock was turned off (%v); turn it back on with: sesh touchid enable", err)
}

// askYes reads a [Y/n] answer from in, writing prompt to w. Enter takes the
// default, yes; n or no declines. End of input with nothing typed (Ctrl-D)
// isn't an answer, so it declines too.
func askYes(in io.Reader, w io.Writer, prompt string) (bool, error) {
	if _, err := fmt.Fprint(w, prompt); err != nil {
		return false, err
	}
	line, err := readAnswer(in)
	if errors.Is(err, io.EOF) && strings.TrimSpace(line) == "" {
		return false, nil
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "n", "no":
		return false, nil
	}
	return true, nil
}

// note writes one line to stderr.
func note(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...) //nolint:errcheck // best-effort notice
}
