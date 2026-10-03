package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bashhack/sesh/internal/agent"
	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/touchid"
)

// The Touch ID calls the CLI makes itself. Tests replace them, so they
// never create Secure Enclave keys or depend on the machine's sensor.
var (
	touchIDAvailable = touchid.Available
	touchIDNewKey    = touchid.NewKey
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
		note("Touch ID unlock failed (%v), so enter your master password. If you changed your fingerprints, turn it back on with: sesh touchid enable", pe)
	}
	return false, nil
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
	w, err := agent.TouchIDWrap(conn, id, pub)
	if err != nil {
		return fmt.Errorf("wrap the vault key for Touch ID: %w", err)
	}
	return touchid.NewFile(id, blob, pub, w).Write(dataDir)
}

// offerTouchID asks once, right after a vault is created at a terminal,
// whether to unlock it with Touch ID from now on. The agent must already
// hold the new vault's key.
func offerTouchID(cfg passwordPromptConfig, dataDir string) {
	if !cfg.interactive || cfg.confirm == nil || !touchIDAvailable() {
		return
	}
	yes, err := cfg.confirm("Unlock with Touch ID instead of typing your password? [Y/n] ")
	if err != nil || !yes {
		return
	}
	mat, err := database.ReadUnlockMaterial(dataDir)
	if err != nil {
		note("warning: couldn't turn on Touch ID unlock (%v); try later with: sesh touchid enable", err)
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
	usesPassword := cfg.Backend.Value == config.BackendSQLite && cfg.KeySource.Value == config.KeySourcePassword

	out := func(format string, a ...any) error {
		_, err := fmt.Fprintf(app.Stdout, format+"\n", a...)
		return err
	}
	switch args[0] {
	case "status":
		if !usesPassword {
			return out("Touch ID unlock: not used (it unlocks a vault protected by a master password)")
		}
		state := "off"
		if f, err := touchid.ReadFile(dataDir); err == nil {
			state = "on"
			if mat, merr := database.ReadUnlockMaterial(dataDir); merr == nil && f.UnlockID != agent.UnlockID(mat.Verify) {
				state = "out of date (turn it back on with: sesh touchid enable)"
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
		if err := touchid.Remove(dataDir); err != nil {
			return err
		}
		return out("Touch ID unlock is off; sesh will ask for your master password.")
	case "enable":
		if !usesPassword {
			return errors.New("touch ID unlock works with a vault protected by a master password (backend = \"sqlite\", key_source = \"password\")")
		}
		if !touchIDAvailable() {
			return errors.New("touch ID isn't available here: this Mac needs a Touch ID sensor with an enrolled fingerprint, and sesh must run in your desktop session (not over SSH)")
		}
		if sidecarMissing(dataDir) {
			return errors.New("there's no vault yet: create it first, by running any sesh command or sesh init")
		}
		// Unlock the agent for this vault, asking for the password if needed.
		oracle, typed, err := keySourceFromAgent(dataDir, resolvePasswordPrompt())
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
		mat, err := database.ReadUnlockMaterial(dataDir)
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

// rewrapTouchID keeps Touch ID unlock working after the master password
// changes: the new key is wrapped to the same Secure Enclave key, which
// needs only its public half, so there's no prompt. It returns a line to
// show, or "" when Touch ID unlock wasn't on.
func rewrapTouchID(dataDir string, newKey []byte) string {
	f, err := touchid.ReadFile(dataDir)
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err == nil && len(newKey) == 0 {
		err = errors.New("the new key wasn't available")
	}
	if err == nil {
		mat, merr := database.ReadUnlockMaterial(dataDir)
		err = merr
		if err == nil {
			id := agent.UnlockID(mat.Verify)
			var w touchid.Wrapped
			if w, err = touchid.Wrap(f.PublicKey, newKey, []byte(id)); err == nil {
				if err = touchid.NewFile(id, f.KeyBlob, f.PublicKey, w).Write(dataDir); err == nil {
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

// dropTouchID turns Touch ID unlock off when the vault no longer uses a
// master password. It returns a line to show, or "" when it wasn't on.
func dropTouchID(dataDir string) string {
	if _, err := os.Stat(filepath.Join(dataDir, touchid.FileName)); err != nil {
		return ""
	}
	if err := touchid.Remove(dataDir); err != nil {
		return fmt.Sprintf("warning: couldn't remove the Touch ID unlock file (%v); run: sesh touchid disable", err)
	}
	return "Touch ID unlock is off: it only unlocks a vault protected by a master password."
}

// askYes reads a [Y/n] answer from in, writing prompt to w. Enter takes the
// default, yes; n or no declines. End of input with nothing typed (Ctrl-D)
// isn't an answer, so it declines too.
func askYes(in io.Reader, w io.Writer, prompt string) (bool, error) {
	if _, err := fmt.Fprint(w, prompt); err != nil {
		return false, err
	}
	line, err := bufio.NewReader(in).ReadString('\n')
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
