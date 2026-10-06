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
	"github.com/bashhack/sesh/internal/keywrap"
	"github.com/bashhack/sesh/internal/recovery"
	"github.com/bashhack/sesh/internal/secure"
)

// recoveryCommands are the commands of `sesh recovery`.
var recoveryCommands = []candidate{
	{"new", "Make a recovery key for this vault, replacing any earlier one"},
	{"remove", "Remove this vault's recovery key"},
	{"status", "Show whether this vault has a recovery key"},
}

// newRecoveryKey makes the key `sesh recovery new` shows, and
// recoveryPrompt is how it talks to the person at the terminal. Tests
// replace both.
var (
	newRecoveryKey = recovery.New
	recoveryPrompt = resolvePasswordPrompt
)

// confirmTries is how many times the last group may be typed wrong before
// the new key is abandoned.
const confirmTries = 3

// wrapFunc wraps the vault key of unlock id to a recovery key's public key.
type wrapFunc func(id string, pub []byte) (keywrap.Wrapped, error)

// agentWrap wraps through an agent unlocked for the vault, so the vault key
// never leaves it.
func agentWrap(conn *agent.Conn) wrapFunc {
	return func(id string, pub []byte) (keywrap.Wrapped, error) {
		return agent.WrapKey(conn, id, agent.WrapForRecovery, pub)
	}
}

// keyWrap wraps with a vault key the caller already holds, as a recovery
// does with the key it has just set.
func keyWrap(key []byte) wrapFunc {
	return func(id string, pub []byte) (keywrap.Wrapped, error) {
		return recovery.Wrap(pub, key, []byte(id))
	}
}

// makeRecoveryKey makes a recovery key for the vault in dataDir, shows it,
// and saves the recovery file once the person has typed back its last
// group. wrap seals the vault key to it. It reports whether the key was
// saved; a key that wasn't confirmed is never saved, so it can't open
// anything.
func makeRecoveryKey(wrap wrapFunc, dataDir string, verify []byte, cfg passwordPromptConfig) (bool, error) {
	if cfg.readLine == nil {
		return false, errors.New("a recovery key is shown once and has to be confirmed, so this needs a terminal")
	}
	k, err := newRecoveryKey()
	if err != nil {
		return false, err
	}
	pub, err := k.PublicKey()
	if err != nil {
		return false, err
	}
	id := agent.UnlockID(verify)
	w, err := wrap(id, pub)
	if err != nil {
		return false, fmt.Errorf("wrap the vault key for the recovery key: %w", err)
	}
	s := k.String()
	note("\nYour recovery key:\n\n    %s\n\nWrite it down and keep it somewhere safe, away from this computer. If you forget\nyour master password, sesh recover uses it to set a new one. Anyone who has it\nand your vault file can open the vault. sesh doesn't keep a copy, so it can't\nshow it again.\n", s)
	last := s[len(s)-4:]
	for try := range confirmTries {
		prompt := "Type the last group (4 characters) to confirm you've saved it: "
		if try > 0 {
			prompt = "That's not the last group. Type it again: "
		}
		typed, err := cfg.readLine(prompt)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return false, err
		}
		if sameGroup(typed, last) {
			if err := recovery.NewFile(id, pub, w).Write(dataDir); err != nil {
				return false, err
			}
			note("The recovery key is set for this vault.")
			return true, nil
		}
	}
	note("No recovery key was set, since it wasn't confirmed. Make one when you're ready with: sesh recovery new")
	return false, nil
}

// sameGroup compares a typed group with the key's, reading it the way
// recovery.Parse does: any case, I or L for 1, O for 0.
func sameGroup(typed, want string) bool {
	norm := strings.NewReplacer("I", "1", "L", "1", "O", "0", "-", "", " ", "")
	return norm.Replace(strings.ToUpper(strings.TrimSpace(typed))) == want
}

// offerRecovery asks once, right after a vault is created at a terminal,
// whether to make a recovery key. The agent must already hold the new
// vault's key.
func offerRecovery(cfg passwordPromptConfig, dbPath string) {
	dataDir := filepath.Dir(dbPath)
	if !cfg.interactive || cfg.confirm == nil || cfg.readLine == nil {
		return
	}
	failed := func(err error) {
		note("warning: couldn't make a recovery key (%v); try later with: sesh recovery new", err)
	}
	mat, err := database.ReadUnlockMaterial(dbPath)
	if err != nil {
		failed(err)
		return
	}
	if f, err := recovery.ReadFile(dataDir); err == nil && f.UnlockID != agent.UnlockID(mat.Verify) {
		note("A recovery key isn't offered for this vault: %s in this folder is another vault's. Keep each vault in its own folder.", recovery.FileName)
		return
	}
	yes, err := cfg.confirm("Make a recovery key, in case you forget your master password? [Y/n] ")
	if err != nil || !yes {
		return
	}
	conn, err := agent.DialExisting()
	if err != nil {
		failed(err)
		return
	}
	defer closeAgentConn(conn)
	if _, err := makeRecoveryKey(agentWrap(conn), dataDir, mat.Verify, cfg); err != nil {
		failed(err)
	}
}

// runRecovery is `sesh recovery new|remove|status`.
func runRecovery(app *App, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: sesh recovery new|remove|status")
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
		f, err := recovery.ReadFile(dataDir)
		if errors.Is(err, os.ErrNotExist) {
			return out("Recovery key: none. Make one with: sesh recovery new")
		}
		if err != nil {
			return err
		}
		if mat, merr := database.ReadUnlockMaterial(cfg.DBPath.Value); merr == nil && f.UnlockID != agent.UnlockID(mat.Verify) {
			return out("Recovery key: out of date, it doesn't open this vault. Make a new one with: sesh recovery new")
		}
		return out("Recovery key: set (made %s)", f.CreatedAt.Local().Format("2006-01-02 15:04"))
	case "remove":
		if _, err := recovery.ReadFile(dataDir); errors.Is(err, os.ErrNotExist) {
			return out("This vault has no recovery key.")
		}
		p := recoveryPrompt()
		if p.interactive && p.confirm != nil {
			yes, err := p.confirm("Remove the recovery key? It will no longer open this vault. [Y/n] ")
			if err != nil || !yes {
				return out("The recovery key was kept.")
			}
		}
		if err := recovery.Remove(dataDir); err != nil {
			return err
		}
		return out("Removed the recovery key; it no longer opens this vault.")
	case "new":
		if err := requireVault(cfg.DBPath.Value, "there's no vault yet: create it first, by running any sesh command or sesh init"); err != nil {
			return err
		}
		p := recoveryPrompt()
		if !p.interactive || p.readLine == nil {
			return errors.New("sesh recovery new needs a terminal: it shows the key once and asks you to confirm you've saved it")
		}
		if f, err := recovery.ReadFile(dataDir); err == nil {
			yes, err := p.confirm(fmt.Sprintf("This vault already has a recovery key (made %s). A new one replaces it, and the old one stops working. Make a new one? [Y/n] ", f.CreatedAt.Local().Format("2006-01-02")))
			if err != nil || !yes {
				return out("The existing recovery key was kept.")
			}
		}
		// Unlock the agent for this vault, asking for the password if needed.
		oracle, typed, err := keySourceFromAgent(cfg.DBPath.Value, p)
		secure.SecureZeroBytes(typed)
		if err != nil {
			return err
		}
		if oracle == nil {
			return errors.New("making a recovery key needs the sesh agent, which isn't available (see the warning above)")
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
		_, err = makeRecoveryKey(agentWrap(conn), dataDir, mat.Verify, p)
		return err
	default:
		return fmt.Errorf("unknown recovery command %q (use new, remove, or status)", args[0])
	}
}

// rewrapRecovery keeps the recovery key working after the master password
// changes: the new vault key is wrapped to the same recovery key, which
// needs only its public half, so there's no prompt. It returns a line to
// show, or "" when the folder has no recovery key for the vault whose key
// record had the id oldID.
func rewrapRecovery(dbPath, oldID string, newKey []byte) string {
	dataDir := filepath.Dir(dbPath)
	f, err := recovery.ReadFile(dataDir)
	if errors.Is(err, os.ErrNotExist) || (err == nil && f.UnlockID != oldID) {
		return ""
	}
	if err == nil && len(newKey) == 0 {
		err = errors.New("the new key wasn't available")
	}
	if err == nil {
		var mat database.UnlockMaterial
		if mat, err = database.ReadUnlockMaterial(dbPath); err == nil {
			id := agent.UnlockID(mat.Verify)
			w, werr := recovery.Wrap(f.PublicKey, newKey, []byte(id))
			if err = werr; err == nil {
				nf := recovery.NewFile(id, f.PublicKey, w)
				nf.CreatedAt = f.CreatedAt // the same key
				if err = nf.Write(dataDir); err == nil {
					return "Your recovery key still works: it now opens the vault with the new master password."
				}
			}
		}
	}
	// A recovery file that can't open the vault would only fail when it's
	// needed, so it's removed, and the person is told.
	if rerr := recovery.Remove(dataDir); rerr != nil {
		return fmt.Sprintf("warning: the recovery key no longer opens the vault (%v), and its file couldn't be removed (%v); run: sesh recovery new", err, rerr)
	}
	return fmt.Sprintf("warning: the recovery key no longer opens the vault (%v), so it was removed; make a new one with: sesh recovery new", err)
}

// readLine reads one line from in, writing prompt to w. End of input with
// nothing typed is io.EOF.
func readLine(in io.Reader, w io.Writer, prompt string) (string, error) {
	if _, err := fmt.Fprint(w, prompt); err != nil {
		return "", err
	}
	line, err := readAnswer(in)
	if errors.Is(err, io.EOF) && strings.TrimSpace(line) == "" {
		return "", io.EOF
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// readAnswer reads one line from in, up to and not including its newline,
// one byte at a time. A buffered reader would read ahead and lose answers
// that arrive together (pasted, or typed ahead) when the next prompt makes
// its own. A last line without a newline comes back with io.EOF.
func readAnswer(in io.Reader) (string, error) {
	var line []byte
	var b [1]byte
	for {
		n, err := in.Read(b[:])
		if n == 1 {
			if b[0] == '\n' {
				return string(line), nil
			}
			line = append(line, b[0])
		}
		if err != nil {
			return string(line), err
		}
	}
}

// keyTries is how many times the recovery key may be typed before sesh
// recover gives up.
const keyTries = 3

// runRecover is `sesh recover`: it opens the vault with its recovery key,
// sets a new master password (the same re-encryption as a password change),
// and replaces the recovery key, since the used one has been taken out and
// typed in.
func runRecover(app *App, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("sesh recover takes no arguments, got %q", strings.Join(args, " "))
	}
	cfg, err := settings()
	if err != nil {
		return err
	}
	dataDir := filepath.Dir(cfg.DBPath.Value)
	if err := requireVault(cfg.DBPath.Value, "there's no vault here to recover"); err != nil {
		return err
	}
	p := recoveryPrompt()
	if !p.interactive || p.prompt == nil {
		return errors.New("sesh recover needs a terminal: it asks for the recovery key and a new master password")
	}
	f, err := recovery.ReadFile(dataDir)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("this vault has no recovery key, so sesh can't set a new master password for it. If you made an encrypted export, start a new vault and import it")
	}
	if err != nil {
		return err
	}
	mat, err := database.ReadUnlockMaterial(cfg.DBPath.Value)
	if err != nil {
		return err
	}
	if f.UnlockID != agent.UnlockID(mat.Verify) {
		return errors.New("the recovery file is out of date: it was made for this vault before its master password changed some other way, so it can't open it")
	}

	key, err := openWithRecoveryKey(f, mat.Verify, p)
	if err != nil {
		return err
	}
	src := &recoveredKey{key: key, id: f.UnlockID}
	note("The recovery key opens this vault. Choose a new master password.")
	newKey, err := rotateMasterPassword(app, p, src)
	src.Close()
	defer secure.SecureZeroBytes(newKey)
	if newKey == nil {
		return err // nothing changed: cancelled (nil), or failed before the swap
	}

	// The new vault is in place, so the used key stops working: its file
	// goes, even if writing the summary failed, and a new key is offered.
	if rerr := recovery.Remove(dataDir); rerr != nil {
		return fmt.Errorf("the master password was changed, but the used recovery key's file couldn't be removed (%w); run: sesh recovery remove", rerr)
	}
	if err != nil {
		return err
	}
	note("Your recovery key has been used, so it no longer works.")
	newMat, err := database.ReadUnlockMaterial(cfg.DBPath.Value)
	if err != nil {
		return err
	}
	yes, err := p.confirm("Make a new recovery key now? [Y/n] ")
	if err == nil && yes {
		saved, merr := makeRecoveryKey(keyWrap(newKey), dataDir, newMat.Verify, p)
		if merr != nil {
			return merr
		}
		if saved {
			return nil
		}
	}
	note("This vault has no recovery key now; make one any time with: sesh recovery new")
	return nil
}

// openWithRecoveryKey asks for the recovery key, up to keyTries times, and
// returns the vault key it opens from f, checked against the vault's
// verify blob.
func openWithRecoveryKey(f *recovery.File, verify []byte, p passwordPromptConfig) ([]byte, error) {
	var lastErr error
	for range keyTries {
		typed, err := p.prompt("Recovery key: ")
		if err != nil {
			return nil, err
		}
		k, err := recovery.Parse(string(typed))
		secure.SecureZeroBytes(typed)
		if err != nil {
			note("%v", err)
			lastErr = err
			continue
		}
		key, err := k.Unwrap(f.Wrapped(), []byte(f.UnlockID))
		if errors.Is(err, recovery.ErrWrongKey) {
			lastErr = errors.New("that recovery key doesn't open this vault (another vault's key, or one that was replaced)")
			note("%v", lastErr)
			continue
		}
		if err != nil {
			return nil, err
		}
		opened, err := database.Decrypt(key, verify)
		if err != nil || !bytes.Equal(opened, []byte(database.VerifyPlaintext)) {
			secure.SecureZeroBytes(key)
			return nil, errors.New("the recovery file doesn't open this vault's key; it may be from a different copy of the vault")
		}
		return key, nil
	}
	return nil, lastErr
}

// recoveredKey is a vault key opened with a recovery key, given to the
// rotation as the key source of the vault as it is.
// recoveredKey is the vault key a recovery key opened, and the id of the
// key record it was checked against.
type recoveredKey struct {
	id  string
	key []byte
}

// UnlockID is the id of the key record the key was checked against.
func (r *recoveredKey) UnlockID() (string, error) { return r.id, nil } //nolint:unparam // the signature CheckKey asks key sources for

func (r *recoveredKey) GetEncryptionKey() ([]byte, error) { return bytes.Clone(r.key), nil }
func (r *recoveredKey) StoreEncryptionKey([]byte) error {
	return errors.New("a recovered key can't be stored")
}
func (r *recoveredKey) RequiresUserInput() bool { return false }
func (r *recoveredKey) Name() string            { return "recovery key" }
func (r *recoveredKey) Close()                  { secure.SecureZeroBytes(r.key) }
