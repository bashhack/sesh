package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/bashhack/sesh/internal/agent"
	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/touchid"
	"github.com/bashhack/sesh/internal/tui"
	"github.com/bashhack/sesh/internal/vault"
)

const uiUsage = `Usage:
  sesh ui    Search every entry; Enter copies its secret, or its TOTP code

Type to search, as --action search does; ↑ and ↓ move; Enter copies, and
the clipboard clears after clipboard_timeout; Esc clears the search, or
quits. TOTP entries show their code and the seconds it has left.

It locks after the agent's idle timeout (agent.idle_timeout) without a key
pressed, or when the agent locks, and asks for the master password again.`

// runUI is sesh ui: the search screen.
func runUI(app *App, args []string) error {
	if len(args) > 0 {
		if isHelp(args[0]) {
			_, err := fmt.Fprintln(app.Stdout, uiUsage)
			return err
		}
		return fmt.Errorf("sesh ui takes no arguments, got %q", strings.Join(args, " "))
	}
	if app.StdinIsTerminal == nil || !app.StdinIsTerminal() {
		return errors.New("sesh ui needs a terminal; to search from a script, use: sesh --service password --action search --query <words>")
	}
	cfg, err := settings()
	if err != nil {
		return err
	}
	if err := requireVault(cfg.DBPath.Value, "there's no vault yet: create it first, by running any sesh command or sesh init"); err != nil {
		return err
	}
	// The first unlock is the usual prompt, before the app draws.
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		return err
	}
	m := tui.New(uiOptions(app, cfg, newUIVault(store)))
	defer m.Close()
	if _, err := tea.NewProgram(m, tea.WithInput(app.Stdin), tea.WithOutput(app.Stdout)).Run(); err != nil {
		return fmt.Errorf("sesh ui: %w", err)
	}
	return m.Err()
}

// uiOptions are the app's, with v open.
func uiOptions(app *App, cfg *config.Config, v tui.Vault) tui.Options {
	dbPath := cfg.DBPath.Value
	opts := tui.Options{
		Vault:       v,
		Copy:        app.ClipboardCopy,
		ClearAfter:  cfg.ClipboardTimeout.Value,
		IdleTimeout: cfg.AgentIdleTimeout.Value,
		MaxLifetime: cfg.AgentMaxLifetime.Value,
		Now:         time.Now,
		Unlock: func(pw []byte) (tui.Vault, error) {
			store, err := reopenWith(cfg, pw)
			if err != nil {
				return nil, err
			}
			return newUIVault(store), nil
		},
	}
	if os.Getenv("SESH_MASTER_PASSWORD") == "" && touchIDSetUp(dbPath) {
		opts.TouchID = func() (tui.Vault, error) {
			store, err := reopenWithTouchID(dbPath)
			if err != nil {
				return nil, err
			}
			return newUIVault(store), nil
		}
	}
	return opts
}

// reopenWith opens the vault again with the password pw, which it wipes, as the
// first unlock did but without a prompt: one try, through the agent
// unless the master password comes from SESH_MASTER_PASSWORD.
func reopenWith(cfg *config.Config, pw []byte) (*database.Store, error) {
	defer secure.SecureZeroBytes(pw)
	pc := passwordPromptConfig{
		prompt:  func(string) ([]byte, error) { return bytes.Clone(pw), nil },
		fromEnv: os.Getenv("SESH_MASTER_PASSWORD") != "",
	}.withKDF(cfg.KDF())
	oracle, err := buildKeySourceWith(cfg.DBPath.Value, pc)
	if errors.Is(err, database.ErrWrongPassword) {
		return nil, tui.ErrWrongPassword
	}
	if err != nil {
		return nil, err
	}
	return openStoreWith(cfg.DBPath.Value, oracle)
}

// touchIDSetUp says whether Touch ID unlock is on for the vault at dbPath.
func touchIDSetUp(dbPath string) bool {
	mat, err := database.ReadUnlockMaterial(dbPath)
	if err != nil {
		return false
	}
	f, err := touchid.ReadFile(filepath.Dir(dbPath))
	return err == nil && f.UnlockID == agent.UnlockID(mat.Verify)
}

// reopenWithTouchID opens the vault again with a fingerprint, through the
// agent; why it didn't is the error.
func reopenWithTouchID(dbPath string) (*database.Store, error) {
	mat, err := database.ReadUnlockMaterial(dbPath)
	if err != nil {
		return nil, err
	}
	conn, err := agent.EnsureAgent()
	if err != nil {
		return nil, fmt.Errorf("sesh agent unavailable: %w", err)
	}
	id := agent.UnlockID(mat.Verify)
	var said []string
	ok, err := tryTouchID(conn, filepath.Dir(dbPath), id, mat.Verify, func(format string, a ...any) {
		said = append(said, fmt.Sprintf(format, a...))
	})
	if !ok {
		closeAgentConn(conn)
		switch {
		case err != nil:
			return nil, err
		case len(said) > 0:
			return nil, errors.New(strings.Join(said, " "))
		}
		return nil, errors.New("unlocking with Touch ID didn't work; enter your master password")
	}
	return openStoreWith(dbPath, agent.NewOracle(conn, id))
}

// uiVault is the vault as the app reads it.
type uiVault struct {
	store   *database.Store
	mgr     *password.Manager
	version atomic.Int64 // the data version Changed last saw
}

func newUIVault(store *database.Store) *uiVault {
	return &uiVault{store: store, mgr: password.NewManager(store)}
}

// Search is every entry for "", or the ones sesh's search finds, best
// first.
func (u *uiVault) Search(query string) ([]vault.Entry, error) {
	all, err := u.store.List(&vault.Filter{})
	if err != nil || strings.TrimSpace(query) == "" {
		return all, err
	}
	found, err := u.mgr.SearchIn(query, &password.ListFilter{})
	if err != nil {
		return nil, err
	}
	byID := make(map[string]int, len(all))
	for i := range all {
		byID[all[i].Key.String()] = i
	}
	out := make([]vault.Entry, 0, len(found))
	for i := range found {
		if j, ok := byID[found[i].ID]; ok {
			out = append(out, all[j])
		}
	}
	return out, nil
}

func (u *uiVault) Secret(k vault.Key, reading string) ([]byte, error) {
	secret, err := u.store.GetFor(k, reading)
	return secret, uiLocked(err)
}

func (u *uiVault) CodeKey(k vault.Key) ([]byte, error) {
	key, err := u.store.CodeKey(k)
	return key, uiLocked(err)
}

// Changed says whether another command committed a change since the last
// call; the first call says no.
func (u *uiVault) Changed() (bool, error) {
	v, err := u.store.DataVersion()
	if err != nil {
		return false, err
	}
	last := u.version.Swap(v)
	return last != 0 && v != last, nil
}

func (u *uiVault) Close() error { return u.store.Close() }

// uiLocked is err as the app takes it: one meaning the vault must be
// unlocked again is tui.ErrLocked, saying why.
func uiLocked(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, database.ErrVaultKeyChanged):
		return tui.Locked("The vault's master password was changed, or the vault restored, by another sesh command.")
	case agent.Locked(err):
		return tui.Locked("sesh's agent locked.")
	}
	return err
}
