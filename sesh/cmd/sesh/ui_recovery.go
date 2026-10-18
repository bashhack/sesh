package main

import (
	"errors"
	"os"
	"strings"

	"github.com/bashhack/sesh/internal/agent"
	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/tui"
)

// uiRecovery is the state of the recovery key of the vault cfg names, as
// sesh recovery status says it.
func uiRecovery(cfg *config.Config) (tui.Recovery, error) {
	dbPath := cfg.DBPath.Value
	unsent := ""
	if recoveryChanged(cfg) {
		unsent = ", not sent to the other computers yet"
	}
	f, err := database.ReadRecovery(dbPath)
	switch {
	case errors.Is(err, database.ErrNoRecovery), errors.Is(err, database.ErrNoVault):
		return tui.Recovery{Said: "none" + unsent}, nil
	case err != nil:
		return tui.Recovery{Said: "its record can't be read", Set: true}, nil //nolint:nilerr // said in the row, which offers removing it
	}
	r := tui.Recovery{Said: "set, made " + f.CreatedAt.Local().Format("2006-01-02") + unsent, Made: f.CreatedAt, Set: true}
	if mat, merr := database.ReadUnlockMaterial(dbPath); merr == nil && f.UnlockID != agent.UnlockID(mat.Verify) {
		r.Said = "made for another vault: it doesn't open this one"
	}
	return r, nil
}

// uiNewRecovery makes a recovery key for the vault cfg names, through the
// agent the app unlocked, as sesh recovery new does: a vault that syncs
// takes the folder's first, and sends its own once it's saved, which is
// once it's confirmed.
func uiNewRecovery(cfg *config.Config) (*tui.NewRecovery, error) {
	dbPath := cfg.DBPath.Value
	if os.Getenv("SESH_MASTER_PASSWORD") != "" {
		return nil, errors.New("a recovery key is made through sesh's agent, which sesh doesn't use while SESH_MASTER_PASSWORD is set; unset it, then run: sesh recovery new")
	}
	var first string
	if cfg.SyncDir.Value != "" {
		if store := agentStore(cfg); store != nil {
			first = strings.Join(recoveryLines(cfg, store, false), " ")
			closeAuditStore(store)
		}
	}
	mat, err := database.ReadUnlockMaterial(dbPath)
	if err != nil {
		return nil, err
	}
	old, rerr := database.ReadRecovery(dbPath)
	replacing := rerr == nil
	conn, err := agent.DialExisting()
	if agent.IsNotRunning(err) {
		return nil, errors.New("a recovery key is made through sesh's agent, which isn't running; run: sesh recovery new")
	}
	if err != nil {
		return nil, uiLocked(err)
	}
	p, err := prepareRecovery(agentWrap(conn), dbPath, mat.Verify)
	closeAgentConn(conn)
	if err != nil {
		return nil, uiLocked(err)
	}
	nr := &tui.NewRecovery{
		Said:      first,
		Replacing: replacing,
		Key:       p.shown,
		Matches:   func(typed string) bool { return sameGroup(typed, p.last()) },
		Save: func() (tui.Done, error) {
			if err := p.save(); err != nil {
				if errors.Is(err, database.ErrVaultKeyChanged) {
					return tui.Done{}, tui.Refused("the master password was changed by another sesh command while this key was shown, so it wasn't saved and opens nothing: throw away the key you wrote down, and make a new one.")
				}
				return tui.Done{}, err
			}
			d := tui.Done{Said: "The recovery key is set for this vault."}
			if said := recoveryChangeSent(cfg); said != "" {
				d.Said += " " + said
			}
			if replacing {
				d.OldBackups, d.Renew = uiOldBackups(dbPath, "recovery key")
			}
			return d, nil
		},
	}
	if replacing {
		nr.Made = old.CreatedAt
	}
	return nr, nil
}

// uiRemoveRecovery removes the recovery key of the vault cfg names, as
// sesh recovery remove does.
func uiRemoveRecovery(cfg *config.Config) (tui.Done, error) {
	dbPath := cfg.DBPath.Value
	if err := database.RemoveRecovery(dbPath); err != nil {
		return tui.Done{}, err
	}
	d := tui.Done{Said: "Removed the recovery key; it no longer opens this vault."}
	if said := recoveryChangeSent(cfg); said != "" {
		d.Said += " " + said
	}
	d.OldBackups, d.Renew = uiOldBackups(dbPath, "recovery key")
	return d, nil
}
