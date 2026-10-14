package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bashhack/sesh/internal/agent"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/touchid"
	"github.com/bashhack/sesh/internal/tui"
)

// uiTouchID is Touch ID unlock's state for the vault at dbPath, and
// whether Touch ID is usable here.
func uiTouchID(dbPath string) tui.TouchID {
	t := tui.TouchID{Said: "off", Here: touchIDAvailable()}
	switch {
	case !t.Here:
		t.Why = "this Mac needs a Touch ID sensor with an enrolled fingerprint, and sesh must run in your desktop session (not over SSH)."
	case overSSH():
		t.Here, t.Why = false, "sesh doesn't use Touch ID over SSH."
	}
	f, err := touchid.ReadFile(filepath.Dir(dbPath))
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		t.Said = "its file can't be read"
	case anotherVaults(f.UnlockID, dbPath):
		t.Said, t.Other = "set up for another vault or an earlier master password", true
	case fingerprintsChanged(f):
		t.Said = "out of date: your fingerprints changed"
	default:
		t.Said, t.On = "on", true
	}
	if !t.Here {
		t.Said += " (Touch ID isn't usable here)"
	}
	return t
}

// uiSetTouchID turns Touch ID unlock for the vault at dbPath on, through
// the agent the app unlocked, or off, as sesh touchid enable and disable
// do.
func uiSetTouchID(dbPath string, on, takeOther bool) (string, error) {
	dataDir := filepath.Dir(dbPath)
	if !on {
		if f, err := touchid.ReadFile(dataDir); err == nil && anotherVaults(f.UnlockID, dbPath) {
			return "", tui.Refused(fmt.Sprintf("Touch ID unlock isn't on for this vault; %s in this folder is another vault's, so it was left alone.", touchid.FileName))
		}
		if err := touchid.Remove(dataDir); err != nil {
			return "", err
		}
		return "Touch ID unlock is off; sesh will ask for your master password.", nil
	}
	if !touchIDAvailable() {
		return "", errors.New("touch ID isn't available here: this Mac needs a Touch ID sensor with an enrolled fingerprint, and sesh must run in your desktop session (not over SSH)")
	}
	if os.Getenv("SESH_MASTER_PASSWORD") != "" {
		return "", errors.New("touch ID unlock is set up through sesh's agent, which sesh doesn't use while SESH_MASTER_PASSWORD is set; unset it, then run: sesh touchid enable")
	}
	mat, err := database.ReadUnlockMaterial(dbPath)
	if err != nil {
		return "", err
	}
	// Made another vault's since the panel was read, it's asked about.
	if f, err := touchid.ReadFile(dataDir); err == nil && f.UnlockID != agent.UnlockID(mat.Verify) && !takeOther {
		return "", tui.Refused(fmt.Sprintf("%s in this folder is set up for another vault or an earlier master password; Enter again asks whether to take it.", touchid.FileName))
	}
	conn, err := agent.DialExisting()
	if agent.IsNotRunning(err) {
		return "", errors.New("touch ID unlock is set up through sesh's agent, which isn't running; run: sesh touchid enable")
	}
	if err != nil {
		return "", uiLocked(err)
	}
	defer closeAgentConn(conn)
	if err := enableTouchID(conn, dataDir, mat.Verify); err != nil {
		return "", uiLocked(err)
	}
	return "Touch ID unlock is on.", nil
}
