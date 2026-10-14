package main

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/agent"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/touchid"
	"github.com/bashhack/sesh/internal/tui"
)

// The app turns Touch ID unlock on through the agent, as sesh touchid enable does, after which a fingerprint
// unlocks it again; and off. Its row says each state sesh touchid status does.
func TestUI_TouchID(t *testing.T) {
	env, _ := recoverableVault(t)
	prompts, _ := softwareTouchID(t)
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := uiSetTouchID(env.dbPath, true); !errors.Is(err, tui.ErrLocked) {
		t.Errorf("the agent locked: %v", err)
	}
	conn, err := agent.DialExisting()
	if err != nil {
		t.Fatal(err)
	}
	defer closeAgentConn(conn)
	mat, err := database.ReadUnlockMaterial(env.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Unlock(conn, []byte("forgotten-pw-1234"), mat.Salt, mat.Verify, mat.Params); err != nil {
		t.Fatal(err)
	}
	if s, err := uiTouchID(env.dbPath); err != nil || s.Said != "off" || s.On || !s.Here {
		t.Fatalf("before: %+v, %v", s, err)
	}
	said, err := uiSetTouchID(env.dbPath, true)
	if err != nil || !strings.HasPrefix(said, "Touch ID unlock is on") {
		t.Fatalf("on: %q, %v", said, err)
	}
	if s, err := uiTouchID(env.dbPath); err != nil || s.Said != "on" || !s.On || !touchIDSetUp(env.dbPath) {
		t.Errorf("after: %+v, %v", s, err)
	}
	// The app's locked screen offers it now, without starting again.
	opts := uiOptions(agentTestApp(), cfg, nil)
	if opts.TouchID == nil || opts.TouchIDOn == nil || !opts.TouchIDOn() {
		t.Error("the locked screen doesn't offer Touch ID once it's on")
	}
	// The locked screen's fingerprint opens it.
	if err := agent.Lock(conn); err != nil {
		t.Fatal(err)
	}
	store, err := reopenWithTouchID(cfg)
	if err != nil || *prompts != 1 {
		t.Fatalf("a fingerprint after turning it on: %v, %d prompts", err, *prompts)
	}
	store.Close() //nolint:errcheck,gosec // test cleanup

	orig := touchIDBiometryState
	touchIDBiometryState = func() ([]byte, error) { return []byte("enrolled fingerprints 2"), nil }
	if s, _ := uiTouchID(env.dbPath); s.Said != "out of date: your fingerprints changed" || s.On { //nolint:errcheck // checked by its state
		t.Errorf("fingerprints changed: %+v", s)
	}
	touchIDBiometryState = orig
	if said, err := uiSetTouchID(env.dbPath, false); err != nil || !strings.HasPrefix(said, "Touch ID unlock is off") || opts.TouchIDOn() {
		t.Errorf("off: %q, %v", said, err)
	}
}

// Another vault's file is said, and not removed; with Touch ID not usable here, or the master password from
// SESH_MASTER_PASSWORD, or no agent, it isn't turned on, saying why.
func TestUI_TouchIDRefused(t *testing.T) {
	healthVault(t)
	softwareTouchID(t)
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	db := cfg.DBPath.Value
	if _, err := uiSetTouchID(db, true); err == nil || !strings.Contains(err.Error(), "SESH_MASTER_PASSWORD") {
		t.Errorf("SESH_MASTER_PASSWORD set: %v", err)
	}
	t.Setenv("SESH_MASTER_PASSWORD", "")
	if _, err := uiSetTouchID(db, true); err == nil || err.Error() != "touch ID unlock is set up through sesh's agent, which isn't running; run: sesh touchid enable" {
		t.Errorf("no agent: %v", err)
	}
	pub := bytes.Repeat([]byte{4}, 65)
	if err := touchid.NewFile("another-key", []byte("blob"), pub, touchid.Wrapped{EphemeralPub: []byte("e"), Ciphertext: []byte("c")}).Write(filepath.Dir(db)); err != nil {
		t.Fatal(err)
	}
	if s, err := uiTouchID(db); err != nil || !s.Other || s.On || s.Said != "set up for another vault or an earlier master password" {
		t.Errorf("another vault's: %+v, %v", s, err)
	}
	if _, err := uiSetTouchID(db, false); !errors.Is(err, tui.ErrRefused) {
		t.Errorf("turning another vault's off: %v", err)
	}
	if _, err := touchid.ReadFile(filepath.Dir(db)); err != nil {
		t.Errorf("another vault's file was removed: %v", err)
	}
	touchIDAvailable = func() bool { return false }
	if s, _ := uiTouchID(db); s.Here || !strings.HasSuffix(s.Said, "(Touch ID isn't usable here)") { //nolint:errcheck // checked by its state
		t.Errorf("not usable: %+v", s)
	}
	if _, err := uiSetTouchID(db, true); err == nil || !strings.Contains(err.Error(), "isn't available here") {
		t.Errorf("not usable, on: %v", err)
	}
}
