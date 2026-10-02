package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/agent"
	"github.com/bashhack/sesh/internal/database"
)

// unlockTestAgent unlocks the agent at SESH_AUTH_SOCK with the vault's
// current sidecar, as an interactive sesh run would.
func unlockTestAgent(t *testing.T, env *rekeyTestEnv, password string) {
	t.Helper()
	mat, err := database.ReadUnlockMaterial(env.dataDir)
	if err != nil {
		t.Fatalf("ReadUnlockMaterial: %v", err)
	}
	conn, err := agent.DialExisting()
	if err != nil {
		t.Fatalf("DialExisting: %v", err)
	}
	defer closeAgentConn(conn)
	if err := agent.Unlock(conn, []byte(password), mat.Salt, mat.Verify, mat.Params); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
}

func testAgentUnlocked(t *testing.T) bool {
	t.Helper()
	conn, err := agent.DialExisting()
	if err != nil {
		t.Fatalf("DialExisting: %v", err)
	}
	defer closeAgentConn(conn)
	st, err := agent.Status(conn)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	return st.Unlocked
}

// populateUnlockedPasswordVault makes a password-mode vault and an agent
// unlocked with its old password.
func populateUnlockedPasswordVault(t *testing.T) {
	t.Helper()
	env := setupRekeyEnv(t)
	t.Setenv("SESH_KEY_SOURCE", "password")
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"sesh-password/password/github/alice": "hunter2"})
	t.Setenv("SESH_MASTER_PASSWORD", "")
	startTestAgent(t)
	unlockTestAgent(t, env, "old-pw-1234")
}

func TestRotate_LocksAgentHoldingOldKey(t *testing.T) {
	populateUnlockedPasswordVault(t)

	app, stderr := rekeyTestApp("y\n")
	if err := runRotateMasterPassword(app, rotateTestCfg("old-pw-1234", "new-pw-5678", "new-pw-5678")); err != nil {
		t.Fatalf("runRotateMasterPassword: %v\nstderr:\n%s", err, stderr.String())
	}
	if testAgentUnlocked(t) {
		t.Error("agent still unlocked with the old key after rotation")
	}
	if !strings.Contains(stderr.String(), "Locked the sesh agent") {
		t.Errorf("stderr missing lock notice:\n%s", stderr.String())
	}
}

func TestRekey_PasswordToKeychainLocksAgent(t *testing.T) {
	populateUnlockedPasswordVault(t)
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")

	app, stderr := rekeyTestApp("y\n")
	if err := runRekey(app, []string{"--to=keychain"}, newKCMock(nil)); err != nil {
		t.Fatalf("runRekey: %v\nstderr:\n%s", err, stderr.String())
	}
	if testAgentUnlocked(t) {
		t.Error("agent still unlocked with the old key after rekey")
	}
}

// failOnWriter fails any write containing marker and passes the rest.
type failOnWriter struct{ marker string }

func (w failOnWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte(w.marker)) {
		return 0, errors.New("stderr closed")
	}
	return len(p), nil
}

func TestRotate_LocksAgentEvenIfSummaryWriteFails(t *testing.T) {
	populateUnlockedPasswordVault(t)

	app, _ := rekeyTestApp("y\n")
	app.Stderr = failOnWriter{marker: "Rotated"}
	err := runRotateMasterPassword(app, rotateTestCfg("old-pw-1234", "new-pw-5678", "new-pw-5678"))
	if err == nil || !strings.Contains(err.Error(), "stderr closed") {
		t.Fatalf("err = %v, want the summary write failure", err)
	}
	if testAgentUnlocked(t) {
		t.Error("agent still unlocked with the old key after a committed rotation")
	}
}

func TestRekey_LocksAgentEvenIfSummaryWriteFails(t *testing.T) {
	populateUnlockedPasswordVault(t)
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")

	app, _ := rekeyTestApp("y\n")
	app.Stderr = failOnWriter{marker: "Rekeyed"}
	err := runRekey(app, []string{"--to=keychain"}, newKCMock(nil))
	if err == nil || !strings.Contains(err.Error(), "stderr closed") {
		t.Fatalf("err = %v, want the summary write failure", err)
	}
	if testAgentUnlocked(t) {
		t.Error("agent still unlocked with the old key after a committed rekey")
	}
}

func TestRotate_CancelledLeavesAgentUnlocked(t *testing.T) {
	populateUnlockedPasswordVault(t)

	app, stderr := rekeyTestApp("n\n")
	if err := runRotateMasterPassword(app, rotateTestCfg("old-pw-1234")); err != nil {
		t.Fatalf("runRotateMasterPassword: %v", err)
	}
	if !testAgentUnlocked(t) {
		t.Error("cancelled rotation locked the agent")
	}
	if strings.Contains(stderr.String(), "agent") {
		t.Errorf("cancelled rotation mentioned the agent:\n%s", stderr.String())
	}
}

func TestLockAgentAfterRekey(t *testing.T) {
	for _, tc := range []struct {
		setup   func(t *testing.T)
		name    string
		wantSub string
	}{
		{func(t *testing.T) { t.Setenv("SESH_AUTH_SOCK", tempAgentSocket(t)) }, "no agent running", ""},
		{startTestAgent, "agent already locked", ""},
		{startRefusingAgent, "agent refuses", "run `sesh agent lock`"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup(t)
			note := lockAgentAfterRekey()
			if tc.wantSub == "" && note != "" {
				t.Errorf("note = %q, want none", note)
			}
			if tc.wantSub != "" && !strings.Contains(note, tc.wantSub) {
				t.Errorf("note = %q, want it to contain %q", note, tc.wantSub)
			}
		})
	}
}
