package main

import (
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
			var out strings.Builder
			lockAgentAfterRekey(&out)
			if tc.wantSub == "" && out.Len() != 0 {
				t.Errorf("output = %q, want none", out.String())
			}
			if tc.wantSub != "" && !strings.Contains(out.String(), tc.wantSub) {
				t.Errorf("output = %q, want it to contain %q", out.String(), tc.wantSub)
			}
		})
	}
}
