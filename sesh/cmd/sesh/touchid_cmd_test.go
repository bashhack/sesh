package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/agent"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/testutil"
	"github.com/bashhack/sesh/internal/touchid"
)

// softwareTouchID stands in for the Mac's Touch ID: a software P-256 key
// plays the Secure Enclave for the CLI and the in-process agent. Setting
// *fail makes the next unwraps fail as a refused fingerprint would. It
// returns a count of Touch ID prompts.
func softwareTouchID(t *testing.T) (prompts *int, fail *error) {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	var failure error
	origAvail, origNewKey, origUnwrap := touchIDAvailable, touchIDNewKey, agent.TouchIDUnwrap
	touchIDAvailable = func() bool { return true }
	touchIDNewKey = func() ([]byte, []byte, error) { return []byte("software chip key"), priv.PublicKey().Bytes(), nil }
	agent.TouchIDUnwrap = func(_ []byte, w touchid.Wrapped, aad []byte) ([]byte, error) {
		n++
		if failure != nil {
			return nil, failure
		}
		return touchid.UnwrapWith(func(peer []byte) ([]byte, error) {
			p, err := ecdh.P256().NewPublicKey(peer)
			if err != nil {
				return nil, err
			}
			return priv.ECDH(p)
		}, w, aad)
	}
	t.Cleanup(func() { touchIDAvailable, touchIDNewKey, agent.TouchIDUnwrap = origAvail, origNewKey, origUnwrap })
	return &n, &failure
}

// withAnswer gives cfg a [Y/n] answer, as a person at the terminal would.
func withAnswer(cfg passwordPromptConfig, yes bool) passwordPromptConfig {
	cfg.confirm = func(string) (bool, error) { return yes, nil }
	return cfg
}

// createVaultWithTouchID creates a vault at a terminal and accepts the
// Touch ID offer, then locks the agent. It returns the vault path.
func createVaultWithTouchID(t *testing.T) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "passwords.db")
	restore := testutil.RedirectStderr(t)
	oracle, err := buildKeySourceWith(dbPath, "password", withAnswer(interactivePrompt(t, "first-password-1234", "first-password-1234"), true))
	out := restore()
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	closeKeySource(t, oracle)
	if !strings.Contains(out, "Touch ID unlock is on") {
		t.Fatalf("stderr missing the Touch ID confirmation:\n%s", out)
	}
	lockTestAgent(t)
	return dbPath
}

func lockTestAgent(t *testing.T) {
	t.Helper()
	conn, err := agent.DialExisting()
	if err != nil {
		t.Fatal(err)
	}
	defer closeAgentConn(conn)
	if err := agent.Lock(conn); err != nil {
		t.Fatal(err)
	}
}

func TestTouchID_OfferedAtFirstRunThenUnlocksWithoutAPassword(t *testing.T) {
	startTestAgent(t)
	prompts, _ := softwareTouchID(t)
	dbPath := createVaultWithTouchID(t)

	f, err := touchid.ReadFile(filepath.Dir(dbPath))
	if err != nil {
		t.Fatalf("no touchid.key after accepting the offer: %v", err)
	}
	mat, err := database.ReadUnlockMaterial(filepath.Dir(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	if f.UnlockID != agent.UnlockID(mat.Verify) {
		t.Error("touchid.key is bound to another vault")
	}

	// The agent is locked: the next command asks for a fingerprint, not a
	// password (interactivePrompt fails the test if a password is asked for).
	oracle, err := buildKeySourceWith(dbPath, "password", interactivePrompt(t))
	if err != nil {
		t.Fatalf("Touch ID unlock: %v", err)
	}
	closeKeySource(t, oracle)
	if *prompts != 1 {
		t.Errorf("Touch ID prompts = %d, want 1", *prompts)
	}
}

func TestTouchID_OfferDeclined(t *testing.T) {
	startTestAgent(t)
	softwareTouchID(t)
	dbPath := filepath.Join(t.TempDir(), "passwords.db")
	oracle, err := buildKeySourceWith(dbPath, "password", withAnswer(interactivePrompt(t, "first-password-1234", "first-password-1234"), false))
	if err != nil {
		t.Fatal(err)
	}
	closeKeySource(t, oracle)
	if _, err := touchid.ReadFile(filepath.Dir(dbPath)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("touchid.key exists after declining (err %v)", err)
	}
}

func TestTouchID_FallsBackToThePassword(t *testing.T) {
	for name, tt := range map[string]struct {
		fail        error
		wantNote    string
		fileRemains bool
	}{
		"cancelled":      {touchid.ErrCancelled, "", true},
		"unavailable":    {touchid.ErrUnavailable, "Touch ID isn't available here", true},
		"locked out":     {touchid.ErrLockedOut, "locked after too many attempts", true},
		"not recognised": {touchid.ErrFailed, "didn't recognise the fingerprint", true},
		"out of date":    {touchid.ErrWrapMismatch, "out of date for this vault and is now off", false},
	} {
		t.Run(name, func(t *testing.T) {
			startTestAgent(t)
			_, fail := softwareTouchID(t)
			dbPath := createVaultWithTouchID(t)
			*fail = tt.fail

			restore := testutil.RedirectStderr(t)
			oracle, err := buildKeySourceWith(dbPath, "password", interactivePrompt(t, "first-password-1234"))
			out := restore()
			if err != nil {
				t.Fatalf("password fallback: %v", err)
			}
			closeKeySource(t, oracle)
			if tt.wantNote != "" && !strings.Contains(out, tt.wantNote) {
				t.Errorf("stderr = %q, want %q", out, tt.wantNote)
			}
			if tt.wantNote == "" && strings.Contains(out, "Touch ID") {
				t.Errorf("a cancelled prompt printed %q", out)
			}
			_, ferr := touchid.ReadFile(filepath.Dir(dbPath))
			if remains := ferr == nil; remains != tt.fileRemains {
				t.Errorf("touchid.key remains = %v, want %v", remains, tt.fileRemains)
			}
		})
	}
}

func TestTouchID_ScriptsNeverWaitOnAFingerprint(t *testing.T) {
	startTestAgent(t)
	prompts, _ := softwareTouchID(t)
	dbPath := createVaultWithTouchID(t)

	cfg := interactivePrompt(t, "first-password-1234")
	cfg.interactive = false
	oracle, err := buildKeySourceWith(dbPath, "password", cfg)
	if err != nil {
		t.Fatal(err)
	}
	closeKeySource(t, oracle)
	if *prompts != 0 {
		t.Errorf("a non-interactive run asked for Touch ID %d time(s)", *prompts)
	}
}

func TestRunTouchID_StatusDisableAndRefusals(t *testing.T) {
	startTestAgent(t)
	softwareTouchID(t)
	dbPath := createVaultWithTouchID(t)
	useConfigFile(t, "db_path = \""+dbPath+"\"\n")

	run := func(args ...string) (string, error) {
		app := agentTestApp()
		err := runTouchID(app, args)
		return app.Stdout.(*bytes.Buffer).String(), err
	}
	if out, err := run("status"); err != nil || !strings.Contains(out, "Touch ID unlock: on") || !strings.Contains(out, "Touch ID on this Mac: available") {
		t.Errorf("status = %q, %v", out, err)
	}
	if out, err := run("disable"); err != nil || !strings.Contains(out, "is off") {
		t.Errorf("disable = %q, %v", out, err)
	}
	if out, err := run("status"); err != nil || !strings.Contains(out, "Touch ID unlock: off") {
		t.Errorf("status after disable = %q, %v", out, err)
	}

	touchIDAvailable = func() bool { return false }
	if _, err := run("enable"); err == nil || !strings.Contains(err.Error(), "isn't available here") {
		t.Errorf("enable without Touch ID: err = %v", err)
	}
	useConfigFile(t, "key_source = \"keychain\"\n")
	if _, err := run("enable"); err == nil || !strings.Contains(err.Error(), "master password") {
		t.Errorf("enable with the keychain key source: err = %v", err)
	}
	if _, err := run("frobnicate"); err == nil {
		t.Error("an unknown subcommand was accepted")
	}
}

func TestRunTouchID_Enable(t *testing.T) {
	startTestAgent(t)
	softwareTouchID(t)
	dbPath := filepath.Join(t.TempDir(), "passwords.db")
	oracle, err := buildKeySourceWith(dbPath, "password", withAnswer(interactivePrompt(t, "first-password-1234", "first-password-1234"), false))
	if err != nil {
		t.Fatal(err)
	}
	closeKeySource(t, oracle)
	useConfigFile(t, "db_path = \""+dbPath+"\"\n")

	app := agentTestApp()
	if err := runTouchID(app, []string{"enable"}); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if _, err := touchid.ReadFile(filepath.Dir(dbPath)); err != nil {
		t.Errorf("no touchid.key after enable: %v", err)
	}
}

func TestRotate_RewrapsTouchIDUnlock(t *testing.T) {
	env := setupRekeyEnv(t)
	startTestAgent(t)
	prompts, _ := softwareTouchID(t)
	t.Setenv("SESH_KEY_SOURCE", "password")
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"sesh-password/password/x/y": "v"})
	t.Setenv("SESH_MASTER_PASSWORD", "")
	// Turn Touch ID unlock on for the vault, as `sesh touchid enable` does.
	conn, err := agent.DialExisting()
	if err != nil {
		t.Fatal(err)
	}
	mat, err := database.ReadUnlockMaterial(env.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Unlock(conn, []byte("old-pw-1234"), mat.Salt, mat.Verify, mat.Params); err != nil {
		t.Fatal(err)
	}
	if err := enableTouchID(conn, env.dataDir, mat.Verify); err != nil {
		t.Fatal(err)
	}
	closeAgentConn(conn)

	app, stderr := rekeyTestApp("y\n")
	if err := runRotateMasterPassword(app, rotateTestCfg("old-pw-1234", "new-pw-5678", "new-pw-5678")); err != nil {
		t.Fatalf("rotate: %v\n%s", err, stderr)
	}
	if !strings.Contains(stderr.String(), "Touch ID unlock now opens the vault with the new master password") {
		t.Errorf("stderr missing the re-wrap note:\n%s", stderr.String())
	}
	newMat, err := database.ReadUnlockMaterial(env.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	f, err := touchid.ReadFile(env.dataDir)
	if err != nil || f.UnlockID != agent.UnlockID(newMat.Verify) {
		t.Fatalf("touchid.key after rotation: %+v, %v; want it bound to the new sidecar", f, err)
	}
	// The agent was locked by the rotation; a fingerprint now opens the
	// rotated vault, with no password.
	oracle, err := buildKeySourceWith(env.dbPath, "password", interactivePrompt(t))
	if err != nil {
		t.Fatalf("Touch ID unlock after rotation: %v", err)
	}
	closeKeySource(t, oracle)
	if *prompts != 1 {
		t.Errorf("Touch ID prompts = %d, want 1", *prompts)
	}
}

func TestRekey_ToKeychainTurnsTouchIDOff(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_KEY_SOURCE", "password")
	t.Setenv("SESH_MASTER_PASSWORD", "old-master-password-1234")
	populatePasswordStore(t, env, map[string]string{"sesh-password/password/x/y": "v"})
	if err := touchid.NewFile("id", []byte("b"), []byte("p"), touchid.Wrapped{EphemeralPub: []byte("e"), Ciphertext: []byte("c")}).Write(env.dataDir); err != nil {
		t.Fatal(err)
	}
	app, stderr := rekeyTestApp("y\n")
	if err := runRekey(app, []string{"--to=keychain"}, newKCMock(nil)); err != nil {
		t.Fatalf("rekey: %v\n%s", err, stderr)
	}
	if _, err := touchid.ReadFile(env.dataDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("touchid.key still exists after switching to the Keychain key (err %v)", err)
	}
	if !strings.Contains(stderr.String(), "Touch ID unlock is off") {
		t.Errorf("stderr missing the note:\n%s", stderr)
	}
}
