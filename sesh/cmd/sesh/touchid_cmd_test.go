package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"io"
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
	// A developer running the tests over SSH still gets the desktop path.
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("SSH_CLIENT", "")
	var n int
	var failure error
	origAvail, origNewKey, origState, origUnwrap := touchIDAvailable, touchIDNewKey, touchIDBiometryState, agent.TouchIDUnwrap
	touchIDAvailable = func() bool { return true }
	touchIDNewKey = func() ([]byte, []byte, error) { return []byte("software chip key"), priv.PublicKey().Bytes(), nil }
	touchIDBiometryState = func() ([]byte, error) { return []byte("enrolled fingerprints 1"), nil }
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
	t.Cleanup(func() {
		touchIDAvailable, touchIDNewKey, touchIDBiometryState, agent.TouchIDUnwrap = origAvail, origNewKey, origState, origUnwrap
	})
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
	oracle, err := buildKeySourceWith(dbPath, withAnswer(interactivePrompt(t, "first-password-1234", "first-password-1234"), true))
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
	oracle, err := buildKeySourceWith(dbPath, interactivePrompt(t))
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
	oracle, err := buildKeySourceWith(dbPath, withAnswer(interactivePrompt(t, "first-password-1234", "first-password-1234"), false))
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
		"other error":    {errors.New("touch ID: com.apple.LocalAuthentication error -1004"), "Touch ID unlock didn't work (", true},
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
			oracle, err := buildKeySourceWith(dbPath, interactivePrompt(t, "first-password-1234"))
			out := restore()
			if err != nil {
				t.Fatalf("password fallback: %v", err)
			}
			closeKeySource(t, oracle)
			if tt.wantNote != "" && !strings.Contains(out, tt.wantNote) {
				t.Errorf("stderr = %q, want %q", out, tt.wantNote)
			}
			if strings.Contains(out, "fingerprints") {
				t.Errorf("stderr guesses at a fingerprint change: %q", out)
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

func TestTouchID_FingerprintsChanged(t *testing.T) {
	startTestAgent(t)
	prompts, _ := softwareTouchID(t)
	dbPath := createVaultWithTouchID(t)
	f, err := touchid.ReadFile(filepath.Dir(dbPath))
	if err != nil || string(f.BiometryState) != "enrolled fingerprints 1" {
		t.Fatalf("touchid.key biometry state = %q, %v", f.BiometryState, err)
	}
	touchIDBiometryState = func() ([]byte, error) { return []byte("enrolled fingerprints 2"), nil }

	restore := testutil.RedirectStderr(t)
	oracle, err := buildKeySourceWith(dbPath, interactivePrompt(t, "first-password-1234"))
	out := restore()
	if err != nil {
		t.Fatalf("password after a fingerprint change: %v", err)
	}
	closeKeySource(t, oracle)
	if *prompts != 0 {
		t.Errorf("asked for Touch ID %d time(s) with a key that can't work", *prompts)
	}
	if want := "Your fingerprints changed since Touch ID unlock was turned on"; !strings.Contains(out, want) {
		t.Errorf("stderr = %q, want %q", out, want)
	}
	if _, err := touchid.ReadFile(filepath.Dir(dbPath)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("touchid.key remains after a fingerprint change (err %v)", err)
	}
}

// Without a stored or a current identifier there's nothing to compare, so
// the fingerprint is asked for as usual.
func TestTouchID_UnknownFingerprintStateStillPrompts(t *testing.T) {
	for name, tt := range map[string]struct {
		now    func() ([]byte, error)
		stored []byte
	}{
		"not stored":     {func() ([]byte, error) { return []byte("enrolled fingerprints 2"), nil }, nil},
		"unreadable now": {func() ([]byte, error) { return nil, touchid.ErrUnavailable }, []byte("enrolled fingerprints 1")},
	} {
		t.Run(name, func(t *testing.T) {
			startTestAgent(t)
			prompts, _ := softwareTouchID(t)
			dbPath := createVaultWithTouchID(t)
			dir := filepath.Dir(dbPath)
			f, err := touchid.ReadFile(dir)
			if err != nil {
				t.Fatal(err)
			}
			f.BiometryState = tt.stored
			if err := f.Write(dir); err != nil {
				t.Fatal(err)
			}
			touchIDBiometryState = tt.now

			oracle, err := buildKeySourceWith(dbPath, interactivePrompt(t))
			if err != nil {
				t.Fatalf("Touch ID unlock: %v", err)
			}
			closeKeySource(t, oracle)
			if *prompts != 1 {
				t.Errorf("Touch ID prompts = %d, want 1", *prompts)
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
	oracle, err := buildKeySourceWith(dbPath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	closeKeySource(t, oracle)
	if *prompts != 0 {
		t.Errorf("a non-interactive run asked for Touch ID %d time(s)", *prompts)
	}
}

func TestTouchID_SkippedOverSSH(t *testing.T) {
	for _, name := range []string{"SSH_CONNECTION", "SSH_CLIENT"} {
		t.Run(name, func(t *testing.T) {
			startTestAgent(t)
			prompts, _ := softwareTouchID(t)
			dbPath := createVaultWithTouchID(t)
			t.Setenv(name, "203.0.113.7 52114 192.0.2.1 22")

			restore := testutil.RedirectStderr(t)
			oracle, err := buildKeySourceWith(dbPath, interactivePrompt(t, "first-password-1234"))
			out := restore()
			if err != nil {
				t.Fatalf("password over SSH: %v", err)
			}
			closeKeySource(t, oracle)
			if *prompts != 0 {
				t.Errorf("a command over SSH asked for Touch ID %d time(s)", *prompts)
			}
			if want := "isn't used over SSH"; !strings.Contains(out, want) {
				t.Errorf("stderr = %q, want %q", out, want)
			}
			if _, err := touchid.ReadFile(filepath.Dir(dbPath)); err != nil {
				t.Errorf("touchid.key gone after an SSH command: %v", err)
			}
		})
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
	touchIDBiometryState = func() ([]byte, error) { return []byte("enrolled fingerprints 2"), nil }
	if out, err := run("status"); err != nil || !strings.Contains(out, "your fingerprints changed") {
		t.Errorf("status after a fingerprint change = %q, %v", out, err)
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
	if _, err := run("frobnicate"); err == nil {
		t.Error("an unknown subcommand was accepted")
	}
}

func TestRunTouchID_Enable(t *testing.T) {
	startTestAgent(t)
	softwareTouchID(t)
	dbPath := filepath.Join(t.TempDir(), "passwords.db")
	oracle, err := buildKeySourceWith(dbPath, withAnswer(interactivePrompt(t, "first-password-1234", "first-password-1234"), false))
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
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"password/x/y": "v"})
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
	if string(f.BiometryState) != "enrolled fingerprints 1" {
		t.Errorf("biometry state after rotation = %q, want it kept", f.BiometryState)
	}
	// The agent was locked by the rotation; a fingerprint now opens the
	// rotated vault, with no password.
	oracle, err := buildKeySourceWith(env.dbPath, interactivePrompt(t))
	if err != nil {
		t.Fatalf("Touch ID unlock after rotation: %v", err)
	}
	closeKeySource(t, oracle)
	if *prompts != 1 {
		t.Errorf("Touch ID prompts = %d, want 1", *prompts)
	}
}

func TestAskYes(t *testing.T) {
	for input, want := range map[string]bool{
		"\n":    true, // Enter takes the default
		"y\n":   true,
		"Yes\n": true,
		"n\n":   false,
		"no\n":  false,
		"":      false, // Ctrl-D: end of input is not an answer
		"y":     true,  // an answer cut short by end of input still counts
	} {
		got, err := askYes(strings.NewReader(input), io.Discard, "? ")
		if err != nil || got != want {
			t.Errorf("askYes(%q) = %v, %v; want %v", input, got, err, want)
		}
	}
}
