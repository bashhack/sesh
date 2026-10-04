package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/agent"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/keywrap"
	"github.com/bashhack/sesh/internal/recovery"
	"github.com/bashhack/sesh/internal/testutil"
)

// fixedRecoveryKey makes newRecoveryKey return one known key, and returns
// it with its last group.
func fixedRecoveryKey(t *testing.T) (recovery.Key, string) {
	t.Helper()
	k, err := recovery.New()
	if err != nil {
		t.Fatal(err)
	}
	orig := newRecoveryKey
	newRecoveryKey = func() (recovery.Key, error) { return k, nil }
	t.Cleanup(func() { newRecoveryKey = orig })
	s := k.String()
	return k, s[len(s)-4:]
}

// noTouchIDOffer keeps the Touch ID offer out of a first run.
func noTouchIDOffer(t *testing.T) {
	t.Helper()
	orig := touchIDAvailable
	touchIDAvailable = func() bool { return false }
	t.Cleanup(func() { touchIDAvailable = orig })
}

// withLines answers readLine with lines in order, then end of input.
func withLines(cfg passwordPromptConfig, lines ...string) passwordPromptConfig {
	i := 0
	cfg.readLine = func(string) (string, error) {
		if i >= len(lines) {
			return "", io.EOF
		}
		i++
		return lines[i-1], nil
	}
	return cfg
}

// opensVault fails the test unless k unwraps the recovery file in dataDir
// to the vault's key.
func opensVault(t *testing.T, k recovery.Key, dataDir string) {
	t.Helper()
	f, err := recovery.ReadFile(dataDir)
	if err != nil {
		t.Fatalf("recovery file: %v", err)
	}
	mat, err := database.ReadUnlockMaterial(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if f.UnlockID != agent.UnlockID(mat.Verify) {
		t.Fatal("the recovery file is bound to another vault")
	}
	key, err := k.Unwrap(f.Wrapped(), []byte(f.UnlockID))
	if err != nil {
		t.Fatalf("the recovery key doesn't open its file: %v", err)
	}
	if opened, err := database.Decrypt(key, mat.Verify); err != nil || string(opened) != database.VerifyPlaintext {
		t.Fatalf("the unwrapped key doesn't open the vault: %q, %v", opened, err)
	}
}

// createVaultOfferingRecovery creates a vault at a terminal, answering the
// recovery offer with yes and then typing lines. It returns the vault path
// and stderr.
func createVaultOfferingRecovery(t *testing.T, offer bool, lines ...string) (string, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "passwords.db")
	cfg := withLines(withAnswer(interactivePrompt(t, "first-password-1234", "first-password-1234"), offer), lines...)
	restore := testutil.RedirectStderr(t)
	oracle, err := buildKeySourceWith(dbPath, "password", cfg)
	out := restore()
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	closeKeySource(t, oracle)
	return dbPath, out
}

func TestRecovery_OfferedAtFirstRun(t *testing.T) {
	startTestAgent(t)
	noTouchIDOffer(t)
	k, last := fixedRecoveryKey(t)
	dbPath, out := createVaultOfferingRecovery(t, true, strings.ToLower(last))
	for _, want := range []string{"Your recovery key:\n\n    " + k.String() + "\n", "sesh doesn't keep a copy", "The recovery key is set for this vault."} {
		if !strings.Contains(out, want) {
			t.Errorf("stderr missing %q:\n%s", want, out)
		}
	}
	opensVault(t, k, filepath.Dir(dbPath))
}

func TestRecovery_NotSavedUnlessConfirmed(t *testing.T) {
	for name, lines := range map[string][]string{
		"three wrong tries": {"AAAA", "BBBB", "CCCC"},
		"end of input":      nil,
	} {
		t.Run(name, func(t *testing.T) {
			startTestAgent(t)
			noTouchIDOffer(t)
			fixedRecoveryKey(t)
			dbPath, out := createVaultOfferingRecovery(t, true, lines...)
			if _, err := recovery.ReadFile(filepath.Dir(dbPath)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("recovery file written without confirmation (err %v)", err)
			}
			if !strings.Contains(out, "No recovery key was set, since it wasn't confirmed. Make one when you're ready with: sesh recovery new") {
				t.Errorf("stderr:\n%s", out)
			}
		})
	}
}

func TestRecovery_OfferDeclined(t *testing.T) {
	startTestAgent(t)
	noTouchIDOffer(t)
	k, _ := fixedRecoveryKey(t)
	dbPath, out := createVaultOfferingRecovery(t, false)
	if strings.Contains(out, k.String()) {
		t.Error("the key was shown although the offer was declined")
	}
	if _, err := recovery.ReadFile(filepath.Dir(dbPath)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("recovery file exists after declining (err %v)", err)
	}
}

func TestRunRecovery_NewStatusRemove(t *testing.T) {
	startTestAgent(t)
	noTouchIDOffer(t)
	dbPath, _ := createVaultOfferingRecovery(t, false)
	dataDir := filepath.Dir(dbPath)
	useConfigFile(t, "db_path = \""+dbPath+"\"\n")
	answers := []string{}
	orig := recoveryPrompt
	recoveryPrompt = func() passwordPromptConfig {
		return withLines(withAnswer(interactivePrompt(t), true), answers...)
	}
	t.Cleanup(func() { recoveryPrompt = orig })
	run := func(args ...string) (string, error) {
		app := agentTestApp()
		restore := testutil.RedirectStderr(t)
		err := runRecovery(app, args)
		restore()
		return app.Stdout.(*bytes.Buffer).String(), err
	}

	if out, err := run("status"); err != nil || out != "Recovery key: none. Make one with: sesh recovery new\n" {
		t.Errorf("status before = %q, %v", out, err)
	}
	first, last := fixedRecoveryKey(t)
	answers = []string{last}
	if _, err := run("new"); err != nil {
		t.Fatalf("new: %v", err)
	}
	opensVault(t, first, dataDir)
	if out, err := run("status"); err != nil || !strings.HasPrefix(out, "Recovery key: set (made ") {
		t.Errorf("status after new = %q, %v", out, err)
	}

	// A second key replaces the first, which then opens nothing.
	second, last := fixedRecoveryKey(t)
	answers = []string{last}
	if _, err := run("new"); err != nil {
		t.Fatalf("second new: %v", err)
	}
	opensVault(t, second, dataDir)
	f, err := recovery.ReadFile(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Unwrap(f.Wrapped(), []byte(f.UnlockID)); !errors.Is(err, recovery.ErrWrongKey) {
		t.Errorf("the replaced key still opens the file (err %v)", err)
	}

	if out, err := run("remove"); err != nil || out != "Removed the recovery key; it no longer opens this vault.\n" {
		t.Errorf("remove = %q, %v", out, err)
	}
	if out, err := run("remove"); err != nil || out != "This vault has no recovery key.\n" {
		t.Errorf("remove again = %q, %v", out, err)
	}

	recoveryPrompt = func() passwordPromptConfig { return passwordPromptConfig{} } // no terminal
	if _, err := run("new"); err == nil || !strings.Contains(err.Error(), "sesh recovery new needs a terminal") {
		t.Errorf("new without a terminal: err = %v", err)
	}
	if _, err := run("frobnicate"); err == nil || !strings.Contains(err.Error(), `unknown recovery command "frobnicate"`) {
		t.Errorf("unknown command: err = %v", err)
	}
	useConfigFile(t, "key_source = \"keychain\"\n")
	if out, err := run("status"); err != nil || !strings.Contains(out, "not used") {
		t.Errorf("status with the keychain key source = %q, %v", out, err)
	}
}

func TestRotate_RewrapsRecoveryKey(t *testing.T) {
	env := setupRekeyEnv(t)
	startTestAgent(t)
	t.Setenv("SESH_KEY_SOURCE", "password")
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"sesh-password/password/x/y": "v"})
	t.Setenv("SESH_MASTER_PASSWORD", "")
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
	k, last := fixedRecoveryKey(t)
	restore := testutil.RedirectStderr(t)
	saved, err := makeRecoveryKey(conn, env.dataDir, mat.Verify, withLines(interactivePrompt(t), last))
	restore()
	closeAgentConn(conn)
	if err != nil || !saved {
		t.Fatalf("makeRecoveryKey = %v, %v", saved, err)
	}
	before, err := recovery.ReadFile(env.dataDir)
	if err != nil {
		t.Fatal(err)
	}

	app, stderr := rekeyTestApp("y\n")
	if err := runRotateMasterPassword(app, rotateTestCfg("old-pw-1234", "new-pw-5678", "new-pw-5678")); err != nil {
		t.Fatalf("rotate: %v\n%s", err, stderr)
	}
	if !strings.Contains(stderr.String(), "Your recovery key still works: it now opens the vault with the new master password.") {
		t.Errorf("stderr missing the re-wrap note:\n%s", stderr.String())
	}
	opensVault(t, k, env.dataDir)
	after, err := recovery.ReadFile(env.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if !after.CreatedAt.Equal(before.CreatedAt) {
		t.Errorf("CreatedAt changed from %v to %v; it's the same key", before.CreatedAt, after.CreatedAt)
	}
}

func TestRekey_ToKeychainRemovesRecoveryKey(t *testing.T) {
	env := setupRekeyEnv(t)
	t.Setenv("SESH_KEY_SOURCE", "password")
	t.Setenv("SESH_MASTER_PASSWORD", "old-master-password-1234")
	populatePasswordStore(t, env, map[string]string{"sesh-password/password/x/y": "v"})
	if err := recovery.NewFile("id", []byte("p"), keywrap.Wrapped{EphemeralPub: []byte("e"), Ciphertext: []byte("c")}).Write(env.dataDir); err != nil {
		t.Fatal(err)
	}
	app, stderr := rekeyTestApp("y\n")
	if err := runRekey(app, []string{"--to=keychain"}, newKCMock(nil)); err != nil {
		t.Fatalf("rekey: %v\n%s", err, stderr)
	}
	if _, err := recovery.ReadFile(env.dataDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("recovery.key still exists after switching to the Keychain key (err %v)", err)
	}
	if !strings.Contains(stderr.String(), "Removed the recovery key: it only opens a vault protected by a master password.") {
		t.Errorf("stderr missing the note:\n%s", stderr)
	}
}

func TestSameGroup(t *testing.T) {
	for typed, want := range map[string]bool{"VP5H": true, "vp5h": true, " VP5H\n": true, "VP5I": false, "VP5": false} {
		if got := sameGroup(typed, "VP5H"); got != want {
			t.Errorf("sameGroup(%q) = %v, want %v", typed, got, want)
		}
	}
	if !sameGroup("1o0l", "1001") {
		t.Error("handwriting look-alikes (o for 0, l for 1) not accepted")
	}
}
