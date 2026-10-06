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
	"github.com/bashhack/sesh/internal/recovery"
	"github.com/bashhack/sesh/internal/testutil"
	"github.com/bashhack/sesh/internal/vault"
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
	oracle, err := buildKeySourceWith(dbPath, cfg)
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
}

func TestRotate_RewrapsRecoveryKey(t *testing.T) {
	env := setupRekeyEnv(t)
	startTestAgent(t)
	t.Setenv("SESH_MASTER_PASSWORD", "old-pw-1234")
	populatePasswordStore(t, env, map[string]string{"password/x/y": "v"})
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
	saved, err := makeRecoveryKey(agentWrap(conn), env.dataDir, mat.Verify, withLines(interactivePrompt(t), last))
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

// Answers that arrive together (pasted, or typed ahead) each reach the
// question they were meant for: a prompt reads only its own line.
func TestPrompts_ReadOneLineEach(t *testing.T) {
	in := strings.NewReader("y\nyes\nVP5H\n")
	var w bytes.Buffer
	if ok, err := promptYesNo(in, &w, "Proceed? "); err != nil || !ok {
		t.Fatalf("promptYesNo = %v, %v", ok, err)
	}
	if ok, err := askYes(in, &w, "Offer? "); err != nil || !ok {
		t.Fatalf("askYes = %v, %v", ok, err)
	}
	if got, err := readLine(in, &w, "Last group: "); err != nil || got != "VP5H" {
		t.Fatalf("readLine = %q, %v; want the third answer", got, err)
	}
}

// recoverableVault makes a password-protected vault holding one entry, with
// a recovery key, and returns its environment and key.
func recoverableVault(t *testing.T) (*rekeyTestEnv, recovery.Key) {
	t.Helper()
	env := setupRekeyEnv(t)
	startTestAgent(t)
	useConfigFile(t, "")
	t.Setenv("SESH_MASTER_PASSWORD", "forgotten-pw-1234")
	populatePasswordStore(t, env, map[string]string{"password/x/y": "the secret"})
	t.Setenv("SESH_MASTER_PASSWORD", "")
	conn, err := agent.DialExisting()
	if err != nil {
		t.Fatal(err)
	}
	defer closeAgentConn(conn)
	mat, err := database.ReadUnlockMaterial(env.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Unlock(conn, []byte("forgotten-pw-1234"), mat.Salt, mat.Verify, mat.Params); err != nil {
		t.Fatal(err)
	}
	k, last := fixedRecoveryKey(t)
	restore := testutil.RedirectStderr(t)
	saved, err := makeRecoveryKey(agentWrap(conn), env.dataDir, mat.Verify, withLines(interactivePrompt(t), last))
	restore()
	if err != nil || !saved {
		t.Fatalf("makeRecoveryKey = %v, %v", saved, err)
	}
	if err := agent.Lock(conn); err != nil {
		t.Fatal(err)
	}
	return env, k
}

// passwordOpens reports whether password opens the vault in dataDir.
func passwordOpens(t *testing.T, dataDir, password string) bool {
	t.Helper()
	mat, err := database.ReadUnlockMaterial(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	key := database.DeriveKey([]byte(password), mat.Salt, mat.Params)
	opened, err := database.Decrypt(key, mat.Verify)
	return err == nil && string(opened) == database.VerifyPlaintext
}

// runRecoverWith runs sesh recover with typed secrets (the recovery key,
// then passwords), answers to [Y/n] questions, and lines.
func runRecoverWith(t *testing.T, secrets []string, offerNew bool, lines ...string) (string, error) {
	t.Helper()
	orig := recoveryPrompt
	recoveryPrompt = func() passwordPromptConfig {
		return withLines(withAnswer(interactivePrompt(t, secrets...), offerNew), lines...)
	}
	t.Cleanup(func() { recoveryPrompt = orig })
	app, stderr := rekeyTestApp("y\n") // the rotation's "Proceed?"
	restore := testutil.RedirectStderr(t)
	err := runRecover(app, nil)
	notes := restore()
	return stderr.String() + notes, err
}

func TestRecover_SetsANewPasswordAndReplacesTheKey(t *testing.T) {
	env, used := recoverableVault(t)
	next, last := fixedRecoveryKey(t)
	out, err := runRecoverWith(t, []string{strings.ToLower(used.String()), "new-pw-5678", "new-pw-5678"}, true, last)
	if err != nil {
		t.Fatalf("recover: %v\n%s", err, out)
	}
	for _, want := range []string{
		"The recovery key opens this vault. Choose a new master password.",
		"Rotated 1 entry under a new master password.",
		"Your recovery key has been used, so it no longer works.",
		"Your recovery key:\n\n    " + next.String(),
		"The recovery key is set for this vault.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if !passwordOpens(t, env.dataDir, "new-pw-5678") || passwordOpens(t, env.dataDir, "forgotten-pw-1234") {
		t.Error("the vault doesn't open with the new password only")
	}
	opensVault(t, next, env.dataDir)
	f, err := recovery.ReadFile(env.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := used.Unwrap(f.Wrapped(), []byte(f.UnlockID)); !errors.Is(err, recovery.ErrWrongKey) {
		t.Errorf("the used key still opens the recovery file (err %v)", err)
	}
	t.Setenv("SESH_MASTER_PASSWORD", "new-pw-5678")
	store, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	defer closeAuditStore(store)
	if got, err := store.Get(vault.Key{Kind: vault.KindPassword, Service: "x", Username: "y"}); err != nil || string(got) != "the secret" {
		t.Errorf("entry after recovery = %q, %v", got, err)
	}
}

func TestRecover_TypoThenTheKey(t *testing.T) {
	env, used := recoverableVault(t)
	s := used.String()
	typo := "Z" + s[1:]
	out, err := runRecoverWith(t, []string{typo, s, "new-pw-5678", "new-pw-5678"}, false)
	if err != nil {
		t.Fatalf("recover: %v\n%s", err, out)
	}
	if !strings.Contains(out, "that's not a valid recovery key: a character is wrong") {
		t.Errorf("no typo message:\n%s", out)
	}
	if !passwordOpens(t, env.dataDir, "new-pw-5678") {
		t.Error("the new password doesn't open the vault")
	}
	// Declining a new key leaves the vault without one.
	if _, err := recovery.ReadFile(env.dataDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a recovery file exists after declining a new key (err %v)", err)
	}
	if !strings.Contains(out, "This vault has no recovery key now; make one any time with: sesh recovery new") {
		t.Errorf("no note about the missing key:\n%s", out)
	}
}

func TestRecover_Refuses(t *testing.T) {
	t.Run("another vault's key", func(t *testing.T) {
		env, _ := recoverableVault(t)
		other, err := recovery.New()
		if err != nil {
			t.Fatal(err)
		}
		o := other.String()
		_, err = runRecoverWith(t, []string{o, o, o}, false)
		if err == nil || !strings.Contains(err.Error(), "that recovery key doesn't open this vault") {
			t.Errorf("err = %v", err)
		}
		if !passwordOpens(t, env.dataDir, "forgotten-pw-1234") {
			t.Error("the vault changed although recovery failed")
		}
	})
	t.Run("cancelled at the confirmation", func(t *testing.T) {
		env, used := recoverableVault(t)
		orig := recoveryPrompt
		recoveryPrompt = func() passwordPromptConfig { return withAnswer(interactivePrompt(t, used.String()), true) }
		t.Cleanup(func() { recoveryPrompt = orig })
		app, stderr := rekeyTestApp("n\n")
		restore := testutil.RedirectStderr(t)
		err := runRecover(app, nil)
		restore()
		if err != nil || !strings.Contains(stderr.String(), "Rotation cancelled.") {
			t.Errorf("err = %v, stderr:\n%s", err, stderr)
		}
		if !passwordOpens(t, env.dataDir, "forgotten-pw-1234") {
			t.Error("the vault changed although the rotation was cancelled")
		}
		opensVault(t, used, env.dataDir)
	})
	t.Run("no recovery key", func(t *testing.T) {
		env, _ := recoverableVault(t)
		if err := recovery.Remove(env.dataDir); err != nil {
			t.Fatal(err)
		}
		_, err := runRecoverWith(t, nil, false)
		if err == nil || !strings.Contains(err.Error(), "this vault has no recovery key") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("no terminal", func(t *testing.T) {
		recoverableVault(t)
		orig := recoveryPrompt
		recoveryPrompt = func() passwordPromptConfig { return passwordPromptConfig{} }
		t.Cleanup(func() { recoveryPrompt = orig })
		if err := runRecover(agentTestApp(), nil); err == nil || !strings.Contains(err.Error(), "sesh recover needs a terminal") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("arguments", func(t *testing.T) {
		if err := runRecover(agentTestApp(), []string{"now"}); err == nil || !strings.Contains(err.Error(), "sesh recover takes no arguments") {
			t.Errorf("err = %v", err)
		}
	})
}

// stderrFailsAt fails every write once one contains marker.
type stderrFailsAt struct {
	marker string
	failed bool
}

func (w *stderrFailsAt) Write(p []byte) (int, error) {
	if w.failed || strings.Contains(string(p), w.marker) {
		w.failed = true
		return 0, errors.New("stderr closed")
	}
	return len(p), nil
}

// If the change commits but its summary can't be written, the used recovery
// key is still retired: the error is reported, and its file is gone.
func TestRecover_RetiresTheKeyEvenIfReportingFails(t *testing.T) {
	env, used := recoverableVault(t)
	orig := recoveryPrompt
	recoveryPrompt = func() passwordPromptConfig {
		return withAnswer(interactivePrompt(t, used.String(), "new-pw-5678", "new-pw-5678"), false)
	}
	t.Cleanup(func() { recoveryPrompt = orig })
	app, _ := rekeyTestApp("y\n")
	app.Stderr = &stderrFailsAt{marker: "Rotated"}
	restore := testutil.RedirectStderr(t)
	err := runRecover(app, nil)
	restore()
	if err == nil {
		t.Fatal("expected the write failure to be reported")
	}
	if !passwordOpens(t, env.dataDir, "new-pw-5678") {
		t.Fatal("the change didn't commit; this test needs it to")
	}
	if _, err := recovery.ReadFile(env.dataDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the used recovery key's file is still there (err %v)", err)
	}
}
