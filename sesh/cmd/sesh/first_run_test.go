package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/agent"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/keywrap"
	"github.com/bashhack/sesh/internal/recovery"
	"github.com/bashhack/sesh/internal/testutil"
)

// interactivePrompt answers prompts with passwords in order, as a person at
// a terminal would, and fails the test if asked once more than that.
func interactivePrompt(t *testing.T, passwords ...string) passwordPromptConfig {
	t.Helper()
	i := 0
	return passwordPromptConfig{
		interactive: true,
		prompt: func(p string) ([]byte, error) {
			if i >= len(passwords) {
				t.Errorf("unexpected prompt %q", p)
				return nil, errors.New("no more passwords")
			}
			i++
			return []byte(passwords[i-1]), nil
		},
	}
}

func TestPlainSeshPrintsGettingStarted(t *testing.T) {
	h := newTestHarness()
	exited := false
	h.app.Exit = func(int) { exited = true }
	run(h.app, []string{"sesh"})
	if exited {
		t.Error("plain sesh exited with an error")
	}
	out := h.stdout.String()
	for _, want := range []string{"sesh keeps your TOTP secrets and passwords in an encrypted vault.", "Get started:", "sesh -service totp -setup", "Available service providers:"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestOptionsWithoutAServiceStillFail(t *testing.T) {
	h := newTestHarness()
	exited := false
	h.app.Exit = func(int) { exited = true }
	run(h.app, []string{"sesh", "-list"})
	if !exited || !strings.Contains(h.stderr.String(), "no service provider specified") {
		t.Errorf("exited = %v, stderr = %q; want the no-provider error", exited, h.stderr.String())
	}
}

func TestFirstRun_ExplainsThenUnlocksTheAgent(t *testing.T) {
	startTestAgent(t)
	dbPath := filepath.Join(t.TempDir(), "passwords.db")

	restore := testutil.RedirectStderr(t)
	oracle, err := buildKeySourceWith(dbPath, "password", interactivePrompt(t, "new-password-1234", "new-password-1234"))
	stderr := restore()
	if err != nil {
		t.Fatalf("creating the vault: %v", err)
	}
	closeKeySource(t, oracle)
	for _, want := range []string{"Creating your sesh vault (first run)", "Location: " + dbPath, "if you forget it, only a recovery key opens the vault\n  (sesh recovery new)"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr)
		}
	}

	// The agent got the new password: the next command asks for nothing.
	mat, err := database.ReadUnlockMaterial(filepath.Dir(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := agent.DialExisting()
	if err != nil {
		t.Fatal(err)
	}
	st, err := agent.Status(conn)
	closeAgentConn(conn)
	if err != nil || !st.Unlocked || st.UnlockID != agent.UnlockID(mat.Verify) {
		t.Fatalf("agent status = %+v, %v; want unlocked for the new vault", st, err)
	}
	next, err := buildKeySourceWith(dbPath, "password", interactivePrompt(t))
	if err != nil {
		t.Fatalf("second command: %v", err)
	}
	closeKeySource(t, next)
}

func TestFirstRun_FromEnvIsQuietAndSkipsTheAgent(t *testing.T) {
	t.Setenv("SESH_AUTH_SOCK", tempAgentSocket(t))
	t.Setenv("SESH_MASTER_PASSWORD", "scripted-password-1234")
	dbPath := filepath.Join(t.TempDir(), "passwords.db")

	restore := testutil.RedirectStderr(t)
	oracle, err := buildKeySource(dbPath, "password")
	stderr := restore()
	if err != nil {
		t.Fatal(err)
	}
	closeKeySource(t, oracle)
	if strings.Contains(stderr, "Creating your sesh vault") {
		t.Errorf("scripted run printed the first-run notice:\n%s", stderr)
	}
	if _, err := agent.DialExisting(); !agent.IsNotRunning(err) {
		t.Errorf("scripted run started an agent (dial err %v)", err)
	}
}

func TestForgottenPasswordHint(t *testing.T) {
	dir := t.TempDir()
	writeLightSidecar(t, dir, "correct-horse")
	dbPath := filepath.Join(dir, "passwords.db")

	t.Run("interactive", func(t *testing.T) {
		startTestAgent(t)
		_, err := buildKeySourceWith(dbPath, "password", interactivePrompt(t, "a-wrong-one", "b-wrong-one", "c-wrong-one"))
		if err == nil || !strings.Contains(err.Error(), "wrong master password (after 3 attempts).\n   If you've forgotten it") {
			t.Fatalf("err = %v, want the hint", err)
		}
		if strings.Contains(err.Error(), "sesh recover") {
			t.Errorf("hint offers sesh recover without a recovery key: %v", err)
		}
	})
	t.Run("interactive, with a recovery key", func(t *testing.T) {
		startTestAgent(t)
		if err := recovery.NewFile("id", []byte("p"), keywrap.Wrapped{EphemeralPub: []byte("e"), Ciphertext: []byte("c")}).Write(dir); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := recovery.Remove(dir); err != nil {
				t.Error(err)
			}
		})
		_, err := buildKeySourceWith(dbPath, "password", interactivePrompt(t, "a-wrong-one", "b-wrong-one", "c-wrong-one"))
		if err == nil || !strings.Contains(err.Error(), "If you've forgotten it, set a new one with your recovery key: sesh recover") {
			t.Fatalf("err = %v, want the recovery hint", err)
		}
	})
	t.Run("scripted", func(t *testing.T) {
		t.Setenv("SESH_AUTH_SOCK", tempAgentSocket(t))
		t.Setenv("SESH_MASTER_PASSWORD", "a-wrong-one")
		_, err := buildKeySource(dbPath, "password")
		if err == nil || strings.Contains(err.Error(), "forgotten") || !errors.Is(err, database.ErrWrongPassword) {
			t.Fatalf("err = %v, want the plain wrong-password error", err)
		}
	})
}
