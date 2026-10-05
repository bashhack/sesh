package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/agent"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/secure"
)

func closeKeySource(t *testing.T, ks database.CryptoOracle) {
	t.Helper()
	c, ok := ks.(interface{ Close() })
	if !ok {
		t.Fatalf("%T has no Close", ks)
	}
	c.Close()
}

func writeLightSidecar(t *testing.T, dir, password string) {
	t.Helper()
	params := database.Argon2idParams{Time: 1, Memory: 8, Threads: 1, KeyLen: 32}
	salt := []byte("0123456789abcdef")
	key := database.DeriveKey([]byte(password), salt, params)
	t.Cleanup(func() { secure.SecureZeroBytes(key) })
	verify, err := database.Encrypt(key, []byte(database.VerifyPlaintext))
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.MarshalIndent(map[string]any{
		"version":   1,
		"salt":      base64.StdEncoding.EncodeToString(salt),
		"algorithm": "argon2id",
		"params":    params,
		"verify":    base64.StdEncoding.EncodeToString(verify),
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "passwords.key"), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func startTestAgent(t *testing.T) {
	t.Helper()
	sockPath := tempAgentSocket(t)
	srv, err := agent.Listen(sockPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		if err := srv.Run(ctx); err != nil {
			t.Errorf("agent Run: %v", err)
		}
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		if err := srv.Close(); err != nil {
			t.Errorf("close agent: %v", err)
		}
		<-done
	})
	t.Setenv("SESH_AUTH_SOCK", sockPath)
}

func TestKeySourceFromAgent_PromptsOnce(t *testing.T) {
	dir := t.TempDir()
	writeLightSidecar(t, dir, "correct-horse")
	startTestAgent(t)

	var prompts int
	cfg := passwordPromptConfig{
		prompt: func(string) ([]byte, error) {
			prompts++
			return []byte("correct-horse"), nil
		},
	}
	ks, _, err := keySourceFromAgent(dir, cfg)
	if err != nil || ks == nil {
		t.Fatalf("first keySourceFromAgent: %v", err)
	}
	closeKeySource(t, ks)
	if prompts != 1 {
		t.Fatalf("prompts = %d, want 1", prompts)
	}

	ks, _, err = keySourceFromAgent(dir, cfg)
	if err != nil || ks == nil {
		t.Fatalf("second keySourceFromAgent: %v", err)
	}
	closeKeySource(t, ks)
	if prompts != 1 {
		t.Fatalf("prompts after unlock = %d, want 1", prompts)
	}
}

func TestKeySourceFromAgent_WrongPasswordDoesNotFallBack(t *testing.T) {
	dir := t.TempDir()
	writeLightSidecar(t, dir, "correct-horse")
	startTestAgent(t)

	// A nil error would send buildKeySource to the direct source for a
	// second round of prompts; the agent's verdict has to stand.
	ks, _, err := keySourceFromAgent(dir, fixedPrompt("not-the-password"))
	if ks != nil {
		t.Fatal("keySourceFromAgent returned a source for a wrong password")
	}
	if err == nil || err.Error() != "wrong master password" {
		t.Fatalf("err = %v, want %q", err, "wrong master password")
	}
}

func TestKeySourceFromAgent_WrongPasswordMessageAfterRetries(t *testing.T) {
	dir := t.TempDir()
	writeLightSidecar(t, dir, "correct-horse")
	startTestAgent(t)

	cfg := fixedPrompt("not-the-password")
	cfg.interactive = true
	_, _, err := keySourceFromAgent(dir, cfg)
	want := fmt.Sprintf("wrong master password (after %d attempts)", interactivePasswordAttempts)
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}
}

func TestBuildKeySource_WrongPasswordFails(t *testing.T) {
	dir := t.TempDir()
	writeLightSidecar(t, dir, "correct-horse")
	startTestAgent(t)
	t.Setenv("SESH_KEY_SOURCE", "password")
	t.Setenv("SESH_MASTER_PASSWORD", "not-the-password")

	_, err := buildKeySource(filepath.Join(dir, "passwords.db"), "password")
	if err == nil || !strings.Contains(err.Error(), "wrong master password") {
		t.Fatalf("err = %v, want wrong master password", err)
	}
}

func fixedPrompt(pw string) passwordPromptConfig {
	return passwordPromptConfig{prompt: func(string) ([]byte, error) { return []byte(pw), nil }}
}

func TestKeySourceFromAgent_SpawnFailureFallsBack(t *testing.T) {
	dir := t.TempDir()
	writeLightSidecar(t, dir, "correct-horse")
	t.Setenv("SESH_AUTH_SOCK", tempAgentSocket(t))

	orig := agent.AgentSpawnCommand
	agent.AgentSpawnCommand = func(string) (*exec.Cmd, error) {
		return nil, errors.New("spawn disabled")
	}
	t.Cleanup(func() { agent.AgentSpawnCommand = orig })

	// nil source and nil error is what sends buildKeySource to the
	// direct master-password source.
	var ks database.CryptoOracle
	var err error
	stderr := withCapturedStderr(t, func() {
		ks, _, err = keySourceFromAgent(dir, fixedPrompt("correct-horse"))
	})
	if ks != nil || err != nil {
		t.Fatalf("keySourceFromAgent = (%v, %v), want (nil, nil)", ks, err)
	}
	if !strings.Contains(stderr, "sesh agent unavailable") {
		t.Fatalf("stderr = %q, want an agent-unavailable warning", stderr)
	}
}

func TestBuildKeySource_EnvPasswordBypassesAgent(t *testing.T) {
	dir := t.TempDir()
	writeLightSidecar(t, dir, "correct-horse")
	startTestAgent(t)
	// Unlock the agent for this vault, as an earlier interactive run would.
	ks, _, err := keySourceFromAgent(dir, fixedPrompt("correct-horse"))
	if err != nil || ks == nil {
		t.Fatalf("unlock agent: %v", err)
	}
	closeKeySource(t, ks)

	t.Setenv("SESH_KEY_SOURCE", "password")
	orig := agent.AgentSpawnCommand
	agent.AgentSpawnCommand = func(string) (*exec.Cmd, error) {
		t.Error("buildKeySource spawned an agent with SESH_MASTER_PASSWORD set")
		return nil, errors.New("spawn disabled")
	}
	t.Cleanup(func() { agent.AgentSpawnCommand = orig })

	// The unlocked agent must not let a wrong env password through.
	t.Setenv("SESH_MASTER_PASSWORD", "not-the-password")
	if _, err := buildKeySource(filepath.Join(dir, "passwords.db"), "password"); err == nil || !strings.Contains(err.Error(), "wrong master password") {
		t.Fatalf("wrong env password: err = %v, want wrong master password", err)
	}

	t.Setenv("SESH_MASTER_PASSWORD", "correct-horse")
	ks, err = buildKeySource(filepath.Join(dir, "passwords.db"), "password")
	if err != nil {
		t.Fatal(err)
	}
	defer closeKeySource(t, ks)
	if _, isAgent := ks.(*agent.Oracle); isAgent {
		t.Fatal("SESH_MASTER_PASSWORD run returned the agent source")
	}
}

func TestKeySourceFromAgent_RetriesWrongPassword(t *testing.T) {
	dir := t.TempDir()
	writeLightSidecar(t, dir, "correct-horse")
	startTestAgent(t)

	var prompts []string
	cfg := passwordPromptConfig{
		interactive: true,
		prompt: func(p string) ([]byte, error) {
			prompts = append(prompts, p)
			if len(prompts) < interactivePasswordAttempts {
				return []byte("nope"), nil
			}
			return []byte("correct-horse"), nil
		},
	}
	ks, _, err := keySourceFromAgent(dir, cfg)
	if err != nil || ks == nil {
		t.Fatalf("keySourceFromAgent: %v", err)
	}
	closeKeySource(t, ks)
	if len(prompts) != interactivePasswordAttempts {
		t.Fatalf("prompts = %d, want %d (%q)", len(prompts), interactivePasswordAttempts, prompts)
	}
	if prompts[0] != "Master password: " {
		t.Fatalf("first prompt = %q", prompts[0])
	}
	want := fmt.Sprintf("Wrong password, try again (2/%d). Master password: ", interactivePasswordAttempts)
	if prompts[1] != want {
		t.Fatalf("second prompt = %q, want %q", prompts[1], want)
	}
}

func TestKeySourceFromAgent_RePromptsWhenSidecarChanges(t *testing.T) {
	dir := t.TempDir()
	writeLightSidecar(t, dir, "password-a")
	startTestAgent(t)

	var prompts int
	cfg := passwordPromptConfig{
		prompt: func(string) ([]byte, error) {
			prompts++
			if prompts == 1 {
				return []byte("password-a"), nil
			}
			return []byte("password-b"), nil
		},
	}
	ks, _, err := keySourceFromAgent(dir, cfg)
	if err != nil || ks == nil {
		t.Fatalf("first keySourceFromAgent: %v", err)
	}
	closeKeySource(t, ks)
	if prompts != 1 {
		t.Fatalf("prompts = %d, want 1", prompts)
	}

	writeLightSidecar(t, dir, "password-b")
	ks, _, err = keySourceFromAgent(dir, cfg)
	if err != nil || ks == nil {
		t.Fatalf("keySourceFromAgent after rotation: %v", err)
	}
	closeKeySource(t, ks)
	if prompts != 2 {
		t.Fatalf("prompts after rotation = %d, want 2", prompts)
	}
}

func TestKeySourceFromAgent_EncryptUsesOriginalUnlockID(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	writeLightSidecar(t, dirA, "password-a")
	writeLightSidecar(t, dirB, "password-b")
	startTestAgent(t)

	passwords := []string{"password-a", "password-b"}
	var n int
	cfg := passwordPromptConfig{
		prompt: func(string) ([]byte, error) {
			pw := passwords[n]
			n++
			return []byte(pw), nil
		},
	}
	ksA, _, err := keySourceFromAgent(dirA, cfg)
	if err != nil || ksA == nil {
		t.Fatalf("vault A: %v", err)
	}
	defer closeKeySource(t, ksA)
	ksB, _, err := keySourceFromAgent(dirB, cfg)
	if err != nil || ksB == nil {
		t.Fatalf("vault B: %v", err)
	}
	defer closeKeySource(t, ksB)

	if _, _, err := ksA.EncryptEntry([]byte("secret"), nil); err == nil {
		t.Fatal("vault A sealed a secret under vault B's key")
	} else {
		var pe *agent.ProtocolError
		if !errors.As(err, &pe) || pe.Code != agent.ErrCodeUnlockMismatch {
			t.Fatalf("EncryptEntry err = %v, want unlock_mismatch", err)
		}
		if !strings.Contains(err.Error(), "unlocked for a different vault") || strings.Contains(err.Error(), agent.ErrCodeUnlockMismatch) {
			t.Fatalf("EncryptEntry err = %q, want the user-facing message without the protocol code", err)
		}
	}
	ct, salt, err := ksB.EncryptEntry([]byte("secret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ksB.DecryptEntry(ct, salt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret" {
		t.Fatalf("plaintext = %q", got)
	}
}

func TestKeySourceFromAgent_MissingSidecarIsSilent(t *testing.T) {
	dir := t.TempDir()
	sock := tempAgentSocket(t)
	t.Setenv("SESH_AUTH_SOCK", sock)
	orig := agent.AgentSpawnCommand
	agent.AgentSpawnCommand = func(string) (*exec.Cmd, error) {
		t.Error("started an agent for a data directory with no sidecar")
		return nil, errors.New("spawn disabled")
	}
	t.Cleanup(func() { agent.AgentSpawnCommand = orig })

	var ks database.CryptoOracle
	var err error
	stderr := withCapturedStderr(t, func() {
		ks, _, err = keySourceFromAgent(dir, passwordPromptConfig{
			prompt: func(string) ([]byte, error) {
				t.Error("prompted without a sidecar")
				return nil, errors.New("prompted")
			},
		})
	})
	if err != nil || ks != nil {
		t.Fatalf("keySourceFromAgent = (%v, %v), want fallback", ks, err)
	}
	if strings.Contains(stderr, "sesh agent") {
		t.Fatalf("stderr = %q, want no agent warning", stderr)
	}
}

func withCapturedStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	fn()
	os.Stderr = orig
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestKeySourceFromAgent_UnlockFailureReusesTypedPassword(t *testing.T) {
	dir := t.TempDir()
	writeLightSidecar(t, dir, "correct-horse")
	startFailingUnlockAgent(t)

	prompts := 0
	cfg := passwordPromptConfig{prompt: func(string) ([]byte, error) {
		prompts++
		return []byte("correct-horse"), nil
	}}
	var oracle database.CryptoOracle
	var typed []byte
	var err error
	stderr := withCapturedStderr(t, func() {
		oracle, typed, err = keySourceFromAgent(dir, cfg)
	})
	if oracle != nil || err != nil {
		t.Fatalf("keySourceFromAgent = (%v, %v), want fallback", oracle, err)
	}
	if string(typed) != "correct-horse" {
		t.Fatalf("typed = %q, want the password the user entered", typed)
	}
	if !strings.Contains(stderr, "sesh agent unlock failed") {
		t.Fatalf("stderr = %q, want an unlock-failed warning", stderr)
	}

	// The fallback source must use the typed password, not ask again.
	mps := cfg.withTypedPassword(typed).newSource(dir)
	defer mps.Close()
	key, err := mps.GetEncryptionKey()
	if err != nil {
		t.Fatalf("fallback unlock: %v", err)
	}
	secure.SecureZeroBytes(key)
	if prompts != 1 {
		t.Fatalf("prompts = %d, want 1", prompts)
	}
}

// startFailingUnlockAgent serves one client that completes hello and
// status normally and answers unlock with internal_error.
func startFailingUnlockAgent(t *testing.T) {
	t.Helper()
	sock := tempAgentSocket(t)
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := lis.Close(); err != nil {
			t.Errorf("close fake agent: %v", err)
		}
	})
	send := func(c net.Conn, v any) {
		b, err := json.Marshal(v)
		if err != nil {
			t.Error(err)
			return
		}
		if _, err := c.Write(append(b, '\n')); err != nil {
			t.Logf("fake agent write: %v", err)
		}
	}
	go func() {
		c, err := lis.Accept()
		if err != nil {
			return
		}
		defer c.Close() //nolint:errcheck // fake agent teardown
		r := bufio.NewReader(c)
		for {
			line, err := r.ReadBytes('\n')
			if err != nil {
				return
			}
			var env struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(line, &env); err != nil {
				return
			}
			switch env.Type {
			case agent.TypeHello:
				send(c, agent.HelloResponse{Type: agent.TypeHelloAck, Version: agent.ProtocolVersion, AgentBuild: agent.Build()})
			case agent.TypeStatus:
				send(c, agent.StatusResponse{Type: agent.TypeStatusAck, Version: agent.ProtocolVersion})
			default:
				send(c, agent.ErrorResponse{Type: agent.TypeError, Version: agent.ProtocolVersion, Code: agent.ErrCodeInternal, Message: "boom"})
			}
		}
	}()
	t.Setenv("SESH_AUTH_SOCK", sock)
}

type closeRecorder struct {
	database.CryptoOracle
	closed bool
}

func (c *closeRecorder) Close() { c.closed = true }

func TestOpenStoreWith_ClosesOracleWhenOpenFails(t *testing.T) {
	oracle := &closeRecorder{}
	dbPath := filepath.Join(t.TempDir(), "missing-dir", "passwords.db")
	if _, err := openStoreWith(dbPath, oracle, "password"); err == nil {
		t.Fatal("openStoreWith succeeded in a missing directory")
	}
	if !oracle.closed {
		t.Fatal("oracle was not closed after database.Open failed")
	}
}
