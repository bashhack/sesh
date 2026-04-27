package database

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/bashhack/sesh/internal/secure"
)

func staticPrompt(passwords ...string) PasswordPromptFunc {
	i := 0
	return func(_ string) ([]byte, error) {
		if i >= len(passwords) {
			return nil, errors.New("no more passwords")
		}
		pw := []byte(passwords[i])
		i++
		return pw, nil
	}
}

func TestMasterPasswordSource_FirstRunCreatesSidecar(t *testing.T) {
	dir := t.TempDir()
	src := NewMasterPasswordSource(dir, staticPrompt("correct-horse-battery-staple", "correct-horse-battery-staple"))

	key, err := src.GetEncryptionKey()
	if err != nil {
		t.Fatalf("GetEncryptionKey: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key))
	}

	if _, err := os.Stat(filepath.Join(dir, sidecarFileName)); err != nil {
		t.Fatalf("sidecar should exist after first run: %v", err)
	}
}

func TestMasterPasswordSource_SidecarPermissions(t *testing.T) {
	dir := t.TempDir()
	src := NewMasterPasswordSource(dir, staticPrompt("hunter2-password-secure", "hunter2-password-secure"))

	if _, err := src.GetEncryptionKey(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(dir, sidecarFileName))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("sidecar permissions should be 0600, got %o", perm)
	}
}

func TestMasterPasswordSource_SecondRunReturnsSameKey(t *testing.T) {
	dir := t.TempDir()
	password := "my-master-password"

	src1 := NewMasterPasswordSource(dir, staticPrompt(password, password))
	key1, err := src1.GetEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}

	src2 := NewMasterPasswordSource(dir, staticPrompt(password))
	key2, err := src2.GetEncryptionKey()
	if err != nil {
		t.Fatalf("second unlock: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Fatal("same password should yield same key across runs")
	}
}

func TestMasterPasswordSource_WrongPasswordRejected(t *testing.T) {
	dir := t.TempDir()

	src1 := NewMasterPasswordSource(dir, staticPrompt("original", "original"))
	if _, err := src1.GetEncryptionKey(); err != nil {
		t.Fatal(err)
	}

	src2 := NewMasterPasswordSource(dir, staticPrompt("wrong-password"))
	_, err := src2.GetEncryptionKey()
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestMasterPasswordSource_MismatchedConfirmation(t *testing.T) {
	dir := t.TempDir()
	src := NewMasterPasswordSource(dir, staticPrompt("first-password", "different-password"))

	_, err := src.GetEncryptionKey()
	if err == nil {
		t.Fatal("expected error for mismatched confirmation")
	}

	if _, err := os.Stat(filepath.Join(dir, sidecarFileName)); !os.IsNotExist(err) {
		t.Fatal("sidecar should not be created when confirmation fails")
	}
}

func TestMasterPasswordSource_RejectsTooShortPassword(t *testing.T) {
	dir := t.TempDir()
	src := NewMasterPasswordSource(dir, staticPrompt("short", "short"))

	_, err := src.GetEncryptionKey()
	if err == nil {
		t.Fatal("expected error for too-short password")
	}
}

func TestMasterPasswordSource_Name(t *testing.T) {
	src := NewMasterPasswordSource("/tmp", staticPrompt())
	if src.Name() != "master-password" {
		t.Errorf("expected 'master-password', got %q", src.Name())
	}
	if !src.RequiresUserInput() {
		t.Error("RequiresUserInput should return true")
	}
}

func TestMasterPasswordSource_UnsupportedVersion(t *testing.T) {
	dir := t.TempDir()
	bad := []byte(`{"version": 99, "algorithm": "argon2id", "salt": "", "params": {"time":3,"memory":65536,"threads":4,"key_len":32}, "verify": ""}`)
	if err := os.WriteFile(filepath.Join(dir, sidecarFileName), bad, 0o600); err != nil {
		t.Fatal(err)
	}

	src := NewMasterPasswordSource(dir, staticPrompt("any-password"))
	_, err := src.GetEncryptionKey()
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestMasterPasswordSource_UnsupportedAlgorithm(t *testing.T) {
	dir := t.TempDir()
	bad := []byte(`{"version": 1, "algorithm": "scrypt", "salt": "", "params": {"time":3,"memory":65536,"threads":4,"key_len":32}, "verify": ""}`)
	if err := os.WriteFile(filepath.Join(dir, sidecarFileName), bad, 0o600); err != nil {
		t.Fatal(err)
	}

	src := NewMasterPasswordSource(dir, staticPrompt("any-password"))
	_, err := src.GetEncryptionKey()
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

func TestMasterPasswordSource_RejectsOutOfRangeParams(t *testing.T) {
	tests := map[string]string{
		"zero memory":   `{"version":1,"algorithm":"argon2id","salt":"","verify":"","params":{"time":3,"memory":0,"threads":4,"key_len":32}}`,
		"huge memory":   `{"version":1,"algorithm":"argon2id","salt":"","verify":"","params":{"time":3,"memory":2147483647,"threads":4,"key_len":32}}`,
		"zero threads":  `{"version":1,"algorithm":"argon2id","salt":"","verify":"","params":{"time":3,"memory":65536,"threads":0,"key_len":32}}`,
		"huge time":     `{"version":1,"algorithm":"argon2id","salt":"","verify":"","params":{"time":999,"memory":65536,"threads":4,"key_len":32}}`,
		"wrong key_len": `{"version":1,"algorithm":"argon2id","salt":"","verify":"","params":{"time":3,"memory":65536,"threads":4,"key_len":16}}`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, sidecarFileName), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			src := NewMasterPasswordSource(dir, staticPrompt("any-password"))
			_, err := src.GetEncryptionKey()
			if err == nil {
				t.Fatal("expected error for out-of-range params")
			}
		})
	}
}

func TestMasterPasswordSource_CachesKeyAcrossCalls(t *testing.T) {
	dir := t.TempDir()
	password := "repeat-test-password"

	callCount := 0
	prompt := func(_ string) ([]byte, error) {
		callCount++
		return []byte(password), nil
	}

	src := NewMasterPasswordSource(dir, prompt)

	// First call: prompts twice (create + confirm), derives key
	key1, err := src.GetEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	firstRunCalls := callCount

	// Second call: cache hit, no prompt
	key2, err := src.GetEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	if callCount != firstRunCalls {
		t.Fatalf("expected no additional prompts after cache hit, got %d (was %d)", callCount, firstRunCalls)
	}
	if !bytes.Equal(key1, key2) {
		t.Fatal("cached key should match first-call key")
	}

	// Close clears the cache — next call prompts again
	src.Close()
	key3, err := src.GetEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	if callCount == firstRunCalls {
		t.Fatal("expected prompt after Close() clears cache")
	}
	if !bytes.Equal(key1, key3) {
		t.Fatal("same password should still yield same key")
	}
}

func TestMasterPasswordSource_ConcurrentFirstRunSerialized(t *testing.T) {
	dir := t.TempDir()
	password := "concurrent-test-password"

	var prompt PasswordPromptFunc = func(_ string) ([]byte, error) {
		return []byte(password), nil
	}

	const N = 4
	keys := make([][]byte, N)
	errs := make([]error, N)

	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	done.Add(N)

	for i := range N {
		go func(idx int) {
			defer done.Done()
			src := NewMasterPasswordSource(dir, prompt)
			start.Wait()
			keys[idx], errs[idx] = src.GetEncryptionKey()
		}(i)
	}
	start.Done()
	done.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}

	for i := 1; i < N; i++ {
		if !bytes.Equal(keys[0], keys[i]) {
			t.Fatalf("goroutine %d derived a different key — flock did not serialize first run", i)
		}
	}

	if _, err := os.Stat(filepath.Join(dir, sidecarFileName)); err != nil {
		t.Fatalf("sidecar missing after concurrent init: %v", err)
	}
}

func TestMasterPasswordSourceHelperProcess(t *testing.T) {
	if os.Getenv("SESH_TEST_MP_HELPER") != "1" {
		return
	}
	dir := os.Getenv("SESH_TEST_MP_DIR")
	password := os.Getenv("SESH_TEST_MP_PASSWORD")

	src := NewMasterPasswordSource(dir, func(_ string) ([]byte, error) {
		return []byte(password), nil
	})

	key, err := src.GetEncryptionKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(hex.EncodeToString(key))
	os.Exit(0)
}

func TestMasterPasswordSource_ConcurrentFirstRunMultiProcess(t *testing.T) {
	dir := t.TempDir()
	password := "multi-process-test-password"

	const N = 4
	cmds := make([]*exec.Cmd, N)
	outs := make([]*bytes.Buffer, N)
	errs := make([]*bytes.Buffer, N)

	for i := range N {
		cmd := exec.Command(os.Args[0], "-test.run=TestMasterPasswordSourceHelperProcess") //nolint:gosec // os.Args[0] is the test binary itself
		cmd.Env = append(os.Environ(),
			"SESH_TEST_MP_HELPER=1",
			"SESH_TEST_MP_DIR="+dir,
			"SESH_TEST_MP_PASSWORD="+password,
		)
		outs[i] = &bytes.Buffer{}
		errs[i] = &bytes.Buffer{}
		cmd.Stdout = outs[i]
		cmd.Stderr = errs[i]
		cmds[i] = cmd
	}

	for i, c := range cmds {
		if err := c.Start(); err != nil {
			t.Fatalf("start process %d: %v", i, err)
		}
	}
	for i, c := range cmds {
		if err := c.Wait(); err != nil {
			t.Fatalf("process %d failed: %v\nstderr: %s", i, err, errs[i].String())
		}
	}

	first := outs[0].String()
	if first == "" {
		t.Fatal("process 0 produced no key output")
	}
	for i := 1; i < N; i++ {
		if outs[i].String() != first {
			t.Fatalf("process %d derived a different key — flock did not serialize across processes\n  process 0: %s\n  process %d: %s", i, first, i, outs[i].String())
		}
	}
}

func TestMasterPasswordSource_ConcurrentGetAndCloseAreSafe(t *testing.T) {
	dir := t.TempDir()
	var prompt PasswordPromptFunc = func(_ string) ([]byte, error) {
		return []byte("test-password-12345"), nil
	}
	src := NewMasterPasswordSource(dir, prompt)
	if _, err := src.GetEncryptionKey(); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if k, err := src.GetEncryptionKey(); err == nil {
				secure.SecureZeroBytes(k)
			}
		}()
		go func() {
			defer wg.Done()
			src.Close()
		}()
	}
	wg.Wait()
}

func TestMasterPasswordSource_StoreEncryptionKey_NoOp(t *testing.T) {
	src := NewMasterPasswordSource(t.TempDir(), staticPrompt())
	if err := src.StoreEncryptionKey([]byte("ignored")); err != nil {
		t.Errorf("StoreEncryptionKey should be a no-op, got %v", err)
	}
}

func TestMasterPasswordSource_RejectsShortSalt(t *testing.T) {
	dir := t.TempDir()
	bad := []byte(`{"version":1,"algorithm":"argon2id","salt":"AQID","verify":"","params":{"time":3,"memory":65536,"threads":4,"key_len":32}}`)
	if err := os.WriteFile(filepath.Join(dir, sidecarFileName), bad, 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	prompt := func(_ string) ([]byte, error) {
		called = true
		return []byte("password"), nil
	}
	src := NewMasterPasswordSource(dir, prompt)
	_, err := src.GetEncryptionKey()
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("salt too short")) {
		t.Fatalf("expected salt-too-short error, got %v", err)
	}
	if called {
		t.Errorf("prompt should not be called when sidecar fails sanity checks")
	}
}

func TestMasterPasswordSource_RejectsShortVerify(t *testing.T) {
	dir := t.TempDir()
	saltB64 := "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="
	bad := []byte(`{"version":1,"algorithm":"argon2id","salt":"` + saltB64 + `","verify":"AQID","params":{"time":3,"memory":65536,"threads":4,"key_len":32}}`)
	if err := os.WriteFile(filepath.Join(dir, sidecarFileName), bad, 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	prompt := func(_ string) ([]byte, error) {
		called = true
		return []byte("password"), nil
	}
	src := NewMasterPasswordSource(dir, prompt)
	_, err := src.GetEncryptionKey()
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("verify blob too short")) {
		t.Fatalf("expected verify-too-short error, got %v", err)
	}
	if called {
		t.Errorf("prompt should not be called when sidecar fails sanity checks")
	}
}

func TestMasterPasswordSource_RejectsNonAbsoluteDataDir(t *testing.T) {
	src := NewMasterPasswordSource("relative/path", staticPrompt("password-12345", "password-12345"))
	_, err := src.GetEncryptionKey()
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("must be an absolute path")) {
		t.Fatalf("expected absolute-path error, got %v", err)
	}
}

func TestMasterPasswordSource_SidecarHasNoSecrets(t *testing.T) {
	dir := t.TempDir()
	password := "super-secret-password-12345"
	src := NewMasterPasswordSource(dir, staticPrompt(password, password))

	if _, err := src.GetEncryptionKey(); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(filepath.Join(dir, sidecarFileName))
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Contains(b, []byte(password)) {
		t.Fatal("sidecar contains the master password in plaintext")
	}
}

// seedSidecar creates a sidecar at dir whose master password is "right-one"
// so retry-loop tests can drive unlock() directly without re-prompting twice
// for the create+confirm flow.
func seedSidecar(t *testing.T, dir string) {
	t.Helper()
	src := NewMasterPasswordSource(dir, staticPrompt("right-one", "right-one"))
	defer src.Close()
	key, err := src.GetEncryptionKey()
	if err != nil {
		t.Fatalf("seed sidecar: %v", err)
	}
	secure.SecureZeroBytes(key)
}

func TestMasterPasswordSource_RetriesWrongPasswordUntilCorrect(t *testing.T) {
	dir := t.TempDir()
	seedSidecar(t, dir)

	var seenPrompts []string
	prompt := func(p string) ([]byte, error) {
		seenPrompts = append(seenPrompts, p)
		switch len(seenPrompts) {
		case 1:
			return []byte("wrong-1"), nil
		case 2:
			return []byte("wrong-2"), nil
		default:
			return []byte("right-one"), nil
		}
	}

	src := NewMasterPasswordSource(dir, prompt, WithMaxAttempts(3))
	defer src.Close()

	key, err := src.GetEncryptionKey()
	if err != nil {
		t.Fatalf("expected success on 3rd attempt: %v", err)
	}
	secure.SecureZeroBytes(key)
	if len(seenPrompts) != 3 {
		t.Fatalf("expected 3 prompts, got %d", len(seenPrompts))
	}
	// The retry-message contract is the user-visible signal that a
	// previous attempt was wrong — assert it actually shows up in the
	// prompt string (not just that we re-prompted).
	if !strings.Contains(seenPrompts[1], "Wrong password") || !strings.Contains(seenPrompts[1], "(2/3)") {
		t.Errorf("2nd prompt %q should announce the retry with (2/3)", seenPrompts[1])
	}
	if !strings.Contains(seenPrompts[2], "(3/3)") {
		t.Errorf("3rd prompt %q should be marked (3/3)", seenPrompts[2])
	}

	// Cache-after-retry: a second GetEncryptionKey must hit the cache
	// and not re-prompt, even though the successful unlock came on a
	// non-first attempt.
	key2, err := src.GetEncryptionKey()
	if err != nil {
		t.Fatalf("second GetEncryptionKey: %v", err)
	}
	secure.SecureZeroBytes(key2)
	if len(seenPrompts) != 3 {
		t.Errorf("cache should suppress re-prompt; got %d total prompts", len(seenPrompts))
	}
}

func TestMasterPasswordSource_FailsAfterMaxAttempts(t *testing.T) {
	dir := t.TempDir()
	seedSidecar(t, dir)

	prompts := 0
	prompt := func(_ string) ([]byte, error) {
		prompts++
		return []byte("always-wrong"), nil
	}

	src := NewMasterPasswordSource(dir, prompt, WithMaxAttempts(3))
	_, err := src.GetEncryptionKey()
	if err == nil {
		t.Fatal("expected error after exhausting attempts")
	}
	if !strings.Contains(err.Error(), "wrong master password") {
		t.Errorf("error %q does not mention wrong password", err.Error())
	}
	// Multi-attempt failures surface the budget so logs/users can tell
	// "they typed it wrong N times" from "single-shot non-interactive fail".
	if !strings.Contains(err.Error(), "after 3 attempts") {
		t.Errorf("error %q should report the attempt count", err.Error())
	}
	if prompts != 3 {
		t.Errorf("expected 3 prompts, got %d", prompts)
	}
}

func TestMasterPasswordSource_DefaultsToSingleAttempt(t *testing.T) {
	dir := t.TempDir()
	seedSidecar(t, dir)

	prompts := 0
	prompt := func(_ string) ([]byte, error) {
		prompts++
		return []byte("wrong"), nil
	}

	src := NewMasterPasswordSource(dir, prompt)
	_, err := src.GetEncryptionKey()
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
	if prompts != 1 {
		t.Errorf("expected 1 prompt without WithMaxAttempts, got %d", prompts)
	}
}

func TestMasterPasswordSource_PromptErrorBreaksLoop(t *testing.T) {
	dir := t.TempDir()
	seedSidecar(t, dir)

	prompts := 0
	prompt := func(_ string) ([]byte, error) {
		prompts++
		if prompts == 1 {
			return []byte("wrong"), nil
		}
		return nil, errors.New("stdin closed")
	}

	src := NewMasterPasswordSource(dir, prompt, WithMaxAttempts(5))
	_, err := src.GetEncryptionKey()
	if err == nil {
		t.Fatal("expected error from prompt failure")
	}
	if !strings.Contains(err.Error(), "read password") {
		t.Errorf("error %q should surface the prompt failure", err.Error())
	}
	if prompts != 2 {
		t.Errorf("expected loop to stop on prompt error after 2 calls, got %d", prompts)
	}
}

func TestMasterPasswordSource_NoRetryOnSidecarError(t *testing.T) {
	dir := t.TempDir()
	// Write a sidecar with an unsupported version so readSidecar fails
	// before any prompt can fire. Confirms the retry loop doesn't run
	// for non-password failures (acceptance criterion #3 in the roadmap).
	bad := `{"version": 99, "algorithm": "argon2id", "salt": "", "verify": "", "params": {"time":3,"memory":65536,"threads":4,"key_len":32}}`
	if err := os.WriteFile(filepath.Join(dir, sidecarFileName), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}

	prompts := 0
	prompt := func(_ string) ([]byte, error) {
		prompts++
		return []byte("anything"), nil
	}

	src := NewMasterPasswordSource(dir, prompt, WithMaxAttempts(3))
	_, err := src.GetEncryptionKey()
	if err == nil {
		t.Fatal("expected error from corrupt sidecar")
	}
	if prompts != 0 {
		t.Errorf("expected 0 prompts when sidecar is corrupt, got %d", prompts)
	}
}

func TestWithMaxAttempts_ClampsBelowOne(t *testing.T) {
	dir := t.TempDir()
	seedSidecar(t, dir)

	for _, n := range []int{0, -1, -100} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			prompts := 0
			prompt := func(_ string) ([]byte, error) {
				prompts++
				return []byte("wrong"), nil
			}
			src := NewMasterPasswordSource(dir, prompt, WithMaxAttempts(n))
			if _, err := src.GetEncryptionKey(); err == nil {
				t.Fatal("expected error")
			}
			if prompts != 1 {
				t.Errorf("WithMaxAttempts(%d) should clamp to 1, got %d prompts", n, prompts)
			}
		})
	}
}
