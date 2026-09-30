package agent

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/secure"
)

func lightParams() database.Argon2idParams {
	return database.Argon2idParams{Time: 1, Memory: 8, Threads: 1, KeyLen: 32}
}

func sealVerify(t *testing.T, password string, params database.Argon2idParams) (salt, verify []byte) {
	t.Helper()
	salt = []byte("0123456789abcdef")
	key := database.DeriveKey([]byte(password), salt, params)
	t.Cleanup(func() { secure.SecureZeroBytes(key) })
	blob, err := database.Encrypt(key, []byte(database.VerifyPlaintext))
	if err != nil {
		t.Fatalf("encrypt verify: %v", err)
	}
	return salt, blob
}

func TestKeystore_UnlockAndRoundTrip(t *testing.T) {
	params := lightParams()
	salt, verify := sealVerify(t, "correct-horse", params)
	var ks keystore
	if err := ks.Unlock([]byte("correct-horse"), salt, verify, params); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	unlocked, id, _ := ks.Status()
	if !unlocked {
		t.Fatal("status unlocked = false")
	}
	if id != UnlockID(verify) {
		t.Fatalf("unlock id = %q, want %q", id, UnlockID(verify))
	}

	ct, entrySalt, err := ks.Encrypt([]byte("secret"), id)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := ks.Decrypt(ct, entrySalt, id)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, []byte("secret")) {
		t.Fatalf("plaintext = %q", got)
	}
}

func TestKeystore_WrongPasswordStaysLocked(t *testing.T) {
	params := lightParams()
	salt, verify := sealVerify(t, "correct-horse", params)
	var ks keystore
	err := ks.Unlock([]byte("nope"), salt, verify, params)
	if !errors.Is(err, errWrongPassword) {
		t.Fatalf("Unlock err = %v, want wrong password", err)
	}
	if unlocked, _, _ := ks.Status(); unlocked {
		t.Fatal("wrong password left the keystore unlocked")
	}
}

func TestKeystore_DecryptBeforeUnlock(t *testing.T) {
	var ks keystore
	_, err := ks.Decrypt([]byte("ct"), []byte("salt"), "")
	if !errors.Is(err, errNotUnlocked) {
		t.Fatalf("Decrypt err = %v, want locked", err)
	}
}

func TestKeystore_ReUnlockReplacesKey(t *testing.T) {
	params := lightParams()
	saltA, verifyA := sealVerify(t, "password-a", params)
	var ks keystore
	if err := ks.Unlock([]byte("password-a"), saltA, verifyA, params); err != nil {
		t.Fatal(err)
	}
	ct, entrySalt, err := ks.Encrypt([]byte("secret"), UnlockID(verifyA))
	if err != nil {
		t.Fatal(err)
	}

	saltB, verifyB := sealVerify(t, "password-b", params)
	if err := ks.Unlock([]byte("password-b"), saltB, verifyB, params); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Decrypt(ct, entrySalt, UnlockID(verifyA)); !errors.Is(err, errUnlockMismatch) {
		t.Fatalf("decrypt with the old id err = %v, want unlock mismatch", err)
	}
	if _, err := ks.Decrypt(ct, entrySalt, UnlockID(verifyB)); !errors.Is(err, errDecryptFailed) {
		t.Fatalf("decrypt under the new key err = %v, want decrypt failed", err)
	}
	if _, id, _ := ks.Status(); id != UnlockID(verifyB) {
		t.Fatalf("unlock id = %q, want password-b id", id)
	}
}

func TestKeystore_RejectsShortSalt(t *testing.T) {
	var ks keystore
	err := ks.Unlock([]byte("pw"), []byte("short"), bytes.Repeat([]byte("v"), 28), lightParams())
	if !errors.Is(err, errBadRequest) {
		t.Fatalf("err = %v, want bad request", err)
	}
}

func TestKeystore_RejectsOutOfRangeParams(t *testing.T) {
	params := lightParams()
	params.Memory = 0
	var ks keystore
	err := ks.Unlock([]byte("pw"), bytes.Repeat([]byte("s"), 16), bytes.Repeat([]byte("v"), 28), params)
	if !errors.Is(err, errBadRequest) {
		t.Fatalf("err = %v, want bad request", err)
	}
}

func TestKeystore_ShutdownClearsKeyAndRefusesUnlock(t *testing.T) {
	params := lightParams()
	salt, verify := sealVerify(t, "correct-horse", params)
	var ks keystore
	if err := ks.Unlock([]byte("correct-horse"), salt, verify, params); err != nil {
		t.Fatal(err)
	}
	ks.shutdown()
	if unlocked, _, _ := ks.Status(); unlocked {
		t.Fatal("shutdown left the keystore unlocked")
	}
	orig := deriveKey
	t.Cleanup(func() { deriveKey = orig })
	deriveKey = func(password, salt []byte, p database.Argon2idParams) []byte {
		t.Error("Unlock ran Argon2id after shutdown")
		return orig(password, salt, p)
	}
	if _, err := ks.Decrypt([]byte("ct"), []byte("0123456789abcdef"), UnlockID(verify)); !errors.Is(err, errNotUnlocked) {
		t.Fatalf("Decrypt after shutdown err = %v, want locked", err)
	}
	if err := ks.Unlock([]byte("correct-horse"), salt, verify, params); !errors.Is(err, errShutDown) {
		t.Fatalf("Unlock after shutdown err = %v, want errShutDown", err)
	}
}

func TestKeystore_ConcurrentUnlocksLeaveOneKey(t *testing.T) {
	params := lightParams()
	saltA, verifyA := sealVerify(t, "password-a", params)
	saltB, verifyB := sealVerify(t, "password-b", params)
	var ks keystore

	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := ks.Unlock([]byte("password-a"), saltA, verifyA, params); err != nil {
			errCh <- err
		}
	}()
	go func() {
		defer wg.Done()
		if err := ks.Unlock([]byte("password-b"), saltB, verifyB, params); err != nil {
			errCh <- err
		}
	}()
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	unlocked, id, _ := ks.Status()
	if !unlocked {
		t.Fatal("concurrent unlocks left the keystore locked")
	}
	if id != UnlockID(verifyA) && id != UnlockID(verifyB) {
		t.Fatalf("unlock id = %q, want one of the two passwords", id)
	}
	ct, entrySalt, err := ks.Encrypt([]byte("secret"), id)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ks.Decrypt(ct, entrySalt, id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("secret")) {
		t.Fatalf("plaintext = %q", got)
	}
}

func TestKeystore_UnlocksDeriveOneAtATime(t *testing.T) {
	var mu sync.Mutex
	var inFlight, peak int
	orig := deriveKey
	t.Cleanup(func() { deriveKey = orig })
	deriveKey = func(password, salt []byte, p database.Argon2idParams) []byte {
		mu.Lock()
		inFlight++
		peak = max(peak, inFlight)
		mu.Unlock()
		// Hold the derivation open long enough for the others to overlap
		// if nothing serializes them.
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		inFlight--
		mu.Unlock()
		return orig(password, salt, p)
	}

	params := lightParams()
	salt, verify := sealVerify(t, "correct-horse", params)
	var ks keystore
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			if err := ks.Unlock([]byte("correct-horse"), salt, verify, params); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if peak != 1 {
		t.Fatalf("peak concurrent derivations = %d, want 1", peak)
	}
}

func TestKeystore_ShutdownDuringUnlockDiscardsKey(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	orig := deriveKey
	t.Cleanup(func() { deriveKey = orig })
	deriveKey = func(password, salt []byte, p database.Argon2idParams) []byte {
		close(entered)
		<-release
		return orig(password, salt, p)
	}

	params := lightParams()
	salt, verify := sealVerify(t, "correct-horse", params)
	var ks keystore
	done := make(chan error, 1)
	go func() { done <- ks.Unlock([]byte("correct-horse"), salt, verify, params) }()

	<-entered
	ks.shutdown() // must not wait for the derivation
	close(release)
	if err := <-done; !errors.Is(err, errShutDown) {
		t.Fatalf("Unlock err = %v, want errShutDown", err)
	}
	if unlocked, _, _ := ks.Status(); unlocked {
		t.Fatal("an unlock that finished after shutdown installed its key")
	}
}
