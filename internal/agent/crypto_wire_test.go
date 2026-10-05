package agent

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/vault"
)

func TestServer_UnlockDecryptEncryptStatus(t *testing.T) {
	sockPath := tempSocketPath(t)
	stop := runServer(t, sockPath)
	defer stop()

	params := lightParams()
	salt, verify := sealVerify(t, "correct-horse", params)

	conn := dialClient(t, sockPath)
	defer mustClose(t, conn)

	st, err := Status(conn)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Unlocked {
		t.Fatal("fresh agent reported unlocked")
	}

	id := UnlockID(verify)
	if _, err := Decrypt(conn, []byte("nope"), []byte("salt"), id); err == nil {
		t.Fatal("decrypt before unlock succeeded")
	} else {
		var pe *ProtocolError
		if !errors.As(err, &pe) || pe.Code != ErrCodeNotUnlocked {
			t.Fatalf("decrypt before unlock err = %v, want not_unlocked", err)
		}
	}
	if _, _, err := Encrypt(conn, []byte("nope"), id); err == nil {
		t.Fatal("encrypt before unlock succeeded")
	} else {
		var pe *ProtocolError
		if !errors.As(err, &pe) || pe.Code != ErrCodeNotUnlocked {
			t.Fatalf("encrypt before unlock err = %v, want not_unlocked", err)
		}
	}

	if err := Unlock(conn, []byte("correct-horse"), salt, verify, params); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	st, err = Status(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Unlocked || st.UnlockID != UnlockID(verify) || st.AgentPID == 0 {
		t.Fatalf("status after unlock = %+v", st)
	}

	ct, entrySalt, err := Encrypt(conn, []byte("secret"), id)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := Decrypt(conn, ct, entrySalt, id)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, []byte("secret")) {
		t.Fatalf("plaintext = %q", got)
	}
}

func TestServer_UnlockWrongPassword(t *testing.T) {
	sockPath := tempSocketPath(t)
	stop := runServer(t, sockPath)
	defer stop()

	params := lightParams()
	salt, verify := sealVerify(t, "correct-horse", params)
	conn := dialClient(t, sockPath)
	defer mustClose(t, conn)

	err := Unlock(conn, []byte("nope"), salt, verify, params)
	var pe *ProtocolError
	if !errors.As(err, &pe) || pe.Code != ErrCodeWrongPassword {
		t.Fatalf("Unlock err = %v, want wrong_password", err)
	}
}

func TestOracle_StoreRoundTrip(t *testing.T) {
	sockPath := tempSocketPath(t)
	stop := runServer(t, sockPath)
	defer stop()

	params := lightParams()
	salt, verify := sealVerify(t, "correct-horse", params)
	conn := dialClient(t, sockPath)
	if err := Unlock(conn, []byte("correct-horse"), salt, verify, params); err != nil {
		t.Fatal(err)
	}
	ks := NewOracle(conn, UnlockID(verify))

	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := database.Open(dbPath, ks)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	k := vault.Key{Kind: vault.KindAPIKey, Service: "github"}
	if err := store.Put(k, []byte("token")); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(k)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("token")) {
		t.Fatalf("secret = %q", got)
	}
	if _, ok := any(ks).(database.KeySource); ok {
		t.Fatal("Oracle satisfies database.KeySource, so it could hand out the key")
	}
}

func TestServer_DecryptCorruptCiphertext(t *testing.T) {
	sockPath := tempSocketPath(t)
	stop := runServer(t, sockPath)
	defer stop()

	params := lightParams()
	salt, verify := sealVerify(t, "correct-horse", params)
	conn := dialClient(t, sockPath)
	defer mustClose(t, conn)
	if err := Unlock(conn, []byte("correct-horse"), salt, verify, params); err != nil {
		t.Fatal(err)
	}
	_, err := Decrypt(conn, []byte("not-a-ciphertext"), []byte("0123456789abcdef"), UnlockID(verify))
	var pe *ProtocolError
	if !errors.As(err, &pe) || pe.Code != ErrCodeDecryptFailed {
		t.Fatalf("Decrypt err = %v, want decrypt_failed", err)
	}
}

func TestServer_EncryptRejectsStaleUnlockID(t *testing.T) {
	sockPath := tempSocketPath(t)
	stop := runServer(t, sockPath)
	defer stop()

	params := lightParams()
	salt, verify := sealVerify(t, "correct-horse", params)
	conn := dialClient(t, sockPath)
	defer mustClose(t, conn)
	if err := Unlock(conn, []byte("correct-horse"), salt, verify, params); err != nil {
		t.Fatal(err)
	}
	_, _, err := Encrypt(conn, []byte("secret"), "not-the-id")
	var pe *ProtocolError
	if !errors.As(err, &pe) || pe.Code != ErrCodeUnlockMismatch {
		t.Fatalf("Encrypt err = %v, want unlock_mismatch", err)
	}
}

func TestServer_UnlockRejectsOutOfRangeParams(t *testing.T) {
	sockPath := tempSocketPath(t)
	stop := runServer(t, sockPath)
	defer stop()

	params := lightParams()
	params.Memory = 0
	salt, verify := sealVerify(t, "correct-horse", lightParams())
	conn := dialClient(t, sockPath)
	defer mustClose(t, conn)
	err := Unlock(conn, []byte("correct-horse"), salt, verify, params)
	var pe *ProtocolError
	if !errors.As(err, &pe) || pe.Code != ErrCodeBadRequest {
		t.Fatalf("Unlock err = %v, want bad_request", err)
	}
}

func TestServer_MaxSizeSecretRoundTrip(t *testing.T) {
	sockPath := tempSocketPath(t)
	stop := runServer(t, sockPath)
	defer stop()

	params := lightParams()
	salt, verify := sealVerify(t, "correct-horse", params)
	conn := dialClient(t, sockPath)
	defer mustClose(t, conn)
	if err := Unlock(conn, []byte("correct-horse"), salt, verify, params); err != nil {
		t.Fatal(err)
	}
	id := UnlockID(verify)

	secret := bytes.Repeat([]byte{0xff}, database.MaxSecretSize)
	ct, entrySalt, err := Encrypt(conn, secret, id)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := Decrypt(conn, ct, entrySalt, id)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("max-size secret did not round-trip")
	}
}

func TestServer_OversizedFrameIsBadRequest(t *testing.T) {
	sockPath := tempSocketPath(t)
	stop := runServer(t, sockPath)
	defer stop()

	conn := dialAndShake(t, sockPath)
	defer mustClose(t, conn)
	// The agent may close before the whole payload is written; the
	// error reply is what matters.
	// The agent reads in buffer-sized chunks, so overshoot by more than one
	// buffer for the limit to trip without a newline.
	_, _ = conn.Write(bytes.Repeat([]byte("x"), maxFrameSize+64<<10)) //nolint:errcheck // see comment
	env, raw, err := readEnvelope(bufio.NewReader(conn))
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	var resp ErrorResponse
	if env.Type != TypeError || decodeMessage(raw, &resp) != nil || resp.Code != ErrCodeBadRequest {
		t.Fatalf("reply = %s, want bad_request", raw)
	}
}

func TestOracle_ConcurrentEncryptDecrypt(t *testing.T) {
	sockPath := tempSocketPath(t)
	stop := runServer(t, sockPath)
	defer stop()

	params := lightParams()
	salt, verify := sealVerify(t, "correct-horse", params)
	conn := dialClient(t, sockPath)
	if err := Unlock(conn, []byte("correct-horse"), salt, verify, params); err != nil {
		t.Fatal(err)
	}
	ks := NewOracle(conn, UnlockID(verify))
	t.Cleanup(ks.Close)

	const n = 8
	var wg sync.WaitGroup
	errCh := make(chan error, n)
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			ct, entrySalt, err := ks.EncryptEntry([]byte("secret"))
			if err != nil {
				errCh <- err
				return
			}
			got, err := ks.DecryptEntry(ct, entrySalt)
			if err != nil {
				errCh <- err
				return
			}
			if !bytes.Equal(got, []byte("secret")) {
				errCh <- errors.New("concurrent plaintext mismatch")
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

func TestOracle_TimeoutRetiresConnection(t *testing.T) {
	old := requestTimeout
	requestTimeout = 200 * time.Millisecond
	t.Cleanup(func() { requestTimeout = old })

	// Fake agent: echoes each ciphertext back as plaintext, and answers
	// the first request only after the client has given up on it.
	sockPath := startFakeAgentLoop(t, func(i int, req DecryptRequest) DecryptResponse {
		if i == 0 {
			time.Sleep(400 * time.Millisecond)
		}
		return DecryptResponse{Type: TypeDecryptAck, Version: ProtocolVersion, Plaintext: req.Ciphertext}
	})
	conn := dialClient(t, sockPath)
	ks := NewOracle(conn, "id")
	defer ks.Close()

	if _, err := ks.DecryptEntry([]byte("secret-of-A"), []byte("salt")); err == nil {
		t.Fatal("first decrypt succeeded, want a timeout")
	}
	time.Sleep(300 * time.Millisecond) // A's late reply is now on the wire
	got, err := ks.DecryptEntry([]byte("secret-of-B"), []byte("salt"))
	if err == nil {
		t.Fatalf("second decrypt returned %q, want an error on the retired connection", got)
	}
	if !errors.Is(err, errConnBroken) {
		t.Fatalf("err = %v, want errConnBroken", err)
	}
}

// startFakeAgentLoop accepts one client, acks hello, and answers each
// decrypt request with reply(i, req).
func startFakeAgentLoop(t *testing.T, reply func(i int, req DecryptRequest) DecryptResponse) string {
	t.Helper()
	sockPath := tempSocketPath(t)
	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mustClose(t, lis) })
	go func() {
		c, err := lis.AcceptUnix()
		if err != nil {
			return
		}
		defer c.Close() //nolint:errcheck // fake agent teardown
		r := bufio.NewReader(c)
		if _, err := r.ReadBytes('\n'); err != nil {
			return
		}
		if err := writeJSON(c, HelloResponse{Type: TypeHelloAck, Version: ProtocolVersion}); err != nil {
			return
		}
		for i := 0; ; i++ {
			line, err := r.ReadBytes('\n')
			if err != nil {
				return
			}
			var req DecryptRequest
			if err := decodeMessage(line, &req); err != nil {
				return
			}
			if err := writeJSON(c, reply(i, req)); err != nil {
				return
			}
		}
	}()
	return sockPath
}

func TestOracle_ClosedRefusesRequests(t *testing.T) {
	sockPath := tempSocketPath(t)
	stop := runServer(t, sockPath)
	defer stop()

	o := NewOracle(dialClient(t, sockPath), "id")
	o.Close()
	o.Close() // second Close is a no-op
	if _, _, err := o.EncryptEntry([]byte("x")); err == nil || !strings.Contains(err.Error(), "agent oracle is closed") {
		t.Fatalf("EncryptEntry after Close err = %v, want agent oracle is closed", err)
	}
	if _, err := o.DecryptEntry([]byte("x"), []byte("salt")); err == nil || !strings.Contains(err.Error(), "agent oracle is closed") {
		t.Fatalf("DecryptEntry after Close err = %v, want agent oracle is closed", err)
	}
}
