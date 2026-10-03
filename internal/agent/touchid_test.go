package agent

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/touchid"
)

// softwareChip replaces the Secure Enclave with a software P-256 key. fail,
// when set, is returned instead of unwrapping, as a refused fingerprint
// would be. It returns the public key and a count of prompts shown.
func softwareChip(t *testing.T, fail error) (pub []byte, prompts *int) {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	orig := touchIDUnwrap
	touchIDUnwrap = func(_ []byte, w touchid.Wrapped, aad []byte) ([]byte, error) {
		n++
		if fail != nil {
			return nil, fail
		}
		return touchid.UnwrapWith(func(peer []byte) ([]byte, error) {
			p, err := ecdh.P256().NewPublicKey(peer)
			if err != nil {
				return nil, err
			}
			return priv.ECDH(p)
		}, w, aad)
	}
	t.Cleanup(func() { touchIDUnwrap = orig })
	return priv.PublicKey().Bytes(), &n
}

// unlockForTouchID unlocks a fresh agent with a password and returns the
// connection, the vault's verify blob, and its unlock id.
func unlockForTouchID(t *testing.T, sockPath string) (conn *Conn, verify []byte, id string) {
	t.Helper()
	params := lightParams()
	salt, verify := sealVerify(t, "correct-horse", params)
	conn = dialClient(t, sockPath)
	if err := Unlock(conn, []byte("correct-horse"), salt, verify, params); err != nil {
		t.Fatal(err)
	}
	return conn, verify, UnlockID(verify)
}

func TestTouchID_WrapThenUnlockWithAFingerprint(t *testing.T) {
	sockPath := tempSocketPath(t)
	var log logBuffer
	serve(t, sockPath, withLogOutput(&log))
	pub, prompts := softwareChip(t, nil)
	conn, verify, id := unlockForTouchID(t, sockPath)
	defer mustClose(t, conn)

	ct, salt, err := Encrypt(conn, []byte("stored before the lock"), id)
	if err != nil {
		t.Fatal(err)
	}
	w, err := TouchIDWrap(conn, id, pub)
	if err != nil {
		t.Fatalf("TouchIDWrap: %v", err)
	}
	if err := Lock(conn); err != nil {
		t.Fatal(err)
	}

	f := touchid.NewFile(id, []byte("chip blob"), pub, w)
	if err := UnlockTouchID(conn, f, verify); err != nil {
		t.Fatalf("UnlockTouchID: %v", err)
	}
	if *prompts != 1 {
		t.Errorf("prompts = %d, want 1", *prompts)
	}
	got, err := Decrypt(conn, ct, salt, id)
	if err != nil || string(got) != "stored before the lock" {
		t.Fatalf("decrypt after a Touch ID unlock = %q, %v", got, err)
	}
	waitForLog(t, &log, "unlocked (Touch ID)")

	// Already unlocked for this vault: a second request doesn't prompt.
	if err := UnlockTouchID(conn, f, verify); err != nil {
		t.Fatal(err)
	}
	if *prompts != 1 {
		t.Errorf("an unlocked agent prompted again (prompts = %d)", *prompts)
	}
}

func TestTouchIDWrap_Refused(t *testing.T) {
	sockPath := tempSocketPath(t)
	serve(t, sockPath)
	pub, _ := softwareChip(t, nil)
	conn, _, id := unlockForTouchID(t, sockPath)
	defer mustClose(t, conn)

	if _, err := TouchIDWrap(conn, "another vault", pub); err == nil || !strings.Contains(err.Error(), ErrCodeUnlockMismatch) {
		t.Errorf("wrap for another vault: err = %v", err)
	}
	if _, err := TouchIDWrap(conn, id, []byte("not a key")); err == nil || !strings.Contains(err.Error(), ErrCodeBadRequest) {
		t.Errorf("wrap to a bad public key: err = %v", err)
	}
	if err := Lock(conn); err != nil {
		t.Fatal(err)
	}
	if _, err := TouchIDWrap(conn, id, pub); err == nil || !strings.Contains(err.Error(), ErrCodeNotUnlocked) {
		t.Errorf("wrap while locked: err = %v", err)
	}
}

func TestUnlockTouchID_Failures(t *testing.T) {
	for name, tt := range map[string]struct {
		fail error
		want error
	}{
		"cancelled":          {touchid.ErrCancelled, touchid.ErrCancelled},
		"unavailable":        {touchid.ErrUnavailable, touchid.ErrUnavailable},
		"locked out":         {touchid.ErrLockedOut, touchid.ErrLockedOut},
		"not recognised":     {touchid.ErrFailed, touchid.ErrFailed},
		"wrap doesn't open":  {touchid.ErrWrapMismatch, ErrTouchIDStale},
		"unexpected failure": {errors.New("chip on fire"), nil},
	} {
		t.Run(name, func(t *testing.T) {
			sockPath := tempSocketPath(t)
			srv, _ := serve(t, sockPath)
			pub, _ := softwareChip(t, tt.fail)
			conn, verify, id := unlockForTouchID(t, sockPath)
			defer mustClose(t, conn)
			w, err := TouchIDWrap(conn, id, pub)
			if err != nil {
				t.Fatal(err)
			}
			if err := Lock(conn); err != nil {
				t.Fatal(err)
			}

			err = UnlockTouchID(conn, touchid.NewFile(id, []byte("blob"), pub, w), verify)
			if err == nil {
				t.Fatal("unlocked despite the failure")
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
			if srv.keys.snapshot().unlocked {
				t.Error("agent unlocked after a failed Touch ID unlock")
			}
		})
	}
}

func TestUnlockTouchID_StaleKeyIsRefused(t *testing.T) {
	sockPath := tempSocketPath(t)
	srv, _ := serve(t, sockPath)
	conn, verify, _ := unlockForTouchID(t, sockPath)
	defer mustClose(t, conn)
	if err := Lock(conn); err != nil {
		t.Fatal(err)
	}
	// The chip hands back a key that doesn't open this vault, as an old wrap
	// would after the master password changed.
	orig := touchIDUnwrap
	touchIDUnwrap = func([]byte, touchid.Wrapped, []byte) ([]byte, error) {
		return make([]byte, 32), nil
	}
	t.Cleanup(func() { touchIDUnwrap = orig })

	f := &touchid.File{KeyBlob: []byte("blob"), EphemeralPub: []byte("e"), Ciphertext: []byte("c")}
	if err := UnlockTouchID(conn, f, verify); !errors.Is(err, ErrTouchIDStale) {
		t.Fatalf("err = %v, want ErrTouchIDStale", err)
	}
	if srv.keys.snapshot().unlocked {
		t.Error("installed a key that doesn't open the vault")
	}
}

func TestUnlockTouchID_RefusesAMalformedRequest(t *testing.T) {
	sockPath := tempSocketPath(t)
	serve(t, sockPath)
	conn := dialClient(t, sockPath)
	defer mustClose(t, conn)
	err := UnlockTouchID(conn, &touchid.File{}, nil)
	if err == nil || !strings.Contains(err.Error(), ErrCodeBadRequest) {
		t.Fatalf("err = %v", err)
	}
}
