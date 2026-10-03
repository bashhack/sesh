package agent

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/touchid"
)

// errConnBroken means an earlier request on this connection failed in a
// way that may have left the stream misaligned.
var errConnBroken = errors.New("agent connection unusable after an earlier failure")

// Conn is a client connection that has completed the hello handshake.
// Replies are read through one buffered reader for the connection's life.
// A Conn is not safe for concurrent use.
type Conn struct {
	uc     *net.UnixConn
	r      *bufio.Reader
	broken error
	// agentBuild and agentPID are what the agent reported in hello_ack.
	agentBuild string
	agentPID   int
	closed     bool
}

// Close closes the connection. Closing twice, or after a transport failure
// already closed it, is a no-op.
func (c *Conn) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	return c.uc.Close()
}

// ProtocolError is an ErrorResponse from the agent.
type ProtocolError struct {
	Code    string
	Message string
}

func (e *ProtocolError) Error() string {
	if e.Message == "" {
		return e.Code
	}
	return e.Code + ": " + e.Message
}

// Unlock sends the password and sidecar material. password is zeroed
// before return. The connection must already have completed hello.
func Unlock(conn *Conn, password, salt, verify []byte, params database.Argon2idParams) error {
	defer secure.SecureZeroBytes(password)
	_, err := roundTrip(conn, UnlockRequest{
		Type:     TypeUnlock,
		Version:  ProtocolVersion,
		Password: password,
		Salt:     salt,
		Params:   KDFParams(params),
		Verify:   verify,
	}, TypeUnlockAck)
	return err
}

// Decrypt asks the agent to open one entry blob. unlockID is the
// verify-blob id the caller was built for.
func Decrypt(conn *Conn, ciphertext, salt []byte, unlockID string) ([]byte, error) {
	raw, err := roundTrip(conn, DecryptRequest{
		Type:       TypeDecrypt,
		Version:    ProtocolVersion,
		UnlockID:   unlockID,
		Ciphertext: ciphertext,
		Salt:       salt,
	}, TypeDecryptAck)
	if err != nil {
		return nil, err
	}
	var resp DecryptResponse
	if err := decodeMessage(raw, &resp); err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
}

// Encrypt asks the agent to seal plaintext. The agent chooses the salt.
// plaintext is only read, so the caller still owns it. unlockID is the
// verify-blob id the caller was built for.
func Encrypt(conn *Conn, plaintext []byte, unlockID string) (ciphertext, salt []byte, err error) {
	raw, err := roundTrip(conn, EncryptRequest{
		Type:      TypeEncrypt,
		Version:   ProtocolVersion,
		UnlockID:  unlockID,
		Plaintext: plaintext,
	}, TypeEncryptAck)
	if err != nil {
		return nil, nil, err
	}
	var resp EncryptResponse
	if err := decodeMessage(raw, &resp); err != nil {
		return nil, nil, err
	}
	return resp.Ciphertext, resp.Salt, nil
}

// Status reports whether the agent holds a key and which verify blob it
// was unlocked against.
func Status(conn *Conn) (StatusResponse, error) {
	raw, err := roundTrip(conn, StatusRequest{
		Type:    TypeStatus,
		Version: ProtocolVersion,
	}, TypeStatusAck)
	if err != nil {
		return StatusResponse{}, err
	}
	var resp StatusResponse
	if err := decodeMessage(raw, &resp); err != nil {
		return StatusResponse{}, err
	}
	return resp, nil
}

// roundTrip sends req and reads its reply. An error reply from the agent
// leaves the connection usable; any other failure (write error, timeout,
// short or malformed frame, wrong reply type) retires it, because the
// stream can no longer be trusted to line up requests with replies.
func roundTrip(conn *Conn, req any, wantType string) ([]byte, error) {
	if conn.broken != nil {
		return nil, fmt.Errorf("%w: %w", errConnBroken, conn.broken)
	}
	raw, err := conn.exchange(req, wantType)
	var pe *ProtocolError
	if err != nil && !errors.As(err, &pe) {
		conn.broken = err
		closeOrLog(conn, "agent connection after transport failure")
	}
	return raw, err
}

func (c *Conn) exchange(req any, wantType string) (raw []byte, err error) {
	timeout := requestTimeout
	if wantType == TypeUnlockAck {
		timeout = unlockTimeout
	}
	if derr := c.uc.SetDeadline(time.Now().Add(timeout)); derr != nil {
		return nil, derr
	}
	defer func() {
		if derr := c.uc.SetDeadline(time.Time{}); derr != nil && err == nil {
			err = derr
		}
	}()

	if werr := writeJSON(c.uc, req); werr != nil {
		return nil, werr
	}
	var env envelope
	env, raw, err = readEnvelope(c.r)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", wantType, err)
	}
	switch env.Type {
	case wantType:
		return raw, nil
	case TypeError:
		var resp ErrorResponse
		if derr := decodeMessage(raw, &resp); derr != nil {
			return nil, derr
		}
		return nil, &ProtocolError{Code: resp.Code, Message: resp.Message}
	default:
		return nil, fmt.Errorf("unexpected response type %q", env.Type)
	}
}

// ErrTouchIDStale means a Touch ID file no longer unlocks its vault, for
// example after the master password changed. The file should be removed.
var ErrTouchIDStale = errors.New("the Touch ID unlock is out of date for this vault")

// TouchIDWrap asks an unlocked agent to wrap the key of vault unlockID to
// the Secure Enclave public key pub. The key itself never leaves the agent.
func TouchIDWrap(conn *Conn, unlockID string, pub []byte) (touchid.Wrapped, error) {
	raw, err := roundTrip(conn, TouchIDWrapRequest{
		Type:      TypeTouchIDWrap,
		Version:   ProtocolVersion,
		UnlockID:  unlockID,
		PublicKey: pub,
	}, TypeTouchIDWrapAck)
	if err != nil {
		return touchid.Wrapped{}, err
	}
	var resp TouchIDWrapResponse
	if err := decodeMessage(raw, &resp); err != nil {
		return touchid.Wrapped{}, err
	}
	return touchid.Wrapped{EphemeralPub: resp.EphemeralPub, Ciphertext: resp.Ciphertext}, nil
}

// UnlockTouchID asks the agent to unlock with the Touch ID file f for the
// vault whose sidecar verify blob is verify. The agent shows the Touch ID
// prompt; this waits up to the unlock timeout for the person to answer.
// Failures match touchid.ErrCancelled, ErrUnavailable, ErrLockedOut,
// ErrFailed, or ErrTouchIDStale.
func UnlockTouchID(conn *Conn, f *touchid.File, verify []byte) error {
	_, err := roundTrip(conn, UnlockTouchIDRequest{
		Type:         TypeUnlockTouchID,
		Version:      ProtocolVersion,
		KeyBlob:      f.KeyBlob,
		EphemeralPub: f.EphemeralPub,
		Ciphertext:   f.Ciphertext,
		Verify:       verify,
	}, TypeUnlockAck)
	var pe *ProtocolError
	if !errors.As(err, &pe) {
		return err
	}
	for code, sentinel := range map[string]error{
		ErrCodeTouchIDCancelled:   touchid.ErrCancelled,
		ErrCodeTouchIDUnavailable: touchid.ErrUnavailable,
		ErrCodeTouchIDLockedOut:   touchid.ErrLockedOut,
		ErrCodeTouchIDFailed:      touchid.ErrFailed,
		ErrCodeTouchIDStale:       ErrTouchIDStale,
	} {
		if pe.Code == code {
			return fmt.Errorf("%w (%w)", sentinel, pe)
		}
	}
	return err
}

// Lock asks the agent to drop its key now. Locking an agent that is
// already locked succeeds.
func Lock(conn *Conn) error {
	_, err := roundTrip(conn, LockRequest{Type: TypeLock, Version: ProtocolVersion}, TypeLockAck)
	return err
}

// Stop asks the agent to shut down. The agent replies only after it has
// shut down, so a nil error means it is gone: no listener, no socket
// file, key zeroed.
func Stop(conn *Conn) error {
	_, err := roundTrip(conn, StopRequest{Type: TypeStop, Version: ProtocolVersion}, TypeStopAck)
	return err
}
