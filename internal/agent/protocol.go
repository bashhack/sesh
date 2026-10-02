package agent

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ProtocolVersion is the on-wire schema version. A version mismatch
// between client and agent is fatal; both sides close the connection
// after writing/reading the error.
//
// Versioning rule: bump on any change that breaks the wire format
// (new required field, type change, removed message). Adding optional
// fields with omitempty does not require a bump.
const ProtocolVersion = 1

// Message-type sentinels. Centralised so the dispatch and the message
// structs can't drift apart.
const (
	TypeHello      = "hello"
	TypeHelloAck   = "hello_ack"
	TypePing       = "ping"
	TypePong       = "pong"
	TypeError      = "error"
	TypeUnlock     = "unlock"
	TypeUnlockAck  = "unlock_ack"
	TypeDecrypt    = "decrypt"
	TypeDecryptAck = "decrypt_ack"
	TypeEncrypt    = "encrypt"
	TypeEncryptAck = "encrypt_ack"
	TypeStatus     = "status"
	TypeStatusAck  = "status_ack"
	TypeLock       = "lock"
	TypeLockAck    = "lock_ack"
	TypeStop       = "stop"
	TypeStopAck    = "stop_ack"
)

// Error codes returned in ErrorResponse.Code. Strings (not ints) so they
// survive log greps and don't require a shared enum file.
const (
	ErrCodeProtocolVersionMismatch = "protocol_version_mismatch"
	ErrCodeUnknownMessageType      = "unknown_message_type"
	ErrCodePeerCredMismatch        = "peer_cred_mismatch"
	ErrCodeInternal                = "internal_error"
	ErrCodeWrongPassword           = "wrong_password"
	ErrCodeNotUnlocked             = "not_unlocked"
	ErrCodeDecryptFailed           = "decrypt_failed"
	ErrCodeUnlockMismatch          = "unlock_mismatch"
	ErrCodeBadRequest              = "bad_request"
)

// envelope is the shared shell every message wears. Used during
// dispatch to decide what to unmarshal into.
type envelope struct {
	Type    string `json:"type"`
	Version int    `json:"version"`
}

// HelloRequest is the mandatory first message on every connection. The
// agent rejects any other type as a first message.
type HelloRequest struct {
	Type    string `json:"type"`    // TypeHello
	Version int    `json:"version"` // ProtocolVersion
}

// HelloResponse is the agent's reply to a successful handshake. AgentPID
// is informational — useful for status / debugging, not security-critical.
type HelloResponse struct {
	Type string `json:"type"` // TypeHelloAck
	// AgentBuild is the agent's Build, so a client from another sesh
	// build can replace it. Empty from agents that predate it.
	AgentBuild string `json:"agent_build,omitempty"`
	Version    int    `json:"version"`   // server's ProtocolVersion
	AgentPID   int    `json:"agent_pid"` // os.Getpid() of the agent
}

// PingRequest is a liveness check with no payload. The agent replies
// with PingResponse.
type PingRequest struct {
	Type    string `json:"type"`    // TypePing
	Version int    `json:"version"` // ProtocolVersion
}

// PingResponse is the agent's reply to a Ping.
type PingResponse struct {
	Type    string `json:"type"` // TypePong
	Version int    `json:"version"`
}

// UnlockRequest asks the agent to derive and cache the master key.
// Password is raw bytes; the agent zeroes it after derivation. A second
// unlock while already unlocked re-derives, so a password change does
// not need a separate lock round-trip.
type UnlockRequest struct {
	Type     string    `json:"type"`
	Password []byte    `json:"password"`
	Salt     []byte    `json:"salt"`
	Verify   []byte    `json:"verify"`
	Params   KDFParams `json:"params"`
	Version  int       `json:"version"`
}

// KDFParams is the Argon2id parameter set on the wire. It is a separate
// type so the protocol does not change when database.Argon2idParams does;
// the two convert directly, and a field added to either breaks that
// conversion at compile time instead of dropping silently.
type KDFParams struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
	KeyLen  uint32 `json:"key_len"`
}

// UnlockResponse acknowledges a successful unlock. The derived key stays
// in the agent.
type UnlockResponse struct {
	Type    string `json:"type"`
	Version int    `json:"version"`
}

// DecryptRequest opens one entry ciphertext. Salt is the per-entry salt
// stored beside the ciphertext; both stay separate so the database schema
// does not change. UnlockID is the verify-blob id the caller was built
// for; the agent rejects the request when its cached key is a different one.
type DecryptRequest struct {
	Type       string `json:"type"`
	UnlockID   string `json:"unlock_id"`
	Ciphertext []byte `json:"ciphertext"`
	Salt       []byte `json:"salt"`
	Version    int    `json:"version"`
}

// DecryptResponse carries the opened plaintext.
type DecryptResponse struct {
	Type      string `json:"type"`
	Plaintext []byte `json:"plaintext"`
	Version   int    `json:"version"`
}

// EncryptRequest seals one plaintext. The agent generates the per-entry salt.
// UnlockID is the verify-blob id the caller was built for.
type EncryptRequest struct {
	Type      string `json:"type"`
	UnlockID  string `json:"unlock_id"`
	Plaintext []byte `json:"plaintext"`
	Version   int    `json:"version"`
}

// EncryptResponse returns the ciphertext and the per-entry salt.
type EncryptResponse struct {
	Type       string `json:"type"`
	Ciphertext []byte `json:"ciphertext"`
	Salt       []byte `json:"salt"`
	Version    int    `json:"version"`
}

// StatusRequest asks whether the agent currently holds a key.
type StatusRequest struct {
	Type    string `json:"type"`
	Version int    `json:"version"`
}

// StatusResponse reports lock state and the auto-lock schedule. UnlockID
// is the hex SHA-256 of the verify blob the cached key was checked
// against, empty when locked. Callers compare it to the sidecar so a
// rotated password is not served with the previous key. Times are Unix
// seconds; 0 means "not applicable". LocksAtUnix is the earlier of the
// idle and max-lifetime deadlines. A timeout of 0 means disabled.
type StatusResponse struct {
	Type             string `json:"type"`
	UnlockID         string `json:"unlock_id,omitempty"`
	AgentBuild       string `json:"agent_build,omitempty"`
	Version          int    `json:"version"`
	AgentPID         int    `json:"agent_pid"`
	AgentStartedUnix int64  `json:"agent_started_unix"`
	UnlockedAtUnix   int64  `json:"unlocked_at_unix,omitempty"`
	LastActivityUnix int64  `json:"last_activity_unix,omitempty"`
	LastUnlockUnix   int64  `json:"last_unlock_unix,omitempty"`
	LocksAtUnix      int64  `json:"locks_at_unix,omitempty"`
	IdleTimeoutSec   int64  `json:"idle_timeout_sec"`
	MaxLifetimeSec   int64  `json:"max_lifetime_sec"`
	Unlocked         bool   `json:"unlocked"`
}

// LockRequest drops the cached key without stopping the agent. Later
// encrypt and decrypt requests get not_unlocked until the next unlock.
// Locking an already-locked agent succeeds.
type LockRequest struct {
	Type    string `json:"type"`
	Version int    `json:"version"`
}

// LockResponse acknowledges a lock.
type LockResponse struct {
	Type    string `json:"type"`
	Version int    `json:"version"`
}

// StopRequest shuts the agent down, like SIGTERM, through the socket so
// callers don't need the agent's pid. The agent stops, then replies.
type StopRequest struct {
	Type    string `json:"type"`
	Version int    `json:"version"`
}

// StopResponse acknowledges a stop. It is sent after the agent has shut
// down, so the agent is gone by the time the client reads it.
type StopResponse struct {
	Type    string `json:"type"`
	Version int    `json:"version"`
}

// ErrorResponse is returned in place of any expected response when the
// request can't be served. Code is machine-readable; Message is for the
// log file / human eyes.
type ErrorResponse struct {
	Type    string `json:"type"` // TypeError
	Code    string `json:"code"`
	Message string `json:"message"`
	Version int    `json:"version"`
	// AgentPID is set on protocol_version_mismatch, so a client that can't
	// talk to this agent can still tell the user which process to stop.
	AgentPID int `json:"agent_pid,omitempty"`
}

// writeJSON marshals v and writes it as one line (no embedded newline)
// followed by '\n' so the peer's bufio.ReadString('\n') frames cleanly.
func writeJSON(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal %T: %w", v, err)
	}
	if _, err := w.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("write %T: %w", v, err)
	}
	return nil
}

// maxFrameSize is the largest newline-terminated message the agent will
// buffer. A peer that never sends a newline cannot grow the process
// without bound. It must carry a database.MaxSecretSize secret after
// base64 (4/3 expansion) plus the JSON envelope.
const maxFrameSize = 4 << 20 // 4 MiB

// errFrameTooLarge means a peer sent more than maxFrameSize bytes
// without a newline.
var errFrameTooLarge = errors.New("frame exceeds size limit")

// readEnvelope reads one newline-terminated JSON message from r and
// decodes only its envelope (type + version). Callers then unmarshal
// the raw line into the concrete request struct via decodeMessage.
//
// io.EOF (peer closed cleanly with no partial frame) is returned
// unwrapped so callers can distinguish "normal disconnect" from
// "truncated frame" / "malformed input."
func readEnvelope(r *bufio.Reader) (env envelope, raw []byte, err error) {
	var line []byte
	for {
		// ReadSlice returns at most one buffer's worth per call, and the
		// check runs before appending, so a frame never grows past the limit.
		// A peer that stops mid-buffer without a newline is only caught once
		// it sends more; the memory bound holds either way.
		chunk, rerr := r.ReadSlice('\n')
		body := len(line) + len(chunk)
		if rerr == nil {
			body-- // the terminator does not count toward the limit
		}
		if body > maxFrameSize {
			return envelope{}, nil, fmt.Errorf("%w of %d bytes", errFrameTooLarge, maxFrameSize)
		}
		line = append(line, chunk...)
		if rerr == nil {
			break
		}
		if errors.Is(rerr, bufio.ErrBufferFull) {
			continue
		}
		// A partial line and EOF is a protocol violation, not a clean
		// disconnect. Wrap ErrUnexpectedEOF so isCleanDisconnect keeps
		// it on the error path.
		if errors.Is(rerr, io.EOF) && len(line) > 0 {
			return envelope{}, line, fmt.Errorf("truncated frame (%d bytes, no terminator): %w", len(line), io.ErrUnexpectedEOF)
		}
		return envelope{}, nil, rerr
	}
	// The line includes the terminator; json.Unmarshal ignores trailing
	// whitespace, so we don't trim.
	if err := json.Unmarshal(line, &env); err != nil {
		return envelope{}, line, fmt.Errorf("parse envelope: %w", err)
	}
	return env, line, nil
}

// decodeMessage unmarshals raw (a previously-read message line) into
// dst. Used by the dispatch after readEnvelope tells us which concrete
// type to expect.
func decodeMessage(raw []byte, dst any) error {
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("parse %T: %w", dst, err)
	}
	return nil
}
