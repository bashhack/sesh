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
	TypeHello    = "hello"
	TypeHelloAck = "hello_ack"
	TypePing     = "ping"
	TypePong     = "pong"
	TypeError    = "error"
)

// Error codes returned in ErrorResponse.Code. Strings (not ints) so they
// survive log greps and don't require a shared enum file.
const (
	ErrCodeProtocolVersionMismatch = "protocol_version_mismatch"
	ErrCodeUnknownMessageType      = "unknown_message_type"
	ErrCodePeerCredMismatch        = "peer_cred_mismatch"
	ErrCodeInternal                = "internal_error"
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
	Type     string `json:"type"`      // TypeHelloAck
	Version  int    `json:"version"`   // server's ProtocolVersion
	AgentPID int    `json:"agent_pid"` // os.Getpid() of the agent
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

// ErrorResponse is returned in place of any expected response when the
// request can't be served. Code is machine-readable; Message is for the
// log file / human eyes.
type ErrorResponse struct {
	Type    string `json:"type"` // TypeError
	Code    string `json:"code"`
	Message string `json:"message"`
	Version int    `json:"version"`
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

// readEnvelope reads one newline-terminated JSON message from r and
// decodes only its envelope (type + version). Callers then unmarshal
// the raw line into the concrete request struct via decodeMessage.
//
// io.EOF (peer closed cleanly with no partial frame) is returned
// unwrapped so callers can distinguish "normal disconnect" from
// "truncated frame" / "malformed input."
func readEnvelope(r *bufio.Reader) (env envelope, raw []byte, err error) {
	line, err := r.ReadBytes('\n')
	if err != nil {
		// bufio returns (partial-data, io.EOF) when the peer closed
		// mid-frame. Partial data with no terminator is a protocol
		// violation, not a clean disconnect — surface as a wrapped
		// ErrUnexpectedEOF so isCleanDisconnect routes it correctly.
		if errors.Is(err, io.EOF) && len(line) > 0 {
			return envelope{}, line, fmt.Errorf("truncated frame (%d bytes, no terminator): %w", len(line), io.ErrUnexpectedEOF)
		}
		return envelope{}, nil, err
	}
	// ReadBytes includes the terminator; json.Unmarshal handles it fine
	// (trailing whitespace is ignored), so we don't trim.
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
