package agent

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestWriteJSON_AppendsNewlineFraming(t *testing.T) {
	var buf bytes.Buffer
	if err := writeJSON(&buf, HelloRequest{Type: TypeHello, Version: ProtocolVersion}); err != nil {
		t.Fatalf("writeJSON: %v", err)
	}
	out := buf.Bytes()
	if len(out) == 0 || out[len(out)-1] != '\n' {
		t.Fatalf("writeJSON output not newline-terminated: %q", string(out))
	}
	if bytes.Count(out, []byte{'\n'}) != 1 {
		t.Fatalf("writeJSON output has %d newlines, want exactly 1: %q", bytes.Count(out, []byte{'\n'}), string(out))
	}
}

func TestReadEnvelope_DecodesTypeAndVersion(t *testing.T) {
	line := `{"type":"hello","version":1}` + "\n"
	r := bufio.NewReader(strings.NewReader(line))
	env, raw, err := readEnvelope(r)
	if err != nil {
		t.Fatalf("readEnvelope: %v", err)
	}
	if env.Type != TypeHello {
		t.Errorf("Type = %q, want %q", env.Type, TypeHello)
	}
	if env.Version != ProtocolVersion {
		t.Errorf("Version = %d, want %d", env.Version, ProtocolVersion)
	}
	if !bytes.HasPrefix(raw, []byte(`{"type"`)) {
		t.Errorf("raw line should preserve original bytes, got %q", string(raw))
	}
}

func TestReadEnvelope_ReturnsEOFOnCleanDisconnect(t *testing.T) {
	r := bufio.NewReader(strings.NewReader(""))
	_, _, err := readEnvelope(r)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("readEnvelope on empty input err = %v, want io.EOF", err)
	}
}

func TestReadEnvelope_TruncatedFrame_ReturnsError(t *testing.T) {
	r := bufio.NewReader(strings.NewReader(`{"type":"hello","version":1`))
	_, _, err := readEnvelope(r)
	if err == nil {
		t.Fatal("readEnvelope accepted a truncated frame")
	}
	if errors.Is(err, io.EOF) {
		t.Fatalf("truncated frame should not be reported as clean EOF, got %v", err)
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("truncated frame should wrap io.ErrUnexpectedEOF, got %v", err)
	}
}

func TestReadEnvelope_RejectsMalformedJSON(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("not json\n"))
	_, _, err := readEnvelope(r)
	if err == nil {
		t.Fatal("readEnvelope accepted malformed JSON")
	}
	if errors.Is(err, io.EOF) {
		t.Fatalf("malformed JSON err shouldn't be io.EOF, got %v", err)
	}
}

func TestRoundTrip_AllMessageTypes(t *testing.T) {
	cases := []any{
		HelloRequest{Type: TypeHello, Version: ProtocolVersion},
		HelloResponse{Type: TypeHelloAck, Version: ProtocolVersion, AgentPID: 12345},
		PingRequest{Type: TypePing, Version: ProtocolVersion},
		PingResponse{Type: TypePong, Version: ProtocolVersion},
		ErrorResponse{Type: TypeError, Version: ProtocolVersion, Code: ErrCodeUnknownMessageType, Message: "type \"banana\" not recognized"},
	}
	for _, msg := range cases {
		var buf bytes.Buffer
		if err := writeJSON(&buf, msg); err != nil {
			t.Errorf("writeJSON %T: %v", msg, err)
			continue
		}
		r := bufio.NewReader(&buf)
		env, raw, err := readEnvelope(r)
		if err != nil {
			t.Errorf("readEnvelope %T: %v", msg, err)
			continue
		}
		if env.Version != ProtocolVersion {
			t.Errorf("%T: round-tripped version = %d, want %d", msg, env.Version, ProtocolVersion)
		}
		switch msg.(type) {
		case HelloRequest:
			var got HelloRequest
			if err := decodeMessage(raw, &got); err != nil {
				t.Errorf("decode HelloRequest: %v", err)
			}
		case HelloResponse:
			var got HelloResponse
			if err := decodeMessage(raw, &got); err != nil {
				t.Errorf("decode HelloResponse: %v", err)
			} else if got.AgentPID != 12345 {
				t.Errorf("HelloResponse.AgentPID = %d, want 12345", got.AgentPID)
			}
		case PingRequest:
			var got PingRequest
			if err := decodeMessage(raw, &got); err != nil {
				t.Errorf("decode PingRequest: %v", err)
			}
		case PingResponse:
			var got PingResponse
			if err := decodeMessage(raw, &got); err != nil {
				t.Errorf("decode PingResponse: %v", err)
			}
		case ErrorResponse:
			var got ErrorResponse
			if err := decodeMessage(raw, &got); err != nil {
				t.Errorf("decode ErrorResponse: %v", err)
			} else if got.Code != ErrCodeUnknownMessageType {
				t.Errorf("ErrorResponse.Code = %q, want %q", got.Code, ErrCodeUnknownMessageType)
			}
		}
	}
}

func TestProtocolVersion_IsStable(t *testing.T) {
	// Bumping ProtocolVersion is intentional but must be a conscious
	// decision — this test makes the bump visible in code review.
	const expected = 1
	if ProtocolVersion != expected {
		t.Fatalf("ProtocolVersion changed to %d; if intentional, update this test and SESH_AGENT_PHASE_*_PLAN.md / SECURITY_MODEL.md as needed", ProtocolVersion)
	}
}
