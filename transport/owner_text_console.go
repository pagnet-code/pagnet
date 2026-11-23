package transport

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"

	"github.com/pagnet-code/pagnet/e2ee"
)

const (
	OwnerTextConsoleProtocolV1   = "pagnet/owner-text-console/v1"
	OwnerTextConsoleMaxWireBytes = 256 << 10

	MsgOwnerTextConsoleOpen  = "host.owner_text_console_open"
	MsgOwnerTextConsoleReady = "host.owner_text_console_ready"
	MsgOwnerTextConsoleFrame = "host.owner_text_console_frame"
	MsgOwnerTextConsoleClose = "host.owner_text_console_close"
)

type OwnerTextConsoleOpenPayload struct {
	Protocol   string                          `json:"protocol"`
	Descriptor e2ee.OwnerTextConsoleDescriptor `json:"descriptor"`
}

type OwnerTextConsoleReadyPayload struct {
	Protocol   string                          `json:"protocol"`
	Descriptor e2ee.OwnerTextConsoleDescriptor `json:"descriptor"`
	Bootstrap  e2ee.OwnerTextConsoleBootstrap  `json:"bootstrap"`
}

type OwnerTextConsoleFramePayload struct {
	Protocol   string `json:"protocol"`
	SessionID  string `json:"sessionId"`
	Sequence   uint64 `json:"sequence"`
	Ciphertext []byte `json:"ciphertext"`
}

type OwnerTextConsoleClosePayload struct {
	Protocol  string `json:"protocol"`
	SessionID string `json:"sessionId"`
}

// Validate checks the frame's wire bounds and its binding to the current session.
// Directional sequence and replay checks belong to the crypto session.
func (p OwnerTextConsoleFramePayload) Validate(sessionID string) error {
	if p.Protocol != OwnerTextConsoleProtocolV1 || p.SessionID != sessionID || p.Sequence >= e2ee.OwnerTextConsoleSequenceLimit || len(p.Ciphertext) < 16 || len(p.Ciphertext) > e2ee.OwnerTextConsoleMaxPlaintext+16 {
		return errors.New("transport: invalid owner text console frame")
	}
	return nil
}

// DecodeOwnerTextConsolePayload rejects duplicate names at every depth, missing,
// unknown and case-aliased fields, trailing values and noncanonical base64.
// Whitespace and object key order are unrestricted.
func DecodeOwnerTextConsolePayload(raw []byte, target any) error {
	invalid := errors.New("transport: invalid owner text console payload")
	if len(raw) == 0 || len(raw) > OwnerTextConsoleMaxWireBytes {
		return invalid
	}
	scan := json.NewDecoder(bytes.NewReader(raw))
	var value func() bool
	value = func() bool {
		token, err := scan.Token()
		if err != nil {
			return false
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return true
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for scan.More() {
				key, err := scan.Token()
				if err != nil {
					return false
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return false
				}
				seen[name] = true
				if !value() {
					return false
				}
			}
		case '[':
			for scan.More() {
				if !value() {
					return false
				}
			}
		default:
			return false
		}
		_, err = scan.Token()
		return err == nil
	}
	if !value() {
		return invalid
	}
	if _, err := scan.Token(); err != io.EOF {
		return invalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	canonical, err := json.Marshal(target)
	if err != nil {
		return err
	}
	var got, want any
	if json.Unmarshal(raw, &got) != nil || json.Unmarshal(canonical, &want) != nil || !reflect.DeepEqual(got, want) {
		return invalid
	}
	return nil
}
