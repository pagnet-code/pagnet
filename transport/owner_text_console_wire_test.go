package transport

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/e2ee"
)

func TestOwnerTextConsolePayloadRoundTrip(t *testing.T) {
	data, err := os.ReadFile("../e2ee/testdata/owner_text_console_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Descriptor e2ee.OwnerTextConsoleDescriptor `json:"descriptor"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, payload := range []any{
		OwnerTextConsoleOpenPayload{OwnerTextConsoleProtocolV1, fixture.Descriptor},
		OwnerTextConsoleReadyPayload{OwnerTextConsoleProtocolV1, fixture.Descriptor, e2ee.OwnerTextConsoleBootstrap{Enc: make([]byte, 32), Ciphertext: make([]byte, 80), Signature: make([]byte, 64)}},
		OwnerTextConsoleFramePayload{OwnerTextConsoleProtocolV1, fixture.Descriptor.SessionID, 0, make([]byte, 16)},
		OwnerTextConsoleClosePayload{OwnerTextConsoleProtocolV1, fixture.Descriptor.SessionID},
	} {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		var target any
		switch payload.(type) {
		case OwnerTextConsoleOpenPayload:
			target = &OwnerTextConsoleOpenPayload{}
		case OwnerTextConsoleReadyPayload:
			target = &OwnerTextConsoleReadyPayload{}
		case OwnerTextConsoleFramePayload:
			target = &OwnerTextConsoleFramePayload{}
		case OwnerTextConsoleClosePayload:
			target = &OwnerTextConsoleClosePayload{}
		}
		if err := DecodeOwnerTextConsolePayload(raw, target); err != nil {
			t.Fatalf("%T: %v", payload, err)
		}
		if _, ok := payload.(OwnerTextConsoleReadyPayload); ok {
			for _, malformed := range []string{
				strings.Replace(string(raw), `"role":"sender"`, `"role":"sender","role":"sender"`, 1),
				strings.Replace(string(raw), `"role":"sender",`, "", 1),
				strings.Replace(string(raw), `"role":`, `"Role":`, 1),
				strings.Replace(string(raw), `"bootstrap":{`, `"bootstrap":{"extra":true,`, 1),
				strings.Replace(string(raw), `"enc":`, `"Enc":`, 1),
				strings.Replace(string(raw), `"ct":`, `"ct":"AA==","ct":`, 1),
				strings.Replace(string(raw), `"signature":`, `"signature":"AA==","Signature":`, 1),
			} {
				if err := DecodeOwnerTextConsolePayload([]byte(malformed), &OwnerTextConsoleReadyPayload{}); err == nil {
					t.Fatalf("accepted malformed nested payload: %s", malformed)
				}
			}
		}
	}
}

func TestDecodeOwnerTextConsolePayloadStrict(t *testing.T) {
	const valid = `{"protocol":"pagnet/owner-text-console/v1","sessionId":"session","sequence":0,"ciphertext":"AAAAAAAAAAAAAAAAAAAAAA=="}`
	for name, raw := range map[string]string{
		"empty":             "",
		"duplicate":         strings.Replace(valid, `"sequence":0`, `"sequence":0,"sequence":1`, 1),
		"missing zero":      strings.Replace(valid, `,"sequence":0`, "", 1),
		"unknown":           strings.Replace(valid, `"sequence":0`, `"sequence":0,"extra":1`, 1),
		"case alias":        strings.Replace(valid, `"sequence":`, `"Sequence":`, 1),
		"string sequence":   strings.Replace(valid, `"sequence":0`, `"sequence":"0"`, 1),
		"negative sequence": strings.Replace(valid, `"sequence":0`, `"sequence":-1`, 1),
		"base64 newline":    strings.Replace(valid, `AAAAAA==`, `AAAAAA\n==`, 1),
		"base64 pad bits":   strings.Replace(valid, `AAAAAA==`, `AAAAAB==`, 1),
		"trailing":          valid + `{}`,
		"null":              `null`,
		"oversize":          valid + strings.Repeat(" ", OwnerTextConsoleMaxWireBytes),
	} {
		t.Run(name, func(t *testing.T) {
			if err := DecodeOwnerTextConsolePayload([]byte(raw), &OwnerTextConsoleFramePayload{}); err == nil {
				t.Fatal("accepted malformed payload")
			}
		})
	}
	for _, raw := range []string{
		valid,
		` { "ciphertext":"AAAAAAAAAAAAAAAAAAAAAA==", "sequence":0,"sessionId":"session","protocol":"pagnet/owner-text-console/v1" } `,
		valid + strings.Repeat(" ", OwnerTextConsoleMaxWireBytes-len(valid)),
	} {
		if err := DecodeOwnerTextConsolePayload([]byte(raw), &OwnerTextConsoleFramePayload{}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOwnerTextConsoleFrameValidate(t *testing.T) {
	for _, size := range []int{16, 65552} {
		frame := OwnerTextConsoleFramePayload{OwnerTextConsoleProtocolV1, "session", (1 << 20) - 1, bytes.Repeat([]byte{1}, size)}
		if err := frame.Validate("session"); err != nil {
			t.Fatal(err)
		}
	}
	for _, frame := range []OwnerTextConsoleFramePayload{
		{OwnerTextConsoleProtocolV1, "session", 1 << 20, make([]byte, 16)},
		{OwnerTextConsoleProtocolV1, "session", 0, make([]byte, 15)},
		{OwnerTextConsoleProtocolV1, "session", 0, make([]byte, 65553)},
		{OwnerTextConsoleProtocol, "session", 0, make([]byte, 16)},
		{OwnerTextConsoleProtocolV1, "other", 0, make([]byte, 16)},
	} {
		if err := frame.Validate("session"); err == nil {
			t.Fatal("accepted invalid frame")
		}
	}
}
