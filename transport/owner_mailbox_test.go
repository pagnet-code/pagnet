package transport

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
)

func ownerMailboxWireDescriptor() e2ee.OwnerMailboxDescriptor {
	return e2ee.OwnerMailboxDescriptor{
		TenantID: "00000000-0000-4000-8000-000000000001", OwnerUserID: "00000000-0000-4000-8000-000000000002",
		InstallationID: "00000000-0000-4000-8000-000000000003", ServiceID: "00000000-0000-4000-8000-000000000004",
		HostID: "00000000-0000-4000-8000-000000000005", SessionID: "00000000-0000-4000-8000-000000000006",
		RunnerID: "00000000-0000-4000-8000-000000000007", HostCredentialID: "00000000-0000-4000-8000-000000000008",
		RunnerEpoch: time.Date(2026, 10, 22, 12, 34, 56, 0, time.UTC), Generation: 9007199254740993,
		BrowserX25519Pub: make([]byte, 32), HostX25519Pub: make([]byte, 32), HostEd25519Pub: make([]byte, 32),
		IssuedAtUnixSeconds: 1792672496, ExpiresAtUnixSeconds: 1792673396,
	}
}

func TestOwnerMailboxEnvelopeRoundTrip(t *testing.T) {
	descriptor := ownerMailboxWireDescriptor()
	tests := []struct {
		messageType string
		payload     any
	}{
		{MsgOwnerMailboxOpen, OwnerMailboxOpenPayload{Protocol: OwnerMailboxProtocolV1, Descriptor: descriptor}},
		{MsgOwnerMailboxReady, OwnerMailboxReadyPayload{
			Protocol: OwnerMailboxProtocolV1, Descriptor: descriptor,
			Bootstrap: e2ee.OwnerMailboxBootstrap{Enc: make([]byte, 32), Ciphertext: make([]byte, 80), Signature: make([]byte, 64)},
		}},
		{MsgOwnerMailboxOperation, OwnerMailboxOperationPayload{Protocol: OwnerMailboxProtocolV1, SessionID: descriptor.SessionID, RequestID: "request-1", Sequence: 0, Ciphertext: []byte{0, 255, 1}}},
		{MsgOwnerMailboxResult, OwnerMailboxResultPayload{Protocol: OwnerMailboxProtocolV1, SessionID: descriptor.SessionID, RequestID: "request-1", Sequence: 7, Ciphertext: []byte{2, 254, 3}}},
		{MsgOwnerMailboxClose, OwnerMailboxClosePayload{Protocol: OwnerMailboxProtocolV1, SessionID: descriptor.SessionID, Code: OwnerMailboxCloseClosed}},
	}
	seen := make(map[string]bool)
	for _, tt := range tests {
		t.Run(tt.messageType, func(t *testing.T) {
			if seen[tt.messageType] {
				t.Fatal("message types must be distinct")
			}
			seen[tt.messageType] = true
			envelope, err := NewEnvelope(tt.messageType, tt.payload)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			var received Envelope
			if err := json.Unmarshal(wire, &received); err != nil {
				t.Fatal(err)
			}
			if !received.IsVersionSupported() || received.Type != tt.messageType {
				t.Fatalf("envelope lost protocol or message type: %+v", received)
			}
			decoded := reflect.New(reflect.TypeOf(tt.payload))
			if err := received.DecodePayload(decoded.Interface()); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(decoded.Elem().Interface(), tt.payload) {
				t.Fatal("payload changed across envelope round trip")
			}
		})
	}
}

func TestOwnerMailboxDescriptorCanonicalJSON(t *testing.T) {
	descriptor := ownerMailboxWireDescriptor()
	want, err := e2ee.EncodeOwnerMailboxDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	open, err := json.Marshal(OwnerMailboxOpenPayload{Protocol: OwnerMailboxProtocolV1, Descriptor: descriptor})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(open, []byte(`"generation":"9007199254740993"`)) {
		t.Fatal("generation must preserve integers above 2^53 as decimal strings")
	}
	var decoded OwnerMailboxOpenPayload
	if err := json.Unmarshal(open, &decoded); err != nil {
		t.Fatal(err)
	}
	ready, err := json.Marshal(OwnerMailboxReadyPayload{Protocol: OwnerMailboxProtocolV1, Descriptor: decoded.Descriptor})
	if err != nil {
		t.Fatal(err)
	}
	var echoed OwnerMailboxReadyPayload
	if err := json.Unmarshal(ready, &echoed); err != nil {
		t.Fatal(err)
	}
	got, err := e2ee.EncodeOwnerMailboxDescriptor(echoed.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("open/ready JSON changed the authenticated canonical descriptor")
	}
	for _, invalid := range []string{`9007199254740993`, `"09007199254740993"`} {
		wire := bytes.Replace(open, []byte(`"9007199254740993"`), []byte(invalid), 1)
		if err := json.Unmarshal(wire, &decoded); err == nil {
			t.Fatalf("accepted noncanonical generation %s", invalid)
		}
	}
}

func TestOwnerMailboxFrameWireSize(t *testing.T) {
	if OwnerMailboxMaxWireBytes != 256*1024 || e2ee.OwnerMailboxMaxPlaintext != 64*1024 {
		t.Fatal("v1 wire or plaintext cap changed")
	}
	descriptor := ownerMailboxWireDescriptor()
	plaintext := make([]byte, e2ee.OwnerMailboxMaxPlaintext)
	ciphertext, err := e2ee.SealOwnerMailboxFrame(descriptor, make([]byte, 32), e2ee.OwnerMailboxClientToHost, 0, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := NewEnvelope(MsgOwnerMailboxOperation, OwnerMailboxOperationPayload{
		Protocol: OwnerMailboxProtocolV1, SessionID: descriptor.SessionID,
		RequestID: "00000000-0000-4000-8000-000000000009", Sequence: 0, Ciphertext: ciphertext,
	})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) <= len(ciphertext) || len(wire) > OwnerMailboxMaxWireBytes {
		t.Fatalf("base64 envelope size %d outside expected bounds", len(wire))
	}
	var payload struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := envelope.DecodePayload(&payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Ciphertext) != ((len(ciphertext)+2)/3)*4 {
		t.Fatal("ciphertext is not encoded as padded base64")
	}
	if _, err := e2ee.SealOwnerMailboxFrame(descriptor, make([]byte, 32), e2ee.OwnerMailboxClientToHost, 1, append(plaintext, 0)); err == nil {
		t.Fatal("wire allowance must not increase the crypto plaintext cap")
	}
}

func TestOwnerMailboxCloseCodes(t *testing.T) {
	for _, code := range []OwnerMailboxCloseCode{
		OwnerMailboxCloseClosed, OwnerMailboxCloseExpired, OwnerMailboxCloseRejected,
		OwnerMailboxCloseUnavailable, OwnerMailboxCloseProtocolError,
	} {
		if !code.IsValid() {
			t.Fatalf("v1 close code %q rejected", code)
		}
	}
	for _, code := range []OwnerMailboxCloseCode{"", "unknown", "private diagnostic text"} {
		if code.IsValid() {
			t.Fatalf("unknown close code %q accepted", code)
		}
	}
}

func TestOwnerMailboxSequenceCanonicalJSON(t *testing.T) {
	for _, payload := range []any{
		OwnerMailboxOperationPayload{Sequence: 7, Ciphertext: []byte{1}},
		OwnerMailboxResultPayload{Sequence: 7, Ciphertext: []byte{1}},
	} {
		wire, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(wire, []byte(`"sequence":"7"`)) {
			t.Fatal("sequence must be a decimal string")
		}
		decoded := reflect.New(reflect.TypeOf(payload)).Interface()
		if err := json.Unmarshal(wire, decoded); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(reflect.ValueOf(decoded).Elem().Interface(), payload) {
			t.Fatal("sequence changed across round trip")
		}
		for _, invalid := range []string{`7`, `"07"`, `"+7"`, `"-1"`, `"7.0"`, `""`, `null`, `"18446744073709551616"`} {
			bad := bytes.Replace(wire, []byte(`"sequence":"7"`), []byte(`"sequence":`+invalid), 1)
			if err := json.Unmarshal(bad, decoded); err == nil {
				t.Fatalf("accepted noncanonical sequence %s", invalid)
			}
		}
		unknown := bytes.Replace(wire, []byte(`"sequence":"7"`), []byte(`"sequence":"7","unexpected":true`), 1)
		if err := json.Unmarshal(unknown, decoded); err == nil {
			t.Fatal("custom sequence decoder bypassed strict field validation")
		}
	}
}
