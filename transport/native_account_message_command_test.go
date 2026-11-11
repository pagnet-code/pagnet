package transport

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
)

func TestAccountMessageCommandCanonicalEnvelope(t *testing.T) {
	var vector struct {
		SourceCanonical string `json:"sourceCanonical"`
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "account_message_source_reply_html_v1.json"))
	if err != nil || json.Unmarshal(raw, &vector) != nil {
		t.Fatalf("source fixture: %v", err)
	}
	var source NativeAccountMessageSource
	if err := json.Unmarshal([]byte(vector.SourceCanonical), &source); err != nil {
		t.Fatal(err)
	}
	var sealed struct {
		Envelope e2ee.EncryptedPayloadV1 `json:"envelope"`
	}
	raw, err = os.ReadFile(filepath.Join("..", "internal", "accountmessage", "testdata", "account_message_v1.json"))
	if err != nil || json.Unmarshal(raw, &sealed) != nil {
		t.Fatalf("sealed fixture: %v", err)
	}
	epoch, err := time.Parse(time.RFC3339Nano, source.Descriptor.RunnerConnectedAt)
	if err != nil {
		t.Fatal(err)
	}
	p := AccountMessagePayload{CommandID: "original-command", InstanceID: source.Descriptor.TargetInstanceID,
		Envelope: sealed.Envelope, NativeDispatch: &NativeDispatchProof{AccountMessageSource: &source,
			OwnershipID: "owner", OwnershipGeneration: "generation", DispatchSequence: 1,
			SourceCommandID: "original-command", SourceAdmissionID: "admission", SourceRunnerID: source.Descriptor.RunnerID,
			SourceRunnerEpoch: epoch, SourceBootID: "boot"}}
	for _, value := range []any{p, json.RawMessage(mustAccountMessageCommandJSON(t, p))} {
		env, err := NewEnvelope(MsgAccountMessage, value)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(env.Payload, []byte("<>&")) || bytes.Contains(env.Payload, []byte(`\u003c`)) {
			t.Fatalf("account source was HTML escaped: %s", env.Payload)
		}
		encoded, err := MarshalNativeJSON(env)
		if err != nil {
			t.Fatal(err)
		}
		var decoded Envelope
		if err = json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		var got AccountMessagePayload
		if err = decoded.DecodePayload(&got); err != nil || got.NativeDispatch == nil || got.NativeDispatch.AccountMessageSource == nil || got.NativeDispatch.AccountMessageSource.Validate() != nil {
			t.Fatalf("round trip lost original source: %v", err)
		}
	}
}

func mustAccountMessageCommandJSON(t *testing.T, p AccountMessagePayload) []byte {
	t.Helper()
	raw, err := MarshalNativeJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
