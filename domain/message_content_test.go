package domain

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestProtectedMessageContentCompatibility(t *testing.T) {
	artifact := ID("artifact")
	parts := []MessagePart{TextPart("hello <world>"), {Kind: MessagePartData, Data: json.RawMessage(`{"amount":42}`)}, {Kind: MessagePartArtifact, ArtifactID: &artifact}}
	encoded, err := EncodeMessageContent(parts)
	if err != nil {
		t.Fatal(err)
	}
	var oldReceiver []MessagePart
	if err := json.Unmarshal(encoded, &oldReceiver); err != nil || !reflect.DeepEqual(parts, oldReceiver) {
		t.Fatal("new sender is incompatible with deployed SDK part-array readers")
	}
	got, err := DecodeMessageContent(encoded)
	if err != nil || !reflect.DeepEqual(parts, got) {
		t.Fatalf("typed roundtrip = %+v, %v", got, err)
	}
	if text := RenderMessageParts(got); !strings.Contains(text, "amount") || !strings.Contains(text, "Message artifact: artifact") {
		t.Fatalf("typed parts lost: %s", text)
	}
	legacy, _ := json.Marshal(parts)
	got, err = DecodeMessageContent(legacy)
	if err != nil || !reflect.DeepEqual(got, parts) {
		t.Fatal("legacy SDK parts unreadable")
	}
	for _, literal := range []string{"human text", string(legacy), `{"pagnet_message_version":99}`, `[]`} {
		wrapped, err := EncodeMessageContent([]MessagePart{TextPart(literal)})
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeMessageContent(wrapped)
		if err != nil || len(decoded) != 1 || decoded[0].Text == nil || *decoded[0].Text != literal {
			t.Fatalf("literal JSON changed: %s %+v %v", literal, decoded, err)
		}
	}
	got, err = DecodeMessageContent([]byte("legacy human text"))
	if err != nil || RenderMessageParts(got) != "legacy human text" {
		t.Fatal("legacy raw text unreadable")
	}
	for _, invalid := range []string{`{"pagnet_message_version":2,"parts":[{"kind":"text","text":"x"}]}`, `{"pagnet_message_version":1,"parts":[]}`, `{"pagnet_message_version":1,"parts":[{"kind":"text"}]}`, `{"pagnet_message_version":1,"parts":[{"kind":"unknown","text":"x"}]}`, ""} {
		if got, err := DecodeMessageContent([]byte(invalid)); err == nil || got != nil {
			t.Fatalf("invalid content accepted: %s", invalid)
		}
	}
}
