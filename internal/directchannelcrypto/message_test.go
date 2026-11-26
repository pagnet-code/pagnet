package directchannelcrypto

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

func messageFixture(t *testing.T) (*Material, []byte, []byte, time.Time) {
	t.Helper()
	raw, err := os.ReadFile("testdata/sdk-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Descriptor, Publication, PeerPrivate []byte
		Now                                  string
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	defer clear(v.PeerPrivate)
	d, err := transport.DecodeDirectChannelDescriptorV2(v.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339Nano, v.Now)
	if err != nil {
		t.Fatal(err)
	}
	m, err := Accept(v.Publication, d, v.PeerPrivate, now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Clear)
	raw, err = os.ReadFile("testdata/sdk-message-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var messages struct{ Ask, Continuation []byte }
	if err := json.Unmarshal(raw, &messages); err != nil {
		t.Fatal(err)
	}
	return m, messages.Ask, messages.Continuation, now
}

// sdk-message-v2.json records synthetic ASK, REPLY, and continuation wires
// produced by the SDK implementation at fa58510 using sdk-v2.json material.
func TestMessageSDKVector(t *testing.T) {
	m, ask, _, now := messageFixture(t)
	a, _ := transport.DecodeDirectChannelMessageV2(ask)
	plaintext, err := m.OpenAsk(a.Header.MessageID, a.Header.RootID, ask, now)
	defer clear(plaintext)
	if err != nil || string(plaintext) != "question" {
		t.Fatal("SDK ASK incompatible")
	}
	reply, err := m.SealReply("33333333-3333-4333-8333-333333333333", a.Header.RootID, ask, []byte("answer"), now)
	if err != nil {
		t.Fatal(err)
	}
	r, err := transport.DecodeDirectChannelMessageV2(reply)
	if err != nil || transport.ValidateDirectChannelReplyToV2(r, a) != nil {
		t.Fatal("reply lost exact ASK binding")
	}
}

func TestMessageRejectsInvalidAsk(t *testing.T) {
	for _, mutation := range []string{"aad", "sender", "ciphertext", "continuation", "wrong-id", "wrong-root", "expired", "zero-time", "source-role"} {
		t.Run(mutation, func(t *testing.T) {
			m, ask, continuation, now := messageFixture(t)
			a, _ := transport.DecodeDirectChannelMessageV2(ask)
			id, root := a.Header.MessageID, a.Header.RootID
			switch mutation {
			case "aad":
				id = "22222222-2222-4222-8222-222222222222"
				root = id
				a.Header.MessageID, a.Header.RootID = id, root
			case "sender":
				a.Header.SenderRole = "P"
			case "ciphertext":
				ct, _ := binary(a.Ciphertext, -1)
				ct[0] ^= 1
				a.Ciphertext = b64(ct)
			case "continuation":
				ask = continuation
				a, _ = transport.DecodeDirectChannelMessageV2(ask)
				id, root = a.Header.MessageID, a.Header.RootID
			case "wrong-id":
				id = "22222222-2222-4222-8222-222222222222"
			case "wrong-root":
				root = "22222222-2222-4222-8222-222222222222"
			case "expired":
				now = now.Add(24 * time.Hour)
			case "zero-time":
				now = time.Time{}
			case "source-role":
				m.Role = "S"
			}
			// Marshal directly so invalid sender headers also reach the decoder.
			ask, _ = json.Marshal(a)
			if plaintext, err := m.OpenAsk(id, root, ask, now); err == nil || len(plaintext) != 0 {
				clear(plaintext)
				t.Fatal("invalid ASK opened")
			}
			if reply, err := m.SealReply("33333333-3333-4333-8333-333333333333", root, ask, []byte("answer"), now); mutation != "wrong-id" && (err == nil || len(reply) != 0) {
				t.Fatal("invalid ASK replied to")
			}
		})
	}
}
