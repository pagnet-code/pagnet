package sdk

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

func TestMessageDeliveryDecodesHumanAndTypedContentWithoutEmptyAcknowledgment(t *testing.T) {
	fs := newFakeServer(t)
	network := fs.createNetwork("content", true)
	recipient, credential := fs.createPrincipal("agent", "recipient", network)
	c := mustConnect(t, fs, credential, t.TempDir())
	waitForCryptoReady(t, fs, recipient)
	var got []MessagePart
	c.Agent("recipient").OnMessage(func(_ context.Context, m *Message) error { got = m.Parts; return nil })
	artifact := domain.ID("invoice")
	typed := []domain.MessagePart{domain.TextPart("hello"), {Kind: domain.MessagePartData, Data: json.RawMessage(`{"amount":42}`)}, {Kind: domain.MessagePartArtifact, ArtifactID: &artifact}}
	wrapped, err := domain.EncodeMessageContent(typed)
	if err != nil {
		t.Fatal(err)
	}
	legacy, _ := json.Marshal(typed)
	for _, content := range [][]byte{[]byte("human-console text"), legacy, wrapped} {
		id := domain.NewID().String()
		aad := fs.buildAAD(network, e2ee.ObjectTypeMessage, id, "human", recipient)
		encrypted, err := e2ee.Encrypt(content, fs.epochKey, aad)
		if err != nil {
			t.Fatal(err)
		}
		env, err := transport.NewEnvelope(transport.MsgEndpointMessageDeliver, transport.EndpointMessageDeliverPayload{MessageID: id, NetworkID: network, Kind: "ASK", Envelope: &encrypted, AAD: &aad})
		if err != nil {
			t.Fatal(err)
		}
		got = nil
		c.handleMessageDeliver(env)
		if len(got) == 0 || !c.seenDeliveries.Contains(id) {
			t.Fatal("valid message became empty/unprocessed")
		}
		if string(content) == "human-console text" {
			if got[0].Text == nil || *got[0].Text != string(content) {
				t.Fatal("human raw text lost")
			}
		} else if len(got) != 3 || got[1].Kind != domain.MessagePartData || got[2].ArtifactID == nil || *got[2].ArtifactID != artifact {
			t.Fatalf("typed parts lost: %+v", got)
		}
	}
	id := domain.NewID().String()
	aad := fs.buildAAD(network, e2ee.ObjectTypeMessage, id, "human", recipient)
	encrypted, err := e2ee.Encrypt([]byte(`{"pagnet_message_version":1,"parts":[]}`), fs.epochKey, aad)
	if err != nil {
		t.Fatal(err)
	}
	env, _ := transport.NewEnvelope(transport.MsgEndpointMessageDeliver, transport.EndpointMessageDeliverPayload{MessageID: id, NetworkID: network, Kind: "ASK", Envelope: &encrypted, AAD: &aad})
	got = nil
	c.handleMessageDeliver(env)
	if got != nil || c.seenDeliveries.Contains(id) {
		t.Fatal("malformed content handled/acknowledged as empty")
	}
	c.delivMu.Lock()
	_, inflight := c.inflightDeliveries[id]
	c.delivMu.Unlock()
	if inflight {
		t.Fatal("malformed content blocks durable retry")
	}
}
