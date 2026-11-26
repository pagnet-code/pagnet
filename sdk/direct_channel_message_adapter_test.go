package sdk

import (
	"testing"

	"github.com/pagnet-code/pagnet/transport"
)

func TestDirectMessageCryptoAdapterParity(t *testing.T) {
	s, p, _, now := directMaterials(t)
	defer s.clear()
	defer p.clear()
	peer := p.cryptoMaterial()
	defer peer.Clear()
	ask, err := s.seal("ASK", directTestAskID, directTestAskID, nil, []byte("question"), now)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := peer.OpenAsk(directTestAskID, directTestAskID, ask, now)
	defer clear(plaintext)
	if err != nil || string(plaintext) != "question" {
		t.Fatal("SDK ASK incompatible with adapter")
	}
	reply, err := peer.SealReply(directTestReplyID, directTestAskID, ask, []byte("answer"), now)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := s.open("REPLY", directTestReplyID, directTestAskID, ask, reply, now)
	defer clear(answer)
	if err != nil || string(answer) != "answer" {
		t.Fatal("adapter REPLY incompatible with SDK")
	}
	// A second valid ciphertext with the same ASK IDs is not the same ASK.
	other, err := s.seal("ASK", directTestAskID, directTestAskID, nil, []byte("question"), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.open("REPLY", directTestReplyID, directTestAskID, other, reply, now); err == nil {
		t.Fatal("reply accepted for another ASK ciphertext")
	}
	w, _ := transport.DecodeDirectChannelMessageV2(reply)
	a, _ := transport.DecodeDirectChannelMessageV2(ask)
	if transport.ValidateDirectChannelReplyToV2(w, a) != nil {
		t.Fatal("reply binding differs from SDK")
	}
}
