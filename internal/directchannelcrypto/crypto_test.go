package directchannelcrypto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

// This synthetic vector was recorded from SDK f08607b before extraction.
func TestSDKVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/sdk-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Descriptor, Publication                            []byte
		SourcePrivate, PeerPrivate, EpochKey, ReadinessKey []byte
		Challenges, Proofs                                 [][]byte
		Now                                                string
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	d, err := transport.DecodeDirectChannelDescriptorV2(v.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339Nano, v.Now)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := Accept(v.Publication, d, v.PeerPrivate, now)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Clear()
	if !bytes.Equal(peer.Key[:], v.EpochKey) {
		t.Fatal("epoch key differs from SDK vector")
	}
	source := *peer
	source.Role = "S"
	defer source.Clear()
	for i, m := range []*Material{&source, peer} {
		key, err := m.ReadinessKey()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(key, v.ReadinessKey) {
			t.Fatal("readiness key differs from SDK vector")
		}
		clear(key)
		c, err := transport.DecodeDirectChannelReadinessChallengeV2(v.Challenges[i])
		if err != nil {
			t.Fatal(err)
		}
		proof, err := m.ReadinessProof(v.Challenges[i], c.CredentialID, now)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(proof, v.Proofs[i]) {
			t.Fatal("proof differs from SDK vector")
		}
		if _, err = m.ReadinessProof(v.Challenges[i], c.CredentialID, now.Add(time.Hour)); err == nil {
			t.Fatal("expired challenge accepted")
		}
	}
	// A fresh Prepare publication must unwrap with the exact old SDK HPKE context.
	prepared, wire, err := Prepare(v.Descriptor, d, v.SourcePrivate, now)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Clear()
	publication, err := transport.DecodeDirectChannelPublicationV2(wire)
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := binary(publication.Enc, 32)
	ct, _ := binary(publication.Ciphertext, 48)
	sender, _ := binary(d.S.PublicKey, 32)
	key, err := e2ee.HPKEUnwrapAuth(v.PeerPrivate, sender, enc, []byte(transport.DirectChannelDomainV2+"/epoch-wrap"), prepared.Hash[:], ct)
	defer clear(key)
	if err != nil || !bytes.Equal(key, prepared.Key[:]) {
		t.Fatal("prepared publication is incompatible with SDK HPKE context")
	}
}

func TestMaterialClearAndRedaction(t *testing.T) {
	m := Material{Key: [32]byte{1, 2, 3}}
	for _, value := range []any{m, &m} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%x"} {
			if got := fmt.Sprintf(format, value); !strings.Contains(got, "REDACTED") {
				t.Fatal("format does not redact material")
			}
		}
		raw, err := json.Marshal(value)
		if err != nil || string(raw) != "{}" {
			t.Fatal("material serialized")
		}
	}
	m.Clear()
	if m.Key != ([32]byte{}) {
		t.Fatal("epoch key was not cleared")
	}
}
