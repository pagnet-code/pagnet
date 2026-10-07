package transport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/fabric"
)

// testFabricHostedPublication builds a fully valid publication: a domain ref
// derived from a real Ed25519 root key, a genuine sealed envelope and the
// bound routing AAD under a test epoch key — so Validate() exercises the
// real wire contract, not a fixture relaxation.
func testFabricHostedPublication(t *testing.T, tombstone bool) FabricHostedPublication {
	t.Helper()
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate domain key: %v", err)
	}
	ref, err := fabric.NewEndpointRef(pubKey)
	if err != nil {
		t.Fatalf("new endpoint ref: %v", err)
	}
	var epochKey [32]byte
	if _, err := rand.Read(epochKey[:]); err != nil {
		t.Fatalf("read epoch key: %v", err)
	}
	instanceID := domain.NewID().String()
	aad := e2ee.AAD{
		ProtocolVersion: ProtocolVersion,
		TenantID:        domain.NewID().String(),
		NetworkID:       domain.NewID().String(),
		ObjectType:      ObjectTypeFabricDescriptor,
		ObjectID:        ref.String(),
		Sender:          instanceID,
		Recipient:       ref.String(),
		CreatedAt:       "2026-10-06T00:00:00Z",
		KeyEpochID:      "epoch-tombstone-wire",
	}
	env, err := e2ee.Encrypt([]byte(`{"protocol":"pagnet.hosted.catalog.v1"}`), epochKey, aad)
	if err != nil {
		t.Fatalf("encrypt test body: %v", err)
	}
	return FabricHostedPublication{
		RequestID:           domain.NewID().String(),
		Ref:                 ref,
		Revision:            "rev-tombstone-wire",
		DomainPublicKey:     pubKey,
		Tombstone:           tombstone,
		NetworkID:           aad.NetworkID,
		InstanceID:          instanceID,
		OwnershipID:         domain.NewID().String(),
		OwnershipGeneration: "gen-1",
		Envelope:            env,
		AAD:                 aad,
	}
}

// TestFabricHostedPublicationTombstoneWireRoundTrip pins the publish wire
// contract for the additive flag: the flag rides the envelope without
// omitempty, a marshal/unmarshal round trip preserves it, and a payload
// from an old peer that never had the field parses to the zero value
// (live) and still validates — backward compatibility is the zero value.
func TestFabricHostedPublicationTombstoneWireRoundTrip(t *testing.T) {
	pub := testFabricHostedPublication(t, true)
	if err := pub.Validate(); err != nil {
		t.Fatalf("valid fixture publication refused: %v", err)
	}
	raw, err := json.Marshal(pub)
	if err != nil {
		t.Fatalf("marshal publication: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"tombstone":true`)) {
		t.Fatalf("flag is not on the wire (must not be omitempty): %s", raw)
	}
	var back FabricHostedPublication
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal publication: %v", err)
	}
	if !back.Tombstone {
		t.Fatal("flag lost in the marshal/unmarshal round trip")
	}
	if !reflect.DeepEqual(pub, back) {
		t.Fatal("round trip changed the publication")
	}

	// Old peer: a payload without the field (a pre-v0.9.0 publisher) must
	// parse to the zero value (live) and keep validating unchanged.
	var legacy map[string]json.RawMessage
	if err := json.Unmarshal(raw, &legacy); err != nil {
		t.Fatalf("re-decode to strip the field: %v", err)
	}
	delete(legacy, "tombstone")
	legacyRaw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy payload: %v", err)
	}
	var old FabricHostedPublication
	if err := json.Unmarshal(legacyRaw, &old); err != nil {
		t.Fatalf("unmarshal legacy payload: %v", err)
	}
	if old.Tombstone {
		t.Fatal("payload without the field must default to false (live), got a tombstone")
	}
	if err := old.Validate(); err != nil {
		t.Fatalf("legacy payload without the field no longer validates: %v", err)
	}
}
