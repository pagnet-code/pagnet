package transport

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
)

func TestManagedEndpointPoPFailureACK(t *testing.T) {
	id := domain.ID("abcdef01-0000-4000-8000-000000000001")
	failure := ManagedEndpointPoPFailureACK{ManagedEndpointPoPProtocol, id, ManagedEndpointPoPFailure}
	raw, err := failure.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"protocolVersion":"managed_endpoint_host_custody_pop_v1","challengeId":"abcdef01-0000-4000-8000-000000000001","error":"managed_endpoint_pop_failed"}`
	if string(raw) != want {
		t.Fatalf("failure wire = %s", raw)
	}
	decoded, err := DecodeManagedEndpointPoPFailureACK(raw, id)
	if err != nil || decoded != failure {
		t.Fatal("failure round trip", err)
	}
	if _, err := DecodeManagedEndpointPoPProof(raw); err == nil {
		t.Fatal("failure accepted as proof")
	}
	for name, bad := range map[string][]byte{
		"duplicate":  bytes.Replace(raw, []byte(`"error":`), []byte(`"error":"managed_endpoint_pop_failed","error":`), 1),
		"unknown":    append([]byte(`{"unknown":null,`), raw[1:]...),
		"missing":    []byte(`{"protocolVersion":"managed_endpoint_host_custody_pop_v1","challengeId":"` + string(id) + `"}`),
		"protocol":   bytes.Replace(raw, []byte(ManagedEndpointPoPProtocol), []byte(ManagedEndpointPrepareProtocol), 1),
		"diagnostic": bytes.Replace(raw, []byte(ManagedEndpointPoPFailure), []byte("arbitrary diagnostic"), 1),
		"null":       bytes.Replace(raw, []byte(`"managed_endpoint_pop_failed"`), []byte(`null`), 1),
		"id-case":    bytes.Replace(raw, []byte(id), []byte(strings.ToUpper(string(id))), 1),
		"id-zero":    bytes.Replace(raw, []byte(id), []byte("00000000-0000-0000-0000-000000000000"), 1),
		"id-short":   bytes.Replace(raw, []byte(id), []byte("abcdef01"), 1),
		"utf8":       bytes.Replace(raw, []byte(ManagedEndpointPoPFailure), []byte{0xff}, 1),
		"surrogate":  bytes.Replace(raw, []byte(ManagedEndpointPoPFailure), []byte(`\ud800`), 1),
		"whitespace": append([]byte(" "), raw...),
		"trailing":   append(append([]byte(nil), raw...), []byte("{}")...),
		"escaped":    bytes.Replace(raw, []byte("challengeId"), []byte(`challenge\u0049d`), 1),
		"case-field": bytes.Replace(raw, []byte("challengeId"), []byte("ChallengeId"), 1),
		"order":      []byte(`{"error":"managed_endpoint_pop_failed","challengeId":"` + string(id) + `","protocolVersion":"managed_endpoint_host_custody_pop_v1"}`),
		"size":       bytes.Repeat([]byte(" "), 1025),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeManagedEndpointPoPFailureACK(bad, id); err == nil {
				t.Fatal("accepted malformed failure")
			}
		})
	}
	for _, expected := range []domain.ID{domain.NewID(), "", domain.ID(strings.ToUpper(string(id)))} {
		if _, err := DecodeManagedEndpointPoPFailureACK(raw, expected); err == nil {
			t.Fatal("accepted mismatched challenge ID")
		}
	}
}

func TestManagedEndpointPoPCommandWire(t *testing.T) {
	if MsgManagedEndpointPoP != "host.managed_endpoint_pop" {
		t.Fatal("PoP message type changed")
	}
	challenge, _, _ := managedPoPFixture(t)
	raw, err := challenge.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := NewEnvelope(MsgManagedEndpointPoP, challenge)
	if err != nil || envelope.Type != MsgManagedEndpointPoP || !bytes.Equal(envelope.Payload, raw) {
		t.Fatal("challenge must be the direct command payload", err)
	}
	if _, err := DecodeManagedEndpointPoPChallenge(envelope.Payload); err != nil {
		t.Fatal(err)
	}
	wrapped, err := json.Marshal(struct {
		Challenge ManagedEndpointPoPChallenge `json:"challenge"`
	}{challenge})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeManagedEndpointPoPChallenge(wrapped); err == nil {
		t.Fatal("accepted nested challenge wrapper")
	}
}
