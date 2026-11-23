package transport

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/fabric"
)

func TestNativeAccountJSONEnclosingRecords(t *testing.T) {
	source, aad, proof := accountContractFixtureFile(t, "account_message_source_reply_html_v1.json")
	endpoint, err := fabric.NewEndpointRef(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ref := NativeContentReference{ManifestAAD: aad}
	deletion := NativeOwnershipDeletionProof{StopProof: proof}
	ownership := NativeWorkerOwnership{DeletionProof: &deletion}
	records := []any{
		source,
		proof,
		ownership,
		deletion,
		NativeOwnershipRetirePayload{UnstartedStop: &proof},
		NativeOwnershipRegisteredPayload{Ownership: &ownership, UnstartedStop: &proof},
		NativeDispatchCancellationProposal{Proof: proof},
		NativeDispatchCancelProposedPayload{Proposals: []NativeDispatchCancellationProposal{{Proof: proof}}},
		NativeDispatchCancelledPayload{Proof: &proof},
		ref,
		NativeContentFragment{AAD: aad},
		NativeContentFragmentPage{Fragments: []NativeContentFragment{{AAD: aad}}},
		NativeContentDescriptor{Reference: ref},
		NativeTurnSourcePayload{OutputContent: &ref},
		InteractionEventPayload{DetailAAD: &aad, DetailContent: &ref},
		LaunchAgentPayload{NativeDispatch: &proof},
		WakeAgentPayload{NativeDispatch: &proof},
		StopAgentPayload{NativeDispatch: &proof},
		RestartAgentPayload{NativeDispatch: &proof},
		NetworkEventPayload{NativeDispatch: &proof},
		TerminalAttachPayload{NativeDispatch: &proof},
		TerminalStopPayload{NativeDispatch: &proof},
		ResolveRuntimeInteractionPayload{NativeDispatch: &proof},
		ForgetInstancePayload{NativeOwnership: &ownership, DeletionProof: &deletion},
		FabricHostedResult{Ref: endpoint, Proof: &proof},
	}
	for _, record := range records {
		t.Run(reflect.TypeOf(record).Name(), func(t *testing.T) {
			raw, err := MarshalNativeJSON(record)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(raw, []byte("<>&")) || bytes.Contains(raw, []byte(`\u003c`)) {
				t.Fatal("account contract escaped")
			}
			target := reflect.New(reflect.TypeOf(record)).Interface()
			if err = json.Unmarshal(raw, target); err != nil {
				t.Fatal("cannot recover", err)
			}
			again, err := MarshalNativeJSON(target)
			if err != nil || !bytes.Equal(raw, again) {
				t.Fatal("record bytes changed", err)
			}
		})
	}
}

func TestNativeAccountJSONEnvelope(t *testing.T) {
	_, aad, proof := accountContractFixtureFile(t, "account_message_source_reply_html_v1.json")
	for _, test := range []struct {
		kind    string
		payload any
	}{
		{MsgStopAgent, StopAgentPayload{NativeDispatch: &proof}},
		{MsgNativeContentBegin, NativeContentReference{ManifestAAD: aad}},
		{MsgRuntimeTurnOutput, NativeTurnSourcePayload{OutputContent: &NativeContentReference{ManifestAAD: aad}}},
		{MsgNativeContentFragment, NativeContentFragment{AAD: aad}},
		{MsgNativeDispatchCancelled, NativeDispatchCancelledPayload{Proof: &proof}},
		{MsgNativeOwnershipRegistered, NativeOwnershipRegisteredPayload{UnstartedStop: &proof}},
	} {
		t.Run(test.kind, func(t *testing.T) {
			env, err := NewEnvelope(test.kind, test.payload)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := MarshalNativeJSON(env)
			if err != nil {
				t.Fatal(err)
			}
			var recovered Envelope
			if err = json.Unmarshal(raw, &recovered); err != nil {
				t.Fatal(err)
			}
			target := reflect.New(reflect.TypeOf(test.payload)).Interface()
			if err = recovered.DecodePayload(target); err != nil {
				t.Fatal("outer envelope changed canonical payload", err)
			}
		})
	}
}

func TestNativeAccountJSONLegacyAndUnrelatedPayload(t *testing.T) {
	for _, record := range []any{NativeDispatchProof{SourceBootID: "legacy <>&"}, NativeDispatchProof{TaskSource: &NativeTaskSource{TaskID: "legacy <>&"}}, NativeDispatchProof{InvocationSource: &NativeInvocationSource{InvocationID: "legacy <>&"}}, NativeContentFragment{AAD: e2ee.AAD{Sender: "legacy <>&"}}, map[string]any{"accountMessageSource": map[string]string{"application": "<>&"}}} {
		expected, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := MarshalNativeJSON(record)
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatal("legacy bytes changed", err)
		}
	}
}

func TestNativeAccountJSONRejectsInvalidContracts(t *testing.T) {
	source, aad, proof := accountContractFixtureFile(t, "account_message_source_reply_html_v1.json")
	source.BindingDigest = "bad"
	proof.AccountMessageSource = &source
	malformed := aad
	malformed.BrowserAccountReply = nil
	invalid := aad
	invalid.Recipient = "other"
	for _, record := range []any{source, proof, NativeContentReference{ManifestAAD: malformed}, NativeContentFragment{AAD: invalid}} {
		if _, err := MarshalNativeJSON(record); err == nil {
			t.Fatal("invalid contract encoded")
		}
	}
}

func TestNativeAccountJSONEscapedQuotesAndUnicode(t *testing.T) {
	source, aad, _ := accountContractFixtureFile(t, "account_message_source_reply_html_v1.json")
	source.Descriptor.EpochID = "epoch <>& \"雪\u2028\u2029"
	source.BindingDigest = source.Descriptor.BindingDigest()
	source.InputAAD.KeyEpochID = source.Descriptor.EpochID
	source.InputAAD.BrowserAccountMessage.BindingDigest = source.BindingDigest
	aad.NativeContent.NativeGeneration = "generation <>& \"雪\u2028\u2029"
	for _, record := range []any{NativeDispatchProof{AccountMessageSource: &source}, NativeContentFragment{AAD: aad}} {
		raw, err := MarshalNativeJSON(record)
		if err != nil {
			t.Fatal(err)
		}
		target := reflect.New(reflect.TypeOf(record)).Interface()
		if err = json.Unmarshal(raw, target); err != nil {
			t.Fatal(err)
		}
		again, err := MarshalNativeJSON(target)
		if err != nil || !bytes.Equal(raw, again) {
			t.Fatal("escaped quote or Unicode changed", err)
		}
	}
}

func TestNativeAccountJSONRawEnvelopePayload(t *testing.T) {
	_, aad, proof := accountContractFixtureFile(t, "account_message_source_reply_html_v1.json")
	for _, test := range []struct {
		kind    string
		payload any
	}{
		{MsgStopAgent, StopAgentPayload{NativeDispatch: &proof}},
		{MsgNativeContentFragment, NativeContentFragment{AAD: aad}},
	} {
		canonical, err := MarshalNativeJSON(test.payload)
		if err != nil {
			t.Fatal(err)
		}
		for _, payload := range []any{json.RawMessage(canonical), func() *json.RawMessage { raw := json.RawMessage(canonical); return &raw }()} {
			envelope, err := NewEnvelope(test.kind, payload)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(envelope.Payload, canonical) {
				t.Fatal("raw payload canonical bytes changed")
			}
			raw, err := MarshalNativeJSON(envelope)
			if err != nil {
				t.Fatal(err)
			}
			var recovered Envelope
			if err = json.Unmarshal(raw, &recovered); err != nil {
				t.Fatal(err)
			}
			target := reflect.New(reflect.TypeOf(test.payload)).Interface()
			if err = recovered.DecodePayload(target); err != nil {
				t.Fatal(err)
			}
		}
	}
	legacy := json.RawMessage(`{"commandId":"legacy <>&"}`)
	expected, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := NewEnvelope(MsgStopAgent, legacy)
	if err != nil || !bytes.Equal(envelope.Payload, expected) {
		t.Fatal("legacy raw payload bytes changed", err)
	}
}
