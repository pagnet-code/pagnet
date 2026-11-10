package sessionworker

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/pagnet-code/pagnet/domain"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

func accountMessageContractSource(t *testing.T) transport.NativeAccountMessageSource {
	t.Helper()
	raw, err := os.ReadFile("../../transport/testdata/account_message_source_reply_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct{ SourceCanonical string }
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var s transport.NativeAccountMessageSource
	if err = json.Unmarshal([]byte(v.SourceCanonical), &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAccountMessageContractFencesExecution(t *testing.T) {
	source := accountMessageContractSource(t)
	if err := new(Journal).BindNativeTurn(context.Background(), NativeTurnSource{SourceAccountMessage: &source, InputKind: "account_message"}); !errors.Is(err, ErrFenced) {
		t.Fatal("account native binding enabled", err)
	}
	for _, kind := range []string{"prompt", "activate", "resolve"} {
		p := transport.NativeDispatchProof{AccountMessageSource: &source}
		op := Operation{Input: "private input", InputKind: "account_message", SourceAccountMessage: &source}
		raw, _ := json.Marshal(op)
		if _, err := prepareDispatchOperation(Request{Kind: kind, Payload: raw, NativeDispatch: &p}); err == nil {
			t.Fatal("account execution enabled", kind)
		}
	}
}

func TestAccountMessageContractDigestAndMixedSources(t *testing.T) {
	source := accountMessageContractSource(t)
	turn := NativeTurnSource{SourceAccountMessage: &source, InputKind: "account_message"}
	original, err := observationDigest(NativeObservation{TurnSource: &turn})
	if err != nil {
		t.Fatal(err)
	}
	if sourceContentDescriptor(&turn) == "" {
		t.Fatal("missing account source descriptor")
	}
	source.SealedDigest = strings.Repeat("b", 64)
	changed, err := observationDigest(NativeObservation{TurnSource: &turn})
	if err != nil || changed == original {
		t.Fatal("source omitted from digest", err)
	}
	turn.SourceTask = &transport.NativeTaskSource{}
	if sourceContentDescriptor(&turn) != "" {
		t.Fatal("mixed source descriptor accepted")
	}
}

func TestAccountMessageContractCancellationUnion(t *testing.T) {
	source := accountMessageContractSource(t)
	id := func() string { return domain.NewID().String() }
	scope := Scope{InstanceID: id(), Generation: "generation"}
	p := transport.NativeDispatchProof{AccountMessageSource: &source, OwnershipID: id(), OwnershipGeneration: scope.Generation, DispatchSequence: 1, SourceCommandID: id(), SourceAdmissionID: id(), SourceRunnerID: id(), SourceRunnerEpoch: time.Now().UTC(), SourceBootID: id()}
	record := DispatchCancellationPreparation{State: "prepared", Proposal: transport.NativeDispatchCancellationProposal{InstanceID: scope.InstanceID, CommandType: "host.agent_input", Reason: "expired", Proof: p}, Request: transport.NativeDispatchCancelPayload{RequestID: id(), PreparationID: id(), InstanceID: scope.InstanceID, OwnershipID: p.OwnershipID, OwnershipGeneration: p.OwnershipGeneration, DispatchSequence: p.DispatchSequence, SourceCommandID: p.SourceCommandID, SourceAdmissionID: p.SourceAdmissionID}}
	if !validCancellationPreparation(scope, record) {
		t.Fatal("valid account cancellation rejected")
	}
	record.Proposal.Proof.TaskSource = &transport.NativeTaskSource{}
	if validCancellationPreparation(scope, record) {
		t.Fatal("mixed cancellation source accepted")
	}
}

func TestAccountMessageContractPreservesLegacyTaskSource(t *testing.T) {
	// Existing task inputs without a descriptor remain a legacy exception.
	raw, _ := json.Marshal(Operation{Input: "legacy task", InputKind: "task"})
	if _, err := prepareDispatchOperation(Request{Kind: "prompt", Payload: raw, NativeDispatch: &transport.NativeDispatchProof{}}); err != nil {
		t.Fatal(err)
	}
}
