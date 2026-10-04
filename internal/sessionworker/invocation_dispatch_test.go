//go:build linux || darwin

package sessionworker

import (
	"encoding/json"
	"testing"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

func TestInvocationDispatchAuthorityRejectsDualSourceAndRelabel(t *testing.T) {
	invocation := &transport.NativeInvocationSource{InvocationID: "remembered-invocation", InputAAD: e2ee.AAD{ObjectType: e2ee.ObjectTypeInvocationInput, ObjectID: "remembered-invocation", NetworkID: "network", KeyEpochID: "original-epoch"}}
	j, _ := testJournal(t)
	lease := lease(t, j)
	owner := dispatchOwnership(t, j, lease)
	proof := dispatchProof(owner, 1)
	proof.InvocationSource = invocation
	operation := Operation{Input: "original input", InputKind: "invocation", SourceInvocation: cloneNativeInvocationSource(invocation)}
	raw, _ := json.Marshal(operation)
	request := Request{Kind: "prompt", Payload: raw, NativeDispatch: &proof}
	prepared, err := prepareDispatchOperation(request)
	if err != nil {
		t.Fatal(err)
	}
	var accepted Operation
	if json.Unmarshal(prepared, &accepted) != nil || accepted.SourceCommandID != proof.SourceCommandID || accepted.SourceAdmissionID != proof.SourceAdmissionID || accepted.SourceInvocation.InvocationID != invocation.InvocationID || accepted.SourceTask != nil {
		t.Fatal("original invocation admission lost")
	}
	for _, mutation := range []string{"identity", "epoch", "object-type", "dual", "label", "resolve", "missing-authority"} {
		t.Run(mutation, func(t *testing.T) {
			p := proof
			p.InvocationSource = cloneNativeInvocationSource(invocation)
			op := operation
			op.SourceInvocation = cloneNativeInvocationSource(invocation)
			kind := "prompt"
			switch mutation {
			case "identity":
				op.SourceInvocation.InvocationID = "another"
			case "epoch":
				op.SourceInvocation.InputAAD.KeyEpochID = "new-epoch"
			case "object-type":
				p.InvocationSource.InputAAD.ObjectType = e2ee.ObjectTypeTask
			case "dual":
				p.TaskSource = &transport.NativeTaskSource{TaskID: "task", InputAAD: e2ee.AAD{ObjectType: e2ee.ObjectTypeTask, ObjectID: "task", NetworkID: "network", KeyEpochID: "epoch"}}
			case "label":
				op.InputKind = "task"
			case "resolve":
				kind = "resolve"
			case "missing-authority":
				p.InvocationSource = nil
			}
			payload, _ := json.Marshal(op)
			if _, err := prepareDispatchOperation(Request{Kind: kind, Payload: payload, NativeDispatch: &p}); err == nil {
				t.Fatal("invocation authority changed")
			}
		})
	}
}
