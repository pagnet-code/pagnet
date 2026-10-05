//go:build linux || darwin

package fabricnative

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/node/dispatch"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

type offerFixtureBinding struct{ rig *adapterRig }

func (b offerFixtureBinding) Select(_ context.Context, _ fabric.ExecutionContext, endpoint fabric.EndpointDescriptor, _ *fabric.OfferDescriptor) (dispatch.Selection, error) {
	return dispatch.Selection{BindingID: "native", EndpointRevision: endpoint.Revision, Fingerprint: b.rig.resolver.handle.Binding.Worker.ProfileDigest, Adapter: b.rig.adapter}, nil
}

type offerFixtureDispatchFence struct{}

func (offerFixtureDispatchFence) WithDispatch(ctx context.Context, _ fabric.ExecutionContext, _, _ []byte, _ fabric.EndpointDescriptor, _ *fabric.OfferDescriptor, _ dispatch.Selection, next func(context.Context) (fabric.InvocationStream, error)) (fabric.InvocationStream, error) {
	return next(ctx)
}

func TestActualNativeOfferNodePreservesTargetSchemaAndOriginalSource(t *testing.T) {
	r := actualAdapterRigWithProfile(t, nativeauthority.InputBindingJSONV1)
	ref, err := r.endpoint.Ref.WithOfferID(bytes.Repeat([]byte{23}, 32))
	if err != nil {
		t.Fatal(err)
	}
	schema := json.RawMessage(`{"type":"object","properties":{"judgment":{"enum":["yes","no"]}},"required":["judgment"],"additionalProperties":false}`)
	revision, err := r.store.PutOffer(r.ctx, r.owner, fabric.OfferDescriptor{Ref: ref, Name: "Typed judgment", BindingID: "native", InputSchema: schema}, "")
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := dispatch.New(dispatch.Config{Audience: r.store.Namespace(), Descriptors: r.store, Bindings: offerFixtureBinding{r}, Admission: offerFixtureDispatchFence{}})
	if err != nil {
		t.Fatal(err)
	}
	index, err := r.store.LoadIndex(r.ctx, search.Config{})
	if err != nil {
		t.Fatal(err)
	}
	batch, err := r.store.PendingIndex(r.ctx, 32)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := index.Prepare(r.ctx, batch)
	if err != nil {
		t.Fatal(err)
	}
	if err = index.Publish(r.ctx, prepared, r.store.CommitIndex); err != nil {
		t.Fatal(err)
	}
	service, err := node.New(node.Config{Audience: r.store.Namespace(), Authenticator: adapterAuthenticator{r.owner.PrincipalView()}, Dispatcher: dispatcher, Descriptors: r.store, Search: index})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().UTC().Add(30 * time.Second)
	envelope := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "actual-native-offer", Operation: fabric.OperationInvoke, Principal: r.owner.PrincipalView(), Source: r.owner.PrincipalView().Ref, Target: &ref, ExpectedRevision: revision, CreatedAt: time.Now().UTC(), Payload: json.RawMessage("{\n\"judgment\":\"yes\"\n}"), Context: fabric.EnvelopeContext{Origin: r.owner.PrincipalView().Ref, Deadline: &deadline}}
	discovery := envelope
	discovery.ID = "discover-native-offer"
	discovery.Operation = fabric.OperationDiscover
	discovery.Target = nil
	discovery.ExpectedRevision = ""
	discovery.Payload = json.RawMessage(`{"query":"Typed judgment","limit":10}`)
	discoveryBytes, _ := json.Marshal(discovery)
	discovered, err := service.Execute(r.ctx, discoveryBytes, "actual trusted fixture owner")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, candidate := range discovered.Discover.Candidates {
		found = found || candidate.Document.Ref == ref
	}
	if !found {
		t.Fatal("actual registered offer not discoverable")
	}
	description := discovery
	description.ID = "describe-native-offer"
	description.Operation = fabric.OperationDescribe
	description.Payload, _ = json.Marshal(fabric.DescribeRequest{Selections: []fabric.DescribeSelection{{Ref: ref, ExpectedRevision: revision}}})
	describeBytes, _ := json.Marshal(description)
	described, err := service.Execute(r.ctx, describeBytes, "actual trusted fixture owner")
	if err != nil || described.Describe == nil || len(described.Describe.Descriptions) != 1 || described.Describe.Descriptions[0].Offer == nil || !bytes.Equal(described.Describe.Descriptions[0].Offer.InputSchema, schema) {
		t.Fatal("same node describe lost selected offer/schema", err)
	}
	exact, _ := json.Marshal(envelope)
	bad := envelope
	bad.ID = "invalid-native-offer"
	bad.Payload = json.RawMessage(`{"judgment":"maybe"}`)
	invalid, _ := json.Marshal(bad)
	if _, err = service.Execute(r.ctx, invalid, "actual trusted fixture owner"); err == nil {
		t.Fatal("invalid registered offer input admitted")
	}
	state, err := r.resolver.handle.Client.Call(r.ctx, sessionworker.LocalRequest{Type: "snapshot"})
	if err != nil || state.Snapshot == nil || state.Snapshot.PID != 0 {
		t.Fatal("schema rejection started native effect", err)
	}
	result, err := service.Execute(r.ctx, exact, "actual trusted fixture owner")
	if err != nil {
		t.Fatal(err)
	}
	saved, _, err := r.adapter.config.Checkpoints.Load(r.ctx, r.owner.PrincipalView(), envelope.ID)
	if err != nil || !bytes.Equal(saved.Original, exact) || saved.Admission.Target != ref || saved.Admission.TargetRevision != revision || saved.Admission.Scope.Endpoint != r.endpoint.Ref {
		t.Fatal("offer rewritten or source provenance lost", err)
	}
	var output bytes.Buffer
	for {
		frame, err := result.Stream.Next(r.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if frame.Kind == fabric.FrameError {
			t.Fatal(frame.Error)
		}
		if frame.Kind == fabric.FrameChunk {
			output.Write(frame.Data)
		}
		if frame.Kind == fabric.FrameComplete {
			break
		}
	}
	if !bytes.Contains(output.Bytes(), []byte("judgment")) {
		t.Fatal("structured prompt data not delivered to genuine parser")
	}
	if err = result.Stream.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = r.store.RetireOffer(r.ctx, r.owner, ref, revision); err != nil {
		t.Fatal(err)
	}
	restored, err := r.authority.RestoreOriginalCaller(r.ctx, r.owner, saved.Admission, saved.Original, saved.Finalized)
	if err != nil || restored.PrincipalView() != r.owner.PrincipalView() {
		t.Fatal("retired selected offer erased original authenticated history", err)
	}
	envelope.ID = "retired-new-invoke"
	retired, _ := json.Marshal(envelope)
	if _, err = service.Execute(r.ctx, retired, "actual trusted fixture owner"); err == nil {
		t.Fatal("retired offer authorized new effect")
	}
}

func TestActualNativeOfferRetiredHistoryControllerRestartCancelsOriginalSource(t *testing.T) {
	r := actualAdapterRigWithProfile(t, nativeauthority.InputBindingJSONV1, false, true)
	ref, _ := r.endpoint.Ref.WithOfferID(bytes.Repeat([]byte{24}, 32))
	revision, err := r.store.PutOffer(r.ctx, r.owner, fabric.OfferDescriptor{Ref: ref, Name: "Held original", BindingID: "native", InputSchema: json.RawMessage(`{"type":"object"}`)}, "")
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := dispatch.New(dispatch.Config{Audience: r.store.Namespace(), Descriptors: r.store, Bindings: offerFixtureBinding{r}, Admission: offerFixtureDispatchFence{}})
	if err != nil {
		t.Fatal(err)
	}
	service, err := node.New(node.Config{Audience: r.store.Namespace(), Authenticator: adapterAuthenticator{r.owner.PrincipalView()}, Dispatcher: dispatcher})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().UTC().Add(30 * time.Second)
	env := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "offer-held-original", Operation: fabric.OperationInvoke, Principal: r.owner.PrincipalView(), Source: r.owner.PrincipalView().Ref, Target: &ref, ExpectedRevision: revision, CreatedAt: time.Now().UTC(), Payload: json.RawMessage(`{"work":"hold permission"}`), Context: fabric.EnvelopeContext{Origin: r.owner.PrincipalView().Ref, Deadline: &deadline}}
	original, _ := json.Marshal(env)
	result, err := service.Execute(r.ctx, original, "actual trusted fixture owner")
	if err != nil {
		t.Fatal(err)
	}
	if frame, err := result.Stream.Next(r.ctx); err != nil || frame.Kind != fabric.FrameStart {
		t.Fatal("no authentic paid start", err)
	}
	old := r.resolver.handle
	saved, _, err := r.adapter.config.Checkpoints.Load(r.ctx, r.owner.PrincipalView(), env.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.store.RetireOffer(r.ctx, r.owner, ref, revision); err != nil {
		t.Fatal(err)
	}
	renamed := r.endpoint
	renamed.Name = "Same native worker renamed"
	renamed.Revision = ""
	currentRevision, err := r.store.Update(r.ctx, r.owner, fabric.RegistryUpdate{Descriptor: renamed, ExpectedRevision: r.endpoint.Revision})
	if err != nil {
		t.Fatal(err)
	}
	currentScope := old.Current.Scope
	currentScope.DescriptorRevision = currentRevision
	B, err := r.authority.AcquireController(r.ctx, r.owner, currentScope, old.Current.Epoch(), "offer-restart-B", "offer-restart-B")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := r.authority.RenewWorkerBinding(r.ctx, r.owner, B, old.Binding)
	if err != nil {
		t.Fatal(err)
	}
	client, err := sessionworker.DialLocal(r.ctx, old.Directory, old.Ownership, old.ControlKey, "offer-controller-B")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	r.resolver.handle = WorkerHandle{InputBindingProfile: old.InputBindingProfile, Current: B, Binding: binding, Ownership: old.Ownership, Directory: old.Directory, ControlKey: old.ControlKey, Client: client}
	restarted, err := NewAdapter(r.adapter.config)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := restarted.Recover(r.ctx, r.owner, r.owner.PrincipalView(), env.ID)
	if err != nil {
		t.Fatal("retired selected offer history not recoverable", err)
	}
	if frame, err := recovered.Next(r.ctx); err != nil || frame.Kind != fabric.FrameStart {
		t.Fatal("retained genuine original start missing", err)
	}
	if err = recovered.Close(); err != nil {
		t.Fatal("original offer source stop denied after rename/retire", err)
	}
	stopCtx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
	defer cancel()
	for {
		snapshot, err := client.Call(stopCtx, sessionworker.LocalRequest{Type: "snapshot"})
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.Snapshot != nil && snapshot.Snapshot.PID == 0 {
			break
		}
		select {
		case <-stopCtx.Done():
			t.Fatal("original native process not joined")
		case <-time.After(25 * time.Millisecond):
		}
	}
	checkpoint, _, err := r.adapter.config.Checkpoints.Load(r.ctx, r.owner.PrincipalView(), env.ID)
	if err != nil || !bytes.Equal(checkpoint.Original, original) || checkpoint.Admission.Target != saved.Admission.Target || checkpoint.Admission.OriginalControllerEpoch != saved.Admission.OriginalControllerEpoch {
		t.Fatal("controller takeover rewrote original selected source", err)
	}
}
