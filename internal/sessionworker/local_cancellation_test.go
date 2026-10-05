//go:build linux || darwin

package sessionworker

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	fabricidentity "github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
)

func TestLocalExpiredCancellationAfterRenameRetainsOriginalSource(t *testing.T) {
	f := newLocalAuthorityFixture(t)
	ctx := context.Background()
	binder := nativeauthority.JSONPromptBinder{ProfileDigest: f.binding.Worker.ProfileDigest}
	c, err := nativeauthority.NewLocalController(f.authority, f.owner, f.binding, binder)
	if err != nil {
		t.Fatal(err)
	}
	// Construct and initialize the real persistent journal BEFORE issuing the
	// finite invocation deadline. Filesystem setup is not an admitted invocation
	// and must not consume the fixture's intentionally short execution lifetime.
	j, err := OpenAuthorityJournal(filepath.Join(t.TempDir(), "worker"), f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	lease, err := j.AdvanceLease(ctx)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().UTC().Add(time.Second)
	envelope := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "expired-original", Operation: fabric.OperationInvoke, Principal: f.owner.PrincipalView(), Source: f.owner.PrincipalView().Ref, Target: &f.binding.Scope.Endpoint, ExpectedRevision: f.binding.Scope.DescriptorRevision, CreatedAt: time.Now().UTC(), Payload: json.RawMessage(`{"input":"original exact prompt"}`), Context: fabric.EnvelopeContext{Origin: f.owner.PrincipalView().Ref, Deadline: &deadline}}
	raw, _ := json.Marshal(envelope)
	caller, err := fabric.NewAuthenticatedContext(f.owner.PrincipalView(), f.authority.Identity().Namespace, raw)
	if err != nil {
		t.Fatal(err)
	}
	source, err := f.authority.Admit(ctx, f.owner, f.controller, f.binding, caller, raw, raw, "cancel-source-A", "attempt", "replay")
	if err != nil {
		t.Fatal(err)
	}
	var accepted nativeauthority.VerifiedIntent
	_, err = c.AdmitIntent(ctx, f.controller, source, caller, raw, raw, func(ctx context.Context, i nativeauthority.VerifiedIntent) (fabricidentity.NativeIntentReceipt, error) {
		accepted = i
		_, r, _, e := j.AdmitLocal(ctx, lease, binder, i)
		return r, e
	})
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := f.store.GetEndpoint(ctx, f.binding.Scope.Endpoint, f.binding.Scope.DescriptorRevision)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.Name = "Renamed without changing physical ownership"
	descriptor.Revision = ""
	rev, err := f.store.Update(ctx, f.owner, fabric.RegistryUpdate{Descriptor: descriptor, ExpectedRevision: f.binding.Scope.DescriptorRevision})
	if err != nil {
		t.Fatal(err)
	}
	nextScope := f.binding.Scope
	nextScope.DescriptorRevision = rev
	B, err := f.authority.AcquireController(ctx, f.owner, nextScope, f.controller.Epoch(), "cancel-B-request", "cancel-B")
	if err != nil {
		t.Fatal(err)
	}
	bindingB, err := f.authority.RenewWorkerBinding(ctx, f.owner, B, f.binding)
	if err != nil {
		t.Fatal(err)
	}
	cB, err := nativeauthority.NewLocalControllerForOwnership(f.authority, f.owner, f.scope, bindingB, binder)
	if err != nil {
		t.Fatal(err)
	}
	<-time.NewTimer(time.Until(deadline) + time.Millisecond).C
	cancelIntent, err := cB.CancellationIntent(B, f.binding, source, accepted.Reservation, raw)
	if err != nil {
		t.Fatal("expired source cannot be stopped", err)
	}
	if _, err = cancelIntent.Request().Verify(f.scope, binder); err == nil {
		t.Fatal("historical cancellation became fresh invocation")
	}
	verified, err := cancelIntent.Request().VerifyCancellation(f.scope, binder)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.requestLocalCancellation(ctx, lease, binder, verified); err != nil {
		t.Fatal(err)
	}
	if yes, err := j.localCancellationRequested(accepted.Commitment.Sequence); err != nil || !yes {
		t.Fatal(err)
	}
	if err = j.requestLocalCancellation(ctx, lease, binder, accepted); !errors.Is(err, ErrFenced) {
		t.Fatal("stale A control accepted", err)
	}
	out, err := j.Outcome(ctx, accepted.Commitment.Sequence)
	if err != nil || out.State != "admitted" || out.LocalSource.Admission.ID != source.ID || out.LocalSource.Binding.Scope != f.binding.Scope {
		t.Fatal("stop rewrote effect or source", err)
	}
	// These phase-boundary cases deliberately have no driver: an unscheduled
	// admitted operation, or an older operation while a different source owns
	// the runtime, must not create any endpoint-stop goroutine/barrier.
	for _, phase := range []struct {
		owned   bool
		current int64
	}{{false, accepted.Commitment.Sequence}, {true, accepted.Commitment.Sequence + 1}} {
		operationCtx, operationCancel := context.WithCancel(ctx)
		pending := &nativeOwnedOperation{ctx: operationCtx, cancel: operationCancel, done: make(chan struct{}), nativeOwned: phase.owned}
		owner := &SessionOwner{ctx: ctx, journal: j, operations: map[int64]*nativeOwnedOperation{accepted.Commitment.Sequence: pending}, candidateTurnSource: NativeTurnSource{Sequence: phase.current}}
		if err = owner.CancelLocalInvocation(ctx, lease, binder, verified); err != nil {
			t.Fatal(err)
		}
		if owner.lastStopDone != nil || operationCtx.Err() != context.Canceled {
			t.Fatal("unrelated or unscheduled source reached endpoint stop")
		}
		operationCancel()
	}
	changed := cancelIntent
	changed.Finalized = json.RawMessage(`{}`)
	if nativeauthority.ValidateCancellationIntent(f.scope, binder, changed) == nil {
		t.Fatal("changed original final envelope accepted")
	}
}
