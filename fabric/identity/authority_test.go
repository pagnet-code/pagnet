package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

var localOwner = fabric.Principal{Ref: "spiffe://offline/owner", Kind: "local.owner", Issuer: "pinned.local.test"}

type ownerFence struct {
	owner  fabric.Principal
	reject bool
	called int
	mu     sync.Mutex
}

func (f *ownerFence) WithAdmission(_ context.Context, facts AdmissionFacts, commit func(Witness) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.called++
	if f.reject || facts.OriginalCaller != f.owner {
		return fabric.NewError(fabric.CodeUnauthenticated, "Current local admission denied")
	}
	return commit(Witness{Version: "owner-trust.v1", FinalizedDigest: facts.FinalizedDigest, Value: json.RawMessage(`{"ownerVerified":true}`)})
}

type nativeFixture struct {
	store *registry.Store
	a     *Authority
	owner fabric.ExecutionContext
	scope Scope
	dir   string
	fence *ownerFence
}

func fixture(t *testing.T) nativeFixture {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "domain")
	s, e := registry.Bootstrap(context.Background(), dir, localOwner)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	owner, e := fabric.NewAuthenticatedContext(localOwner, s.Namespace(), []byte("authenticated owner setup"))
	if e != nil {
		t.Fatal(e)
	}
	ref, e := fabric.NewEndpointRef(s.AuthorityIdentity().PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	rev, e := s.Register(context.Background(), owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "agent.local", Name: "Offline", Description: "Local native", Bindings: []fabric.BindingSummary{{ID: "native", Protocol: "local.native", Version: "1"}}}})
	if e != nil {
		t.Fatal(e)
	}
	f := &ownerFence{owner: localOwner}
	a, e := New(s, f)
	if e != nil {
		t.Fatal(e)
	}
	return nativeFixture{s, a, owner, Scope{ref, rev, "native"}, dir, f}
}
func (f nativeFixture) controller(t *testing.T, expected uint64, id string) Controller {
	t.Helper()
	c, e := f.a.AcquireController(context.Background(), f.owner, f.scope, expected, id, "controller-"+id)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func (f nativeFixture) binding(t *testing.T, c Controller) Binding {
	t.Helper()
	b, e := f.a.BindWorker(context.Background(), f.owner, c, 0, WorkerBinding{WorkerID: "worker-1", StateDirectoryID: "random-state-dir-1", OwnershipGeneration: "owned-generation-1", ActualRuntime: "fake-persistent", ProfileDigest: sha256.Sum256([]byte("verified executable profile"))})
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func (f nativeFixture) invocation(t *testing.T) (fabric.ExecutionContext, []byte, []byte) {
	t.Helper()
	deadline := time.Now().UTC().Add(time.Hour)
	env := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "native-invoke-1", Operation: fabric.OperationInvoke, Principal: localOwner, Source: localOwner.Ref, Target: &f.scope.Endpoint, ExpectedRevision: f.scope.DescriptorRevision, CreatedAt: time.Now().UTC(), Payload: json.RawMessage(`{"text":"original"}`), Context: fabric.EnvelopeContext{Origin: localOwner.Ref, Deadline: &deadline}}
	original, _ := json.Marshal(env)
	caller, e := fabric.NewAuthenticatedContext(localOwner, f.store.Namespace(), original)
	if e != nil {
		t.Fatal(e)
	}
	env.Payload = json.RawMessage(`{"text":"finalized"}`)
	finalized, _ := json.Marshal(env)
	return caller, original, finalized
}
func TestOfflineAuthorityControllerRetryNoEpochResurrectionAndRestart(t *testing.T) {
	f := fixture(t)
	cA := f.controller(t, 0, "A")
	cB := f.controller(t, cA.Epoch(), "B")
	again, e := f.a.AcquireController(context.Background(), f.owner, f.scope, 0, "A", "controller-A")
	if e != nil || again.Epoch() != cA.Epoch() {
		t.Fatal("old ambiguous retry advanced epoch", e)
	}
	if _, e = f.a.AcquireController(context.Background(), f.owner, f.scope, cB.Epoch(), "A", "changed"); e == nil {
		t.Fatal("same request identity rebound")
	}
	if _, e = f.a.BindWorker(context.Background(), f.owner, again, 0, WorkerBinding{WorkerID: "worker", StateDirectoryID: "state", OwnershipGeneration: "generation", ActualRuntime: "fake-persistent", ProfileDigest: sha256.Sum256([]byte("profile"))}); e == nil {
		t.Fatal("original A retry authorized new effects under B")
	}
	root := f.a.Identity()
	if e = f.store.Close(); e != nil {
		t.Fatal(e)
	}
	opened, e := registry.Open(context.Background(), f.dir)
	if e != nil {
		t.Fatal(e)
	}
	defer opened.Close()
	a, e := New(opened, f.fence)
	if e != nil {
		t.Fatal(e)
	}
	again, e = a.AcquireController(context.Background(), f.owner, f.scope, 0, "A", "controller-A")
	if e != nil || again.Epoch() != cA.Epoch() || a.Identity().StoreID != root.StoreID {
		t.Fatal("restart replaced original control proof", e)
	}
}
func TestOfflineAdmissionAndOriginPreserveAUnderBThenRetireWithHistory(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	cA := f.controller(t, 0, "A")
	binding := f.binding(t, cA)
	caller, original, final := f.invocation(t)
	admission, e := f.a.Admit(ctx, f.owner, cA, binding, caller, original, final, "admission-1", "attempt-1", "replay-1")
	if e != nil {
		t.Fatal(e)
	}
	callerFrame, _ := admission.CallerFrame.SigningBytes()
	dispatchFrame, _ := admission.DispatchFrame.SigningBytes()
	if !ed25519.Verify(f.a.Identity().PublicKey, callerFrame, admission.CallerSignature) || !ed25519.Verify(f.a.Identity().PublicKey, dispatchFrame, admission.DispatchSignature) {
		t.Fatal("exact original/final authority proof invalid")
	}
	cB := f.controller(t, cA.Epoch(), "B")
	retry, e := f.a.Admit(ctx, f.owner, cB, binding, caller, original, final, "admission-1", "attempt-1", "replay-1")
	if e != nil || retry.OriginalControllerEpoch != cA.Epoch() {
		t.Fatal("rebound original source admission", e)
	}
	origin, e := f.a.RegisterOrigin(ctx, f.owner, cB, binding, admission, caller, original, final, "origin-1", "actual-generation-1")
	if e != nil {
		t.Fatal(e)
	}
	if origin.OriginalControllerEpoch != cA.Epoch() || origin.RegisteredControllerEpoch != cB.Epoch() {
		t.Fatal("source vs current epochs mixed")
	}
	if _, e = f.a.RegisterOrigin(ctx, f.owner, cA, binding, admission, caller, original, final, "origin-2", "generation-2"); e == nil {
		t.Fatal("stale controller actuated original source")
	}
	if _, e = f.a.RegisterOrigin(ctx, f.owner, cB, binding, admission, caller, original, final, "origin-1", "changed-generation"); e == nil {
		t.Fatal("rebound original native generation")
	}
	if _, e = f.a.RetireOrigin(ctx, f.owner, origin, "genuine-source-reaped"); e != nil {
		t.Fatal(e)
	}
	if _, e = f.a.RegisterOrigin(ctx, f.owner, cB, binding, admission, caller, original, final, "origin-1", "actual-generation-1"); e == nil {
		t.Fatal("retired native origin resurrected")
	}
	if _, e = f.store.Retire(ctx, f.owner, f.scope.Endpoint, f.scope.DescriptorRevision); e != nil {
		t.Fatal(e)
	}
	outcome := SourceOutcome{OriginID: origin.ID, NativeGeneration: origin.NativeGeneration, NativeSessionID: "actual-session-1", SourceID: "source-1", CiphertextCommitment: sha256.Sum256([]byte("retained encrypted source")), Effect: fabric.EffectUnknown}
	receipt, e := f.a.CommitSource(ctx, f.owner, origin, outcome)
	if e != nil {
		t.Fatal("historical source lost after retirement", e)
	}
	exact, e := f.a.CommitSource(ctx, f.owner, origin, outcome)
	if e != nil || exact.Sequence != receipt.Sequence {
		t.Fatal("historical exact retry duplicated", e)
	}
	outcome.Effect = fabric.EffectCompleted
	if _, e = f.a.CommitSource(ctx, f.owner, origin, outcome); e == nil {
		t.Fatal("changed source outcome overwrote first truth")
	}
	if e = f.store.Close(); e != nil {
		t.Fatal(e)
	}
	s, e := registry.Open(ctx, f.dir)
	if e != nil {
		t.Fatal("signed local source readback", e)
	}
	defer s.Close()
}
func TestOfflineAdmissionWrongAudienceIssuerRevocationAndMutableProofDenied(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	c := f.controller(t, 0, "A")
	b := f.binding(t, c)
	caller, original, final := f.invocation(t)
	wrong, _ := fabric.NewAuthenticatedContext(localOwner, "another-domain", original)
	if _, e := f.a.Admit(ctx, f.owner, c, b, wrong, original, final, "a", "attempt", "replay"); e == nil {
		t.Fatal("caller audience self-check accepted foreign node")
	}
	if f.fence.called != 0 {
		t.Fatal("foreign context reached external fence")
	}
	var env fabric.Envelope
	json.Unmarshal(original, &env)
	env.Principal.Issuer = "foreign.issuer"
	changed, _ := json.Marshal(env)
	foreign, _ := fabric.NewAuthenticatedContext(env.Principal, f.store.Namespace(), changed)
	env.Payload = json.RawMessage(`{"text":"final"}`)
	foreignFinal, _ := json.Marshal(env)
	if _, e := f.a.Admit(ctx, f.owner, c, b, foreign, changed, foreignFinal, "a", "attempt", "replay"); e == nil {
		t.Fatal("unpinned caller issuer accepted by configured fence")
	}
	fake := c
	fake.ControllerID = "forged public wrapper"
	if _, e := f.a.Admit(ctx, f.owner, fake, b, caller, original, final, "a", "attempt", "replay"); e == nil {
		t.Fatal("public context wrapper treated as authentication")
	}
	f.fence.reject = true
	if _, e := f.a.Admit(ctx, f.owner, c, b, caller, original, final, "a", "attempt", "replay"); e == nil {
		t.Fatal("current revocation ignored")
	}
	f.fence.reject = false
	a, e := f.a.Admit(ctx, f.owner, c, b, caller, original, final, "a", "attempt", "replay")
	if e != nil {
		t.Fatal(e)
	}
	env.Principal = localOwner
	env.Source = localOwner.Ref
	env.Payload = json.RawMessage(`{"text":"changed-final"}`)
	newFinal, _ := json.Marshal(env)
	if _, e = f.a.Admit(ctx, f.owner, c, b, caller, original, newFinal, "a", "attempt", "replay"); e == nil {
		t.Fatal("stable admission ID rebound finalized digest")
	}
	f.fence.reject = true
	if _, e = f.a.RegisterOrigin(ctx, f.owner, c, b, a, caller, original, final, "origin", "generation"); e == nil {
		t.Fatal("old admitted source bypassed current revocation before native effect")
	}
}
func TestOfflineConcurrentControllerCASOnlyOneWinner(t *testing.T) {
	f := fixture(t)
	first := f.controller(t, 0, "initial")
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := time.Unix(int64(i), 0).String()
			if _, e := f.a.AcquireController(context.Background(), f.owner, f.scope, first.Epoch(), id, id); e == nil {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if success != 1 {
		t.Fatal("concurrent epoch CAS admitted", success)
	}
}

type escapeFence struct {
	saved func(Witness) error
	facts AdmissionFacts
}

func (f *escapeFence) WithAdmission(_ context.Context, facts AdmissionFacts, commit func(Witness) error) error {
	f.saved = commit
	f.facts = facts
	return nil
}
func TestOfflineFenceCannotEscapeAndCommitAfterReturn(t *testing.T) {
	f := fixture(t)
	c := f.controller(t, 0, "A")
	b := f.binding(t, c)
	caller, original, final := f.invocation(t)
	escape := &escapeFence{}
	a, e := New(f.store, escape)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.Admit(context.Background(), f.owner, c, b, caller, original, final, "a", "attempt", "replay"); e == nil {
		t.Fatal("fence without authorization accepted")
	}
	if e = escape.saved(Witness{Version: "owner-trust.v1", FinalizedDigest: escape.facts.FinalizedDigest, Value: json.RawMessage(`{}`)}); e == nil {
		t.Fatal("escaped callback mutated durable authority after return")
	}
	if _, e = f.a.Admit(context.Background(), f.owner, c, b, caller, original, final, "a", "attempt", "replay"); e != nil {
		t.Fatal("escaped callback left conflicting admission", e)
	}
}

type failingFence struct{ after bool }

func (f failingFence) WithAdmission(_ context.Context, facts AdmissionFacts, commit func(Witness) error) error {
	if f.after {
		if e := commit(Witness{Version: "owner-trust.v1", FinalizedDigest: facts.FinalizedDigest, Value: json.RawMessage(`{}`)}); e != nil {
			return e
		}
	}
	return errors.New("private fence error")
}
func TestOfflineFenceErrorAfterCommitRetainsKnownProof(t *testing.T) {
	f := fixture(t)
	c := f.controller(t, 0, "A")
	b := f.binding(t, c)
	caller, original, final := f.invocation(t)
	a, _ := New(f.store, failingFence{after: true})
	issued, e := a.Admit(context.Background(), f.owner, c, b, caller, original, final, "a", "attempt", "replay")
	if e == nil || issued.Proof.Revision != 1 {
		t.Fatal("known committed proof discarded", e)
	}
	retry, e := f.a.Admit(context.Background(), f.owner, c, b, caller, original, final, "a", "attempt", "replay")
	if e != nil || retry.Proof.Sequence != issued.Proof.Sequence {
		t.Fatal("retry changed immutable known admission", e)
	}
}

func TestOfflineForeignRootContextBindingSwapAndRetirementFailClosed(t *testing.T) {
	f := fixture(t)
	other := fixture(t)
	ctx := context.Background()
	c := f.controller(t, 0, "A")
	b := f.binding(t, c)
	caller, original, final := f.invocation(t)
	foreign := other.controller(t, 0, "A")
	foreign.Scope = f.scope
	if _, e := f.a.Admit(ctx, f.owner, foreign, b, caller, original, final, "a", "attempt", "replay"); e == nil {
		t.Fatal("foreign signed root transplanted into same public scope")
	}
	transplant := b
	transplant.Worker.StateDirectoryID = "other-state-directory"
	if _, e := f.a.Admit(ctx, f.owner, c, transplant, caller, original, final, "a", "attempt", "replay"); e == nil {
		t.Fatal("same domain different state directory binding transplanted")
	}
	first, e := f.a.Admit(ctx, f.owner, c, b, caller, original, final, "a", "attempt", "replay")
	if e != nil {
		t.Fatal(e)
	}
	changed := b.Worker
	changed.OwnershipGeneration = "replacement-generation"
	replacement, e := f.a.BindWorker(ctx, f.owner, c, b.Proof.Revision, changed)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.a.RegisterOrigin(ctx, f.owner, c, replacement, first, caller, original, final, "origin", "native-generation"); e == nil {
		t.Fatal("original admission actuated under replacement worker")
	}
	retired, e := f.a.RetireWorker(ctx, f.owner, c, replacement)
	if e != nil {
		t.Fatal(e)
	}
	exact, e := f.a.RetireWorker(ctx, f.owner, c, replacement)
	if e != nil || exact.Sequence != retired.Sequence {
		t.Fatal("retirement retry mutated history", e)
	}
	if _, e = f.a.BindWorker(ctx, f.owner, c, retired.Revision, changed); e == nil {
		t.Fatal("retired ownership identity resurrected")
	}
}

type panicFence struct {
	saved func(Witness) error
	facts AdmissionFacts
}

func (f *panicFence) WithAdmission(_ context.Context, facts AdmissionFacts, commit func(Witness) error) error {
	f.saved = commit
	f.facts = facts
	panic("private provider details")
}
func TestOfflinePanickingFenceClosesCapturedCallback(t *testing.T) {
	f := fixture(t)
	c := f.controller(t, 0, "A")
	b := f.binding(t, c)
	caller, original, final := f.invocation(t)
	bad := &panicFence{}
	a, _ := New(f.store, bad)
	if _, e := a.Admit(context.Background(), f.owner, c, b, caller, original, final, "a", "attempt", "replay"); e == nil || e.Error() == "private provider details" {
		t.Fatal("panicking fence not redacted", e)
	}
	if e := bad.saved(Witness{Version: "owner-trust.v1", FinalizedDigest: bad.facts.FinalizedDigest, Value: json.RawMessage(`{}`)}); e == nil {
		t.Fatal("panicking fence retained executable callback")
	}
}
