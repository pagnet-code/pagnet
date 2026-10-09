package actions

// Real crash fixtures for the production durable Admitter. These are
// integration tests: a real registry store (the universal original claim's
// trust root), a real node.Service (the adapter association), and a real
// endpoint adapter. They cover: duplicates, concurrent delivery, lost reply,
// restart before/after admission, trigger/emit/redirect loops, provider crash,
// and retained UNKNOWN with no second effect.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

var crashOwner = fabric.Principal{Ref: "spiffe://local/owner", Kind: "local.owner", Issuer: "local.test"}

// crashEndpoint is a real endpoint adapter that counts actual invocations. The
// count is the "effect": a paid operation must increment it at most once.
type crashEndpoint struct{ invocations atomic.Int32 }

func (e *crashEndpoint) Invoke(_ context.Context, _ fabric.ExecutionContext, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
	e.invocations.Add(1)
	return &completeFixtureStream{id: r.InvocationID}, nil
}

// crashAuthenticator authenticates the retained action against the store's
// original source authority and retained definitions, then forwards the exact
// engine envelope. Its store pointer is wired after the actions Store exists.
type crashAuthenticator struct{ store *Store }

func (a *crashAuthenticator) Authenticate(ctx context.Context, r fabric.AuthenticationRequest) (fabric.ExecutionContext, error) {
	grant, ok := r.PeerEvidence.(*actionGrant)
	if !ok || a.store == nil || r.Audience != a.store.config.Scope.Audience {
		return fabric.ExecutionContext{}, denied()
	}
	action := grant.request.Action
	if len(r.ExactEnvelope) == 0 || string(r.ExactEnvelope) != string(action.ExactEnvelope) {
		return fabric.ExecutionContext{}, denied()
	}
	original, v, e := a.store.verifySource(ctx, grant.request.Source)
	if e != nil {
		return fabric.ExecutionContext{}, e
	}
	var envelope fabric.Envelope
	if fabric.DecodeJSON(r.ExactEnvelope, &envelope) != nil || envelope.Principal != v.Caller.PrincipalView() || envelope.Source != v.Caller.PrincipalView().Ref {
		return fabric.ExecutionContext{}, denied()
	}
	key := "emit"
	var definition *TriggerDefinition
	if action.DefinitionID != "" {
		d, ok := a.store.definitions[action.DefinitionID]
		if !ok || d.Revision != action.DefinitionRevision || a.store.config.DefinitionAuthority.Verify(ctx, a.store.config.Scope, cloneDefinition(d)) != nil {
			return fabric.ExecutionContext{}, denied()
		}
		key = d.ID + "@" + d.Revision
		definition = &d
	}
	id, lineage, e := actionIdentity(a.store.config.Scope, original, v, key, definition)
	expected, _ := json.Marshal(lineage)
	actual, _ := json.Marshal(envelope.Context)
	if e != nil || id != action.ID || envelope.ID != id || string(expected) != string(actual) || a.store.config.Authorizer.Check(ctx, v.Caller, cloneAction(action)) != nil {
		return fabric.ExecutionContext{}, denied()
	}
	p := fabric.Provenance{Origin: lineage.Origin, ParentID: lineage.ParentID, Hops: lineage.Hops, Ancestry: lineage.Ancestry, ExtensionChain: lineage.ExtensionChain, TriggerLineage: lineage.TriggerLineage}
	return fabric.NewAuthenticatedForwardContext(v.Caller.PrincipalView(), r.Audience, r.ExactEnvelope, p)
}

// nodeAdapter is the real adapter association: it drives the actual
// node.Service (authenticate + dispatch to the real endpoint adapter). loseReply
// and panicAdapter model a committed admission whose reply is lost or whose
// provider crashes, AFTER the durable commit.
type nodeAdapter struct {
	service      *node.Service
	loseReply    atomic.Bool
	panicAdapter atomic.Bool
}

func (a *nodeAdapter) Invoke(ctx context.Context, request AdmissionRequest) (fabric.InvocationStream, error) {
	result, err := a.service.Execute(ctx, request.Action.ExactEnvelope, &actionGrant{request})
	if err != nil {
		return nil, err
	}
	if result.Stream == nil {
		return nil, errors.New("node produced no stream")
	}
	if a.loseReply.Load() {
		_ = result.Stream.Close()
		return nil, errors.New("committed reply lost in transit")
	}
	if a.panicAdapter.Load() {
		_ = result.Stream.Close()
		panic("provider crashed mid-admission")
	}
	return result.Stream, nil
}

type registryTargetScope struct{ store *registry.Store }

func (r registryTargetScope) ResolveTargetScope(ctx context.Context, target fabric.EndpointRef, revision fabric.Revision) (TargetScope, error) {
	if target.IsOffer() {
		return TargetScope{}, errors.New("fixture resolves physical endpoints only")
	}
	endpoint, err := r.store.GetEndpoint(ctx, target, revision)
	if err != nil || len(endpoint.Bindings) == 0 {
		return TargetScope{}, errors.New("target binding unavailable")
	}
	return TargetScope{Endpoint: endpoint.Ref, EndpointRevision: endpoint.Revision, BindingID: endpoint.Bindings[0].ID}, nil
}

type crashSetup struct {
	registryDir string
	actionsDir  string
	registry    *registry.Store
	config      Config
	source      SourceInput
	adapter     *nodeAdapter
	endpoint    *crashEndpoint
	auth        *crashAuthenticator
	owner       func(context.Context) (fabric.ExecutionContext, error)
	definition  TriggerDefinition
}

func crashFixture(t *testing.T) crashSetup {
	t.Helper()
	ctx := t.Context()
	rootDir := t.TempDir()
	registryDir := filepath.Join(rootDir, "domain")
	s, err := registry.Bootstrap(ctx, registryDir, crashOwner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	owner, err := fabric.NewAuthenticatedContext(crashOwner, s.Namespace(), []byte("trusted original request"))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := fabric.NewEndpointRef(s.AuthorityIdentity().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	d := fabric.EndpointDescriptor{Ref: ref, Kind: "agent.local", Name: "Crash", Description: "Crash fixture", Bindings: []fabric.BindingSummary{{ID: "local", Protocol: "local.native", Version: "1"}}}
	revision, err := s.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: d})
	if err != nil {
		t.Fatal(err)
	}
	d.Revision = revision

	producerPub, producerPriv, _ := ed25519.GenerateKey(rand.Reader)
	sourceAuthority, err := NewEd25519SourceAuthority(s.Namespace(), map[string]ProducerIdentity{crashOwner.Ref: {Principal: crashOwner, PublicKey: producerPub}})
	if err != nil {
		t.Fatal(err)
	}
	defPub, defPriv, _ := ed25519.GenerateKey(rand.Reader)
	definitionAuthority, err := NewEd25519DefinitionAuthority(defPub, nil)
	if err != nil {
		t.Fatal(err)
	}
	authorizer := NewEnvelopeAuthorizer()

	definition := TriggerDefinition{ID: "trigger.crash", Revision: "1", Source: crashOwner.Ref, Type: "crash.action", Target: ref, TargetRevision: revision, BindingDigest: digest([]byte("profile"))}
	definition.SignedAuthorization, _ = json.Marshal(ed25519.Sign(defPriv, DefinitionSigningBytes(definition)))

	endpoint := &crashEndpoint{}
	auth := &crashAuthenticator{}
	service, err := node.New(node.Config{Audience: s.Namespace(), Authenticator: auth, Dispatcher: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &nodeAdapter{service: service}
	scope := durable.Scope{Audience: s.Namespace(), Domain: "crash-domain"}
	admitter, err := NewDurableAdmitter(s, scope, func(context.Context) (fabric.ExecutionContext, error) { return owner, nil }, sourceAuthority, registryTargetScope{store: s}, adapter)
	if err != nil {
		t.Fatal(err)
	}
	protector, err := durable.NewAESGCM(durable.KeyReference{ID: "crash-key", Version: "1"}, repeatByte([]byte{41}, 32))
	if err != nil {
		t.Fatal(err)
	}
	config := DefaultConfig(scope)
	config.Definitions = []TriggerDefinition{definition}
	config.SourceAuthority = sourceAuthority
	config.DefinitionAuthority = definitionAuthority
	config.Authorizer = authorizer
	config.Admitter = admitter
	config.Protector = protector
	config.Queue.RetryDelay = time.Millisecond
	config.Queue.LeaseTTL = 100 * time.Millisecond

	e := event.New("1.0")
	e.SetID("crash-original-event")
	e.SetSource(crashOwner.Ref)
	e.SetType("crash.action")
	e.SetTime(time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC))
	if err := e.SetData("application/json", json.RawMessage(`{"crash":"fixture","n":9007199254740993}`)); err != nil {
		t.Fatal(err)
	}
	raw, err := events.Encode(e, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := json.Marshal(ed25519.Sign(producerPriv, raw))

	return crashSetup{
		registryDir: registryDir,
		actionsDir:  filepath.Join(rootDir, "actions"),
		registry:    s,
		config:      config,
		source:      SourceInput{ExactEvent: raw, Proof: proof},
		adapter:     adapter,
		endpoint:    endpoint,
		auth:        auth,
		owner:       func(context.Context) (fabric.ExecutionContext, error) { return owner, nil },
		definition:  definition,
	}
}

func repeatByte(b []byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b[0]
	}
	return out
}

// open opens (or bootstraps) the actions store and wires the authenticator.
func (f crashSetup) open(t *testing.T, create bool) *Store {
	t.Helper()
	var (
		s   *Store
		err error
	)
	if create {
		s, err = Bootstrap(t.Context(), f.actionsDir, f.config)
	} else {
		s, err = Open(t.Context(), f.actionsDir, f.config)
	}
	if err != nil {
		t.Fatal(err)
	}
	f.auth.store = s
	return s
}

func (f *crashSetup) rebuildAdmitter(t *testing.T, reg *registry.Store) {
	t.Helper()
	admitter, err := NewDurableAdmitter(reg, f.config.Scope, f.owner, f.config.SourceAuthority, registryTargetScope{store: reg}, f.adapter)
	if err != nil {
		t.Fatal(err)
	}
	f.config.Admitter = admitter
}

func claimDelivery(t *testing.T, s *Store, now time.Time) durable.Delivery {
	t.Helper()
	d, ok, err := s.queue.Claim(t.Context(), "actions.dispatch", "crash.worker", now)
	if err != nil || !ok {
		t.Fatal("no genuine queue claim", err)
	}
	return d
}

func actionFromDelivery(t *testing.T, d durable.Delivery) (Action, SourceInput) {
	t.Helper()
	var set actionSet
	if err := fabric.DecodeJSON(d.Event.Data(), &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Actions) != 1 {
		t.Fatal("expected a single-action delivery")
	}
	return set.Actions[0], set.Source
}

// TestCrashDuplicatesNeverDoubleDispatch enqueues the same source twice: the
// second is an explicit duplicate and the endpoint adapter runs exactly once.
func TestCrashDuplicatesNeverDoubleDispatch(t *testing.T) {
	f := crashFixture(t)
	s := f.open(t, true)
	defer s.Close()
	if _, err := s.Trigger(t.Context(), f.source); err != nil {
		t.Fatal(err)
	}
	dup, err := s.Trigger(t.Context(), f.source)
	if err != nil || !dup.Duplicate {
		t.Fatalf("exact original retry was not a duplicate: %v %+v", err, dup)
	}
	// The Ack is evaluated at the claim's own instant: the delivery work
	// between Claim and Ack must not race the 100ms lease on a loaded runner
	// (real-time lease expiry is covered by the restart tests below).
	ackNow := time.Now()
	d := claimDelivery(t, s, ackNow)
	if err := s.deliver(t.Context(), d.Event); err != nil {
		t.Fatal(err)
	}
	if f.endpoint.invocations.Load() != 1 {
		t.Fatalf("duplicate source dispatched %d times", f.endpoint.invocations.Load())
	}
	if err := s.queue.Ack(t.Context(), d.Claim, ackNow); err != nil {
		t.Fatal(err)
	}
}

// TestCrashConcurrentDeliveryAdmitsOnce runs AdmitOrGet concurrently for the
// same retained action: exactly one endpoint effect, and every caller recovers
// the same durable receipt.
func TestCrashConcurrentDeliveryAdmitsOnce(t *testing.T) {
	f := crashFixture(t)
	s := f.open(t, true)
	defer s.Close()
	if _, err := s.Trigger(t.Context(), f.source); err != nil {
		t.Fatal(err)
	}
	d := claimDelivery(t, s, time.Now())
	action, source := actionFromDelivery(t, d)
	var mu sync.Mutex
	receipts := make([]AdmissionReceipt, 0, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := s.config.Admitter.AdmitOrGet(t.Context(), AdmissionRequest{Action: cloneAction(action), Source: SourceInput{append([]byte(nil), source.ExactEvent...), append([]byte(nil), source.Proof...)}})
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			receipts = append(receipts, r)
			mu.Unlock()
		}()
	}
	wg.Wait()
	if f.endpoint.invocations.Load() != 1 {
		t.Fatalf("concurrent admission dispatched %d times", f.endpoint.invocations.Load())
	}
	if len(receipts) != 8 {
		t.Fatalf("concurrent admission returned %d receipts", len(receipts))
	}
	first := receipts[0]
	for _, r := range receipts[1:] {
		if r.ActionID != first.ActionID || r.EnvelopeDigest != first.EnvelopeDigest || r.AdmissionID != first.AdmissionID || !r.AcceptedAt.Equal(first.AcceptedAt) {
			t.Fatalf("concurrent admission returned divergent receipts: %+v vs %+v", r, first)
		}
	}
}

// TestCrashLostReplyRecoversSameReceiptWithNoSecondEffect commits the admission
// then loses the reply. The retry recovers the identical retained receipt and
// never repeats the endpoint effect.
func TestCrashLostReplyRecoversSameReceiptWithNoSecondEffect(t *testing.T) {
	f := crashFixture(t)
	s := f.open(t, true)
	defer s.Close()
	if _, err := s.Trigger(t.Context(), f.source); err != nil {
		t.Fatal(err)
	}
	d := claimDelivery(t, s, time.Now())
	action, source := actionFromDelivery(t, d)
	f.adapter.loseReply.Store(true)
	if _, err := s.config.Admitter.AdmitOrGet(t.Context(), AdmissionRequest{Action: cloneAction(action), Source: source}); err == nil {
		t.Fatal("lost reply was hidden")
	}
	if f.endpoint.invocations.Load() != 1 {
		t.Fatalf("lost reply ran %d effects", f.endpoint.invocations.Load())
	}
	f.adapter.loseReply.Store(false)
	again, err := s.config.Admitter.AdmitOrGet(t.Context(), AdmissionRequest{Action: cloneAction(action), Source: source})
	if err != nil {
		t.Fatal(err)
	}
	if f.endpoint.invocations.Load() != 1 {
		t.Fatalf("retry after lost reply repeated the effect: %d", f.endpoint.invocations.Load())
	}
	if again.ActionID != action.ID || again.EnvelopeDigest != digest(action.ExactEnvelope) || again.AdmissionID == "" {
		t.Fatalf("recovered receipt is not the retained one: %+v", again)
	}
}

// TestCrashRestartAfterAdmissionRecoversReceipt commits an admission, then
// "crashes" without acking the delivery. On restart (registry + actions store
// reopened) the delivery is redelivered and the Admitter recovers the retained
// receipt WITHOUT re-invoking the already-paid endpoint adapter.
func TestCrashRestartAfterAdmissionRecoversReceipt(t *testing.T) {
	f := crashFixture(t)
	s := f.open(t, true)
	if _, err := s.Trigger(t.Context(), f.source); err != nil {
		t.Fatal(err)
	}
	claimNow := time.Now()
	d := claimDelivery(t, s, claimNow)
	action, source := actionFromDelivery(t, d)
	// Commit the admission (claim + receipt) and run the endpoint effect, then
	// crash before the delivery is acked: the lease is left unacked.
	if _, err := s.config.Admitter.AdmitOrGet(t.Context(), AdmissionRequest{Action: cloneAction(action), Source: source}); err != nil {
		t.Fatal(err)
	}
	if f.endpoint.invocations.Load() != 1 {
		t.Fatalf("pre-restart effects: %d", f.endpoint.invocations.Load())
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Restart: reopen the registry (same owner) and rebuild the Admitter over
	// it, then reopen the actions store.
	if err := f.registry.Close(); err != nil {
		t.Fatal(err)
	}
	reg2, err := registry.Open(t.Context(), f.registryDir)
	if err != nil {
		t.Fatal(err)
	}
	defer reg2.Close()
	f.rebuildAdmitter(t, reg2)
	s2, err := Open(t.Context(), f.actionsDir, f.config)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	f.auth.store = s2
	// Let the unacked lease expire at the real clock so the delivery is
	// redelivered; the post-restart claim and Ack share one instant so the
	// delivery work cannot race the 100ms lease on a loaded runner. The
	// retained receipt is recovered with no second endpoint effect.
	time.Sleep(f.config.Queue.LeaseTTL + 200*time.Millisecond)
	ackNow := time.Now()
	d2 := claimDelivery(t, s2, ackNow)
	if err := s2.deliver(t.Context(), d2.Event); err != nil {
		t.Fatal(err)
	}
	if f.endpoint.invocations.Load() != 1 {
		t.Fatalf("redelivery after restart repeated the paid effect: %d", f.endpoint.invocations.Load())
	}
	if err := s2.queue.Ack(t.Context(), d2.Claim, ackNow); err != nil {
		t.Fatal(err)
	}
}

// TestCrashRestartBeforeAdmissionDeliversOnce commits NOTHING (the crash happens
// after the enqueue but before the admission commit). On restart the delivery is
// redelivered and admitted exactly once: no lost work, no double effect.
func TestCrashRestartBeforeAdmissionDeliversOnce(t *testing.T) {
	f := crashFixture(t)
	s := f.open(t, true)
	if _, err := s.Trigger(t.Context(), f.source); err != nil {
		t.Fatal(err)
	}
	// Claim the delivery (lease) then crash BEFORE admitting: no admission is
	// committed and the delivery is left unacked.
	claimDelivery(t, s, time.Now())
	if f.endpoint.invocations.Load() != 0 {
		t.Fatalf("pre-restart effects: %d", f.endpoint.invocations.Load())
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.registry.Close(); err != nil {
		t.Fatal(err)
	}
	reg2, err := registry.Open(t.Context(), f.registryDir)
	if err != nil {
		t.Fatal(err)
	}
	defer reg2.Close()
	f.rebuildAdmitter(t, reg2)
	s2, err := Open(t.Context(), f.actionsDir, f.config)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	f.auth.store = s2
	// Let the unacked lease expire at the real clock, then redeliver and admit
	// fresh; the new claim and its Ack share one instant so the delivery work
	// cannot race the 100ms lease on a loaded runner.
	time.Sleep(f.config.Queue.LeaseTTL + 200*time.Millisecond)
	ackNow := time.Now()
	d2 := claimDelivery(t, s2, ackNow)
	if err := s2.deliver(t.Context(), d2.Event); err != nil {
		t.Fatal(err)
	}
	if f.endpoint.invocations.Load() != 1 {
		t.Fatalf("restart-before-admission admitted %d times", f.endpoint.invocations.Load())
	}
	if err := s2.queue.Ack(t.Context(), d2.Claim, ackNow); err != nil {
		t.Fatal(err)
	}
}

// TestCrashTriggerSelfRecursionLoopRejected confirms a source whose genuine
// parent lineage already contains the trigger's ID is rejected, not looped.
func TestCrashTriggerSelfRecursionLoopRejected(t *testing.T) {
	f := crashFixture(t)
	// Install a parent lineage carrying the trigger's own ID BEFORE the store is
	// opened, so the store's retained source authority sees a self-recursing
	// trigger and rejects it before any admission.
	f.sourceAuthParent(t)
	s := f.open(t, true)
	defer s.Close()
	if _, err := s.Trigger(t.Context(), f.source); err == nil {
		t.Fatal("trigger self-recursion loop accepted")
	}
	if f.endpoint.invocations.Load() != 0 {
		t.Fatalf("self-recursion loop reached the adapter: %d", f.endpoint.invocations.Load())
	}
}

// sourceAuthParent wraps the source authority so its Verified source carries a
// genuine parent envelope whose trigger lineage already contains the trigger's
// own ID (a self-recursing trigger). Must be called before open.
func (f *crashSetup) sourceAuthParent(t *testing.T) {
	t.Helper()
	f.config.SourceAuthority = &parentSourceAuthority{inner: f.config.SourceAuthority, parentID: f.definition.ID, target: f.definition.Target}
}

// parentSourceAuthority wraps a SourceAuthority and attaches a genuine parent
// envelope whose trigger lineage already contains a trigger ID. The parent is a
// valid invoke envelope (with a target) so it passes Verify, and ONLY the
// self-recursion check (the trigger id already in the lineage) rejects it.
type parentSourceAuthority struct {
	inner    SourceAuthority
	parentID string
	target   fabric.EndpointRef
}

func (p *parentSourceAuthority) Verify(ctx context.Context, scope durable.Scope, input SourceInput) (VerifiedSource, error) {
	v, err := p.inner.Verify(ctx, scope, input)
	if err != nil {
		return VerifiedSource{}, err
	}
	e, err := events.Decode(input.ExactEvent, 1<<20)
	if err != nil {
		return VerifiedSource{}, err
	}
	target := p.target
	parent := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "crash-loop-parent", Operation: fabric.OperationInvoke, Principal: v.Caller.PrincipalView(), Source: v.Caller.PrincipalView().Ref, Target: &target, ExpectedRevision: "1", CreatedAt: e.Time(), Payload: json.RawMessage(`{}`), Context: fabric.EnvelopeContext{Origin: v.Caller.PrincipalView().Ref, TriggerLineage: []string{p.parentID}}}
	v.Parent = &parent
	return v, nil
}

// continuationSourceAuthority gives the source a genuine authenticated parent so
// the EMIT continuation (parent/trace/ancestry) can be observed.
type continuationSourceAuthority struct {
	inner  SourceAuthority
	target fabric.EndpointRef
}

func (c *continuationSourceAuthority) Verify(ctx context.Context, scope durable.Scope, input SourceInput) (VerifiedSource, error) {
	v, err := c.inner.Verify(ctx, scope, input)
	if err != nil {
		return VerifiedSource{}, err
	}
	e, err := events.Decode(input.ExactEvent, 1<<20)
	if err != nil {
		return VerifiedSource{}, err
	}
	target := c.target
	parent := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "emit-continuation-parent", Operation: fabric.OperationInvoke, Principal: v.Caller.PrincipalView(), Source: v.Caller.PrincipalView().Ref, Target: &target, ExpectedRevision: "1", CreatedAt: e.Time(), Payload: json.RawMessage(`{}`), Context: fabric.EnvelopeContext{Origin: v.Caller.PrincipalView().Ref, Hops: 0}}
	v.Parent = &parent
	return v, nil
}

// TestEmitContinuationNewIDCarriesParentLineageAndDispatchesOnce confirms EMIT
// creates a NEW invocation id that CONTINUES the original execution (parent id,
// ancestry, hops carried from the genuine authenticated parent), and dispatches
// the exact retained envelope exactly once (no reinjected modified request).
func TestEmitContinuationNewIDCarriesParentLineageAndDispatchesOnce(t *testing.T) {
	f := crashFixture(t)
	f.config.SourceAuthority = &continuationSourceAuthority{inner: f.config.SourceAuthority, target: f.definition.Target}
	s := f.open(t, true)
	defer s.Close()
	if _, err := s.Emit(t.Context(), f.source, EmitRequest{Target: f.definition.Target, Revision: f.definition.TargetRevision, Input: json.RawMessage(`{"emit":"continuation"}`)}); err != nil {
		t.Fatal(err)
	}
	d := claimDelivery(t, s, time.Now())
	action, _ := actionFromDelivery(t, d)
	var envelope fabric.Envelope
	if fabric.DecodeJSON(action.ExactEnvelope, &envelope) != nil {
		t.Fatal("emit envelope undecodable")
	}
	if envelope.ID == "" || envelope.Context.ParentID != "emit-continuation-parent" ||
		len(envelope.Context.Ancestry) != 1 || envelope.Context.Ancestry[0] != "emit-continuation-parent" || envelope.Context.Hops != 1 {
		t.Fatalf("emit did not continue the original execution lineage: %+v", envelope.Context)
	}
	if err := s.deliver(t.Context(), d.Event); err != nil {
		t.Fatal(err)
	}
	if f.endpoint.invocations.Load() != 1 {
		t.Fatalf("emit continuation dispatched %d times", f.endpoint.invocations.Load())
	}
	// An exact retry of the same emit is a duplicate and never re-dispatches.
	if _, err := s.Emit(t.Context(), f.source, EmitRequest{Target: f.definition.Target, Revision: f.definition.TargetRevision, Input: json.RawMessage(`{"emit":"continuation"}`)}); err != nil {
		t.Fatal(err)
	}
	if f.endpoint.invocations.Load() != 1 {
		t.Fatalf("emit retry re-dispatched: %d", f.endpoint.invocations.Load())
	}
}

// TestCrashProviderCrashRetainsUnknownWithNoSecondEffect lets the provider crash
// after the admission commit. The retained receipt is recovered; the endpoint
// effect is never repeated.
func TestCrashProviderCrashRetainsUnknownWithNoSecondEffect(t *testing.T) {
	f := crashFixture(t)
	s := f.open(t, true)
	defer s.Close()
	if _, err := s.Trigger(t.Context(), f.source); err != nil {
		t.Fatal(err)
	}
	d := claimDelivery(t, s, time.Now())
	action, source := actionFromDelivery(t, d)
	f.adapter.panicAdapter.Store(true)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("provider did not crash as scripted")
			}
		}()
		_, _ = s.config.Admitter.AdmitOrGet(t.Context(), AdmissionRequest{Action: cloneAction(action), Source: source})
	}()
	f.adapter.panicAdapter.Store(false)
	recovered, err := s.config.Admitter.AdmitOrGet(t.Context(), AdmissionRequest{Action: cloneAction(action), Source: source})
	if err != nil {
		t.Fatal(err)
	}
	if recovered.AdmissionID == "" || recovered.ActionID != action.ID {
		t.Fatalf("crash did not retain a durable receipt: %+v", recovered)
	}
	effectsAfter := f.endpoint.invocations.Load()
	if _, err := s.config.Admitter.AdmitOrGet(t.Context(), AdmissionRequest{Action: cloneAction(action), Source: source}); err != nil {
		t.Fatal(err)
	}
	if f.endpoint.invocations.Load() != effectsAfter {
		t.Fatalf("crashed admission re-dispatched a paid operation: %d -> %d", effectsAfter, f.endpoint.invocations.Load())
	}
}
