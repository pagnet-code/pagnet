//go:build linux || darwin

package fabricnode

// Real installed-level crash fixtures for the production durable Admitter.
// These are integration tests over the ACTUAL installed node: a real
// localinstallation, a real node.Service (the adapter association), a real
// dispatch to a real registered binding, and the real installed.go wiring that
// composes the Actions runtime over the node. They cover: duplicates,
// concurrent delivery, lost reply, restart before/after admission, trigger
// self-recursion, emit continuation, and provider crash with retained UNKNOWN
// and no second effect.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cevent "github.com/cloudevents/sdk-go/v2/event"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events"
	"github.com/pagnet-code/pagnet/fabric/events/actions"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
)

const (
	testBindingProtocol = "test.count"
	testBindingVersion  = "1"
)

// countingEndpoint is a real endpoint adapter that counts actual invocations.
// The count is the "effect": a paid operation must increment it at most once.
type countingEndpoint struct{ invocations atomic.Int32 }

func (e *countingEndpoint) Invoke(_ context.Context, _ fabric.ExecutionContext, _ fabric.EndpointDescriptor, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
	e.invocations.Add(1)
	return &completeStream{id: r.InvocationID}, nil
}

// completeStream is a terminal two-frame stream: start, complete, then EOF.
type completeStream struct {
	id   string
	next uint64
}

func (s *completeStream) Next(context.Context) (fabric.InvocationFrame, error) {
	s.next++
	if s.next > 2 {
		return fabric.InvocationFrame{}, io.EOF
	}
	kind := fabric.FrameStart
	if s.next == 2 {
		kind = fabric.FrameComplete
	}
	return fabric.InvocationFrame{InvocationID: s.id, Sequence: s.next - 1, Kind: kind}, nil
}
func (*completeStream) Close() error { return nil }

// testBindingProvider resolves the shared counting endpoint for the fixture's
// private test.count binding. It is explicit composition, never discovery.
type testBindingProvider struct{ endpoint *countingEndpoint }

func (p *testBindingProvider) ResolveBinding(_ context.Context, _ fabric.ExecutionContext, _ fabric.EndpointDescriptor, b fabric.BindingSummary, _ *fabric.OfferDescriptor) (fabric.EndpointAdapter, [32]byte, error) {
	fingerprint := sha256.Sum256([]byte(b.ID + "/" + b.Protocol + "/" + b.Version))
	return p.endpoint, fingerprint, nil
}

var _ BindingProvider = (*testBindingProvider)(nil)

// installedActionLineage wraps the retained actions source authority to attach
// a genuine authenticated parent envelope. It models the trusted
// test/observability boundary the daemon composes via
// InstalledConfig.ActionSourceAuthorityWrapper; the wrapped authority remains
// the inner verifier.
type installedActionLineage struct {
	inner    actions.SourceAuthority
	parentID string   // the parent envelope's ID
	lineage  []string // the parent's TriggerLineage (self-recursion: the trigger's own ID)
	target   fabric.EndpointRef
}

func (w *installedActionLineage) Verify(ctx context.Context, scope durable.Scope, input actions.SourceInput) (actions.VerifiedSource, error) {
	v, err := w.inner.Verify(ctx, scope, input)
	if err != nil {
		return actions.VerifiedSource{}, err
	}
	e, err := events.Decode(input.ExactEvent, 1<<20)
	if err != nil {
		return actions.VerifiedSource{}, err
	}
	target := w.target
	parent := fabric.Envelope{
		ProtocolVersion:  fabric.CurrentProtocolVersion,
		ID:               w.parentID,
		Operation:        fabric.OperationInvoke,
		Principal:        v.Caller.PrincipalView(),
		Source:           v.Caller.PrincipalView().Ref,
		Target:           &target,
		ExpectedRevision: "1",
		CreatedAt:        e.Time(),
		Payload:          json.RawMessage(`{}`),
		Context:          fabric.EnvelopeContext{Origin: v.Caller.PrincipalView().Ref, TriggerLineage: w.lineage},
	}
	v.Parent = &parent
	return v, nil
}

var _ actions.SourceAuthority = (*installedActionLineage)(nil)

type installedActionsFixture struct {
	dir         string
	socket      string
	binary      string
	endpoint    *countingEndpoint
	endpointRef fabric.EndpointRef
	revision    fabric.Revision
	source      actions.SourceInput
	definition  actions.TriggerDefinition
	producer    fabric.Principal
}

func installedHexDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// installedActionsFixture bootstraps a real installation, registers a real
// endpoint with a private test.count binding, retains a signed trigger
// definition and producer key, and performs the explicit actions setup. The
// installation is closed so OpenInstalled can load it as the only writer.
func newInstalledActionsFixture(t *testing.T) installedActionsFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	parent, e := os.MkdirTemp("", "pgn-iactions-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(parent) })
	dir := filepath.Join(parent, "authority")
	socket := filepath.Join(parent, "node.sock")
	installed, e := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if e != nil {
		t.Fatal(e)
	}
	owner, e := installed.Operator(ctx)
	if e != nil {
		t.Fatal(e)
	}
	root := installed.Store.AuthorityIdentity()
	ref, e := fabric.NewEndpointRef(root.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	// A real registered endpoint with a private test.count binding the node's
	// own (local.native) bindings cannot serve; the explicit ActionBindings set
	// resolves it to the counting adapter through the real dispatch path.
	d := fabric.EndpointDescriptor{Ref: ref, Kind: "agent.local", Name: "Installed", Description: "Installed actions fixture", Bindings: []fabric.BindingSummary{{ID: "test", Protocol: testBindingProtocol, Version: testBindingVersion, Streaming: true, Idempotency: true}}}
	revision, e := installed.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: d})
	if e != nil {
		t.Fatal(e)
	}

	producer := fabric.Principal{Ref: "spiffe://local/producer", Kind: "local.producer", Issuer: "local.test"}
	producerPub, producerPriv, _ := ed25519.GenerateKey(rand.Reader)
	defPub, defPriv, _ := ed25519.GenerateKey(rand.Reader)

	definition := actions.TriggerDefinition{ID: "trigger.installed", Revision: "1", Source: producer.Ref, Type: "installed.action", Target: ref, TargetRevision: revision, BindingDigest: installedHexDigest([]byte("installed.profile"))}
	definition.SignedAuthorization, e = json.Marshal(ed25519.Sign(defPriv, actions.DefinitionSigningBytes(definition)))
	if e != nil {
		t.Fatal(e)
	}

	ev := cevent.New("1.0")
	ev.SetID("installed-original-event")
	ev.SetSource(producer.Ref)
	ev.SetType("installed.action")
	ev.SetTime(time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC))
	if e = ev.SetData("application/json", json.RawMessage(`{"installed":"fixture"}`)); e != nil {
		t.Fatal(e)
	}
	raw, e := events.Encode(ev, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	proof, e := json.Marshal(ed25519.Sign(producerPriv, raw))
	if e != nil {
		t.Fatal(e)
	}
	source := actions.SourceInput{ExactEvent: raw, Proof: proof}

	settings := ActionsSettings{
		Producers:           []ActionsProducerSettings{{Principal: producer, PublicKey: producerPub}},
		DefinitionPublicKey: defPub,
		Definitions:         []actions.TriggerDefinition{definition},
		Queue:               durable.DefaultConfig([]durable.Subscription{{ID: "actions.dispatch", Types: []string{"dev.pagnet.actions.queued"}}}),
		MaxDefinitions:      128,
		MaxFanout:           32,
		MaxProofBytes:       65536,
		MaxEnvelopeBytes:    65536,
	}
	settings.Queue.LeaseTTL = 100 * time.Millisecond
	settings.Queue.RetryDelay = time.Millisecond
	if e = InitializeConfiguredActions(ctx, installed, settings); e != nil {
		t.Fatal("explicit actions setup: ", e)
	}
	if e = installed.Close(); e != nil {
		t.Fatal(e)
	}
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	return installedActionsFixture{dir: dir, socket: socket, binary: binary, endpoint: &countingEndpoint{}, endpointRef: ref, revision: revision, source: source, definition: definition, producer: producer}
}

// openNode opens the ACTUAL installed node with the installed actions surface
// and the explicit test.count binding provider. It closes the background
// durable worker so the test owns claims deterministically; the durable
// Admitter, store, registry and real dispatch (the crash boundary) remain the
// real installed composition.
func (f *installedActionsFixture) openNode(t *testing.T, wrapper func(actions.SourceAuthority) actions.SourceAuthority) *InstalledNode {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	n, err := OpenInstalled(ctx, InstalledConfig{
		Directory: f.dir,
		Binary:    f.binary,
		Actions:   &InstalledActionsConfig{},
		ActionBindings: map[BindingProtocol]BindingProvider{
			{Protocol: testBindingProtocol, Version: testBindingVersion}: &testBindingProvider{endpoint: f.endpoint},
		},
		ActionSourceAuthorityWrapper: wrapper,
	})
	if err != nil {
		t.Fatal("open installed node: ", err)
	}
	if n.Actions == nil || n.Actions.Store == nil || n.Actions.Admitter == nil || n.Actions.Adapter == nil || n.Node == nil || n.Node.Service == nil {
		t.Fatal("installed actions runtime not wired over the real node")
	}
	if n.Actions.Workers != nil {
		if err := n.Actions.Workers.Close(ctx); err != nil {
			t.Fatal("close action workers: ", err)
		}
	}
	return n
}

type claimedAction struct {
	delivery durable.Delivery
	action   actions.Action
	source   actions.SourceInput
}

// claim leases one pending delivery from the real actions queue and decodes its
// single action. The caller owns the lease and decides whether to ack.
func (f *installedActionsFixture) claim(t *testing.T, store *actions.Store) claimedAction {
	t.Helper()
	d, ok, err := store.ClaimDelivery(t.Context(), "installed.worker", time.Now())
	if err != nil || !ok {
		t.Fatal("no genuine queue claim: ", err)
	}
	var set struct {
		Source  actions.SourceInput `json:"source"`
		Actions []actions.Action    `json:"actions"`
	}
	if err := fabric.DecodeJSON(d.Event.Data(), &set); err != nil || len(set.Actions) != 1 {
		t.Fatal("expected a single-action delivery: ", err)
	}
	return claimedAction{delivery: d, action: set.Actions[0], source: set.Source}
}

func (c claimedAction) ack(t *testing.T, store *actions.Store) {
	t.Helper()
	if err := store.AckDelivery(t.Context(), c.delivery.Claim, time.Now()); err != nil {
		t.Fatal("ack delivery: ", err)
	}
}

// TestInstalledActionsDuplicatesNeverDoubleDispatch enqueues the same source
// twice through the installed node: the second is an explicit duplicate and the
// real endpoint adapter runs exactly once.
func TestInstalledActionsDuplicatesNeverDoubleDispatch(t *testing.T) {
	f := newInstalledActionsFixture(t)
	n := f.openNode(t, nil)
	defer n.Close()
	if _, err := n.Actions.Store.Trigger(t.Context(), f.source); err != nil {
		t.Fatal(err)
	}
	dup, err := n.Actions.Store.Trigger(t.Context(), f.source)
	if err != nil || !dup.Duplicate {
		t.Fatalf("exact original retry was not a duplicate: %v %+v", err, dup)
	}
	c := f.claim(t, n.Actions.Store)
	if _, err := n.Actions.Admitter.AdmitOrGet(t.Context(), actions.AdmissionRequest{Action: c.action, Source: c.source}); err != nil {
		t.Fatal(err)
	}
	c.ack(t, n.Actions.Store)
	if f.endpoint.invocations.Load() != 1 {
		t.Fatalf("duplicate source dispatched %d times", f.endpoint.invocations.Load())
	}
}

// TestInstalledActionsConcurrentDeliveryAdmitsOnce runs AdmitOrGet concurrently
// for the same retained action on the installed node: exactly one endpoint
// effect, and every caller recovers the same durable receipt.
func TestInstalledActionsConcurrentDeliveryAdmitsOnce(t *testing.T) {
	f := newInstalledActionsFixture(t)
	n := f.openNode(t, nil)
	defer n.Close()
	if _, err := n.Actions.Store.Trigger(t.Context(), f.source); err != nil {
		t.Fatal(err)
	}
	c := f.claim(t, n.Actions.Store)
	var mu sync.Mutex
	receipts := make([]actions.AdmissionReceipt, 0, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a := c.action
			a.ExactEnvelope = append([]byte(nil), c.action.ExactEnvelope...)
			r, err := n.Actions.Admitter.AdmitOrGet(t.Context(), actions.AdmissionRequest{Action: a, Source: c.source})
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

// TestInstalledActionsLostReplyRecoversSameReceiptWithNoSecondEffect commits the
// admission on the installed node then loses the reply. The retry recovers the
// identical retained receipt and never repeats the endpoint effect.
func TestInstalledActionsLostReplyRecoversSameReceiptWithNoSecondEffect(t *testing.T) {
	f := newInstalledActionsFixture(t)
	n := f.openNode(t, nil)
	defer n.Close()
	if _, err := n.Actions.Store.Trigger(t.Context(), f.source); err != nil {
		t.Fatal(err)
	}
	c := f.claim(t, n.Actions.Store)
	n.Actions.Adapter.lostReply.Store(true)
	if _, err := n.Actions.Admitter.AdmitOrGet(t.Context(), actions.AdmissionRequest{Action: c.action, Source: c.source}); err == nil {
		t.Fatal("lost reply was hidden")
	}
	if f.endpoint.invocations.Load() != 1 {
		t.Fatalf("lost reply ran %d effects", f.endpoint.invocations.Load())
	}
	n.Actions.Adapter.lostReply.Store(false)
	again, err := n.Actions.Admitter.AdmitOrGet(t.Context(), actions.AdmissionRequest{Action: c.action, Source: c.source})
	if err != nil {
		t.Fatal(err)
	}
	if f.endpoint.invocations.Load() != 1 {
		t.Fatalf("retry after lost reply repeated the effect: %d", f.endpoint.invocations.Load())
	}
	if again.ActionID != c.action.ID || again.EnvelopeDigest != installedHexDigest(c.action.ExactEnvelope) || again.AdmissionID == "" {
		t.Fatalf("recovered receipt is not the retained one: %+v", again)
	}
}

// TestInstalledActionsRestartAfterAdmissionRecoversReceipt commits an admission
// on the installed node, then "crashes" without acking the delivery. On restart
// the delivery is redelivered and the Admitter recovers the retained receipt
// WITHOUT re-invoking the already-paid endpoint adapter.
func TestInstalledActionsRestartAfterAdmissionRecoversReceipt(t *testing.T) {
	f := newInstalledActionsFixture(t)
	n := f.openNode(t, nil)
	if _, err := n.Actions.Store.Trigger(t.Context(), f.source); err != nil {
		t.Fatal(err)
	}
	c := f.claim(t, n.Actions.Store)
	// Commit the admission (claim + receipt) and run the endpoint effect, then
	// crash before the delivery is acked: the lease is left unacked.
	if _, err := n.Actions.Admitter.AdmitOrGet(t.Context(), actions.AdmissionRequest{Action: c.action, Source: c.source}); err != nil {
		t.Fatal(err)
	}
	if f.endpoint.invocations.Load() != 1 {
		t.Fatalf("pre-restart effects: %d", f.endpoint.invocations.Load())
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	// Restart: the real installed node reopens the same installation.
	n2 := f.openNode(t, nil)
	defer n2.Close()
	// Let the unacked lease expire so the delivery is redelivered.
	time.Sleep(300 * time.Millisecond)
	d2 := f.claim(t, n2.Actions.Store)
	if _, err := n2.Actions.Admitter.AdmitOrGet(t.Context(), actions.AdmissionRequest{Action: d2.action, Source: d2.source}); err != nil {
		t.Fatal(err)
	}
	d2.ack(t, n2.Actions.Store)
	if f.endpoint.invocations.Load() != 1 {
		t.Fatalf("redelivery after restart repeated the paid effect: %d", f.endpoint.invocations.Load())
	}
}

// TestInstalledActionsRestartBeforeAdmissionDeliversOnce commits NOTHING on the
// installed node (the crash happens after the enqueue but before the admission
// commit). On restart the delivery is redelivered and admitted exactly once.
func TestInstalledActionsRestartBeforeAdmissionDeliversOnce(t *testing.T) {
	f := newInstalledActionsFixture(t)
	n := f.openNode(t, nil)
	if _, err := n.Actions.Store.Trigger(t.Context(), f.source); err != nil {
		t.Fatal(err)
	}
	// Claim the delivery (lease) then crash BEFORE admitting: no admission is
	// committed and the delivery is left unacked.
	f.claim(t, n.Actions.Store)
	if f.endpoint.invocations.Load() != 0 {
		t.Fatalf("pre-restart effects: %d", f.endpoint.invocations.Load())
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	// Restart: the real installed node reopens the same installation.
	n2 := f.openNode(t, nil)
	defer n2.Close()
	// Let the unacked lease expire, then redeliver and admit fresh.
	time.Sleep(300 * time.Millisecond)
	d2 := f.claim(t, n2.Actions.Store)
	if _, err := n2.Actions.Admitter.AdmitOrGet(t.Context(), actions.AdmissionRequest{Action: d2.action, Source: d2.source}); err != nil {
		t.Fatal(err)
	}
	d2.ack(t, n2.Actions.Store)
	if f.endpoint.invocations.Load() != 1 {
		t.Fatalf("restart-before-admission admitted %d times", f.endpoint.invocations.Load())
	}
}

// TestInstalledActionsTriggerSelfRecursionLoopRejected confirms a source whose
// genuine parent lineage already contains the trigger's ID is rejected on the
// installed node, not looped.
func TestInstalledActionsTriggerSelfRecursionLoopRejected(t *testing.T) {
	f := newInstalledActionsFixture(t)
	wrapper := func(inner actions.SourceAuthority) actions.SourceAuthority {
		return &installedActionLineage{inner: inner, parentID: "installed-loop-parent", lineage: []string{f.definition.ID}, target: f.endpointRef}
	}
	n := f.openNode(t, wrapper)
	defer n.Close()
	if _, err := n.Actions.Store.Trigger(t.Context(), f.source); err == nil {
		t.Fatal("trigger self-recursion loop accepted")
	}
	if f.endpoint.invocations.Load() != 0 {
		t.Fatalf("self-recursion loop reached the adapter: %d", f.endpoint.invocations.Load())
	}
}

// TestInstalledActionsEmitContinuationNewIDCarriesParentLineageAndDispatchesOnce
// confirms EMIT on the installed node creates a NEW invocation id that CONTINUES
// the original execution (parent id, ancestry, hops carried from the genuine
// authenticated parent), and dispatches the exact retained envelope exactly once.
func TestInstalledActionsEmitContinuationNewIDCarriesParentLineageAndDispatchesOnce(t *testing.T) {
	f := newInstalledActionsFixture(t)
	wrapper := func(inner actions.SourceAuthority) actions.SourceAuthority {
		return &installedActionLineage{inner: inner, parentID: "installed-continuation-parent", lineage: nil, target: f.endpointRef}
	}
	n := f.openNode(t, wrapper)
	defer n.Close()
	if _, err := n.Actions.Store.Emit(t.Context(), f.source, actions.EmitRequest{Target: f.endpointRef, Revision: f.revision, Input: json.RawMessage(`{"emit":"continuation"}`)}); err != nil {
		t.Fatal(err)
	}
	c := f.claim(t, n.Actions.Store)
	var envelope fabric.Envelope
	if fabric.DecodeJSON(c.action.ExactEnvelope, &envelope) != nil {
		t.Fatal("emit envelope undecodable")
	}
	if envelope.ID == "" || envelope.Context.ParentID != "installed-continuation-parent" ||
		len(envelope.Context.Ancestry) != 1 || envelope.Context.Ancestry[0] != "installed-continuation-parent" || envelope.Context.Hops != 1 {
		t.Fatalf("emit did not continue the original execution lineage: %+v", envelope.Context)
	}
	if _, err := n.Actions.Admitter.AdmitOrGet(t.Context(), actions.AdmissionRequest{Action: c.action, Source: c.source}); err != nil {
		t.Fatal(err)
	}
	c.ack(t, n.Actions.Store)
	if f.endpoint.invocations.Load() != 1 {
		t.Fatalf("emit continuation dispatched %d times", f.endpoint.invocations.Load())
	}
	// An exact retry of the same emit is a duplicate and never re-dispatches.
	if _, err := n.Actions.Store.Emit(t.Context(), f.source, actions.EmitRequest{Target: f.endpointRef, Revision: f.revision, Input: json.RawMessage(`{"emit":"continuation"}`)}); err != nil {
		t.Fatal(err)
	}
	if f.endpoint.invocations.Load() != 1 {
		t.Fatalf("emit retry re-dispatched: %d", f.endpoint.invocations.Load())
	}
}

// TestInstalledActionsProviderCrashRetainsUnknownWithNoSecondEffect lets the
// provider crash after the admission commit on the installed node. The retained
// receipt is recovered; the endpoint effect is never repeated.
func TestInstalledActionsProviderCrashRetainsUnknownWithNoSecondEffect(t *testing.T) {
	f := newInstalledActionsFixture(t)
	n := f.openNode(t, nil)
	defer n.Close()
	if _, err := n.Actions.Store.Trigger(t.Context(), f.source); err != nil {
		t.Fatal(err)
	}
	c := f.claim(t, n.Actions.Store)
	n.Actions.Adapter.providerCrash.Store(true)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("provider did not crash as scripted")
			}
		}()
		_, _ = n.Actions.Admitter.AdmitOrGet(t.Context(), actions.AdmissionRequest{Action: c.action, Source: c.source})
	}()
	n.Actions.Adapter.providerCrash.Store(false)
	recovered, err := n.Actions.Admitter.AdmitOrGet(t.Context(), actions.AdmissionRequest{Action: c.action, Source: c.source})
	if err != nil {
		t.Fatal(err)
	}
	if recovered.AdmissionID == "" || recovered.ActionID != c.action.ID {
		t.Fatalf("crash did not retain a durable receipt: %+v", recovered)
	}
	effectsAfter := f.endpoint.invocations.Load()
	if _, err := n.Actions.Admitter.AdmitOrGet(t.Context(), actions.AdmissionRequest{Action: c.action, Source: c.source}); err != nil {
		t.Fatal(err)
	}
	if f.endpoint.invocations.Load() != effectsAfter {
		t.Fatalf("crashed admission re-dispatched a paid operation: %d -> %d", effectsAfter, f.endpoint.invocations.Load())
	}
}
