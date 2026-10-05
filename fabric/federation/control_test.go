package federation_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/federation"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fixtureControlGate struct {
	f      *ledgerFixture
	caller fabric.ExecutionContext
}

func (g fixtureControlGate) WithControl(ctx context.Context, f registry.ControlFacts, accept func(context.Context) error) error {
	raw, e := f.Frame.SigningBytes()
	if e != nil || g.caller.VerifyAuthenticatedData(raw, g.f.source.Namespace()) != nil {
		return fabric.NewError(fabric.CodeUnauthenticated, "fixture current source session denied")
	}
	return accept(ctx)
}
func (g fixtureControlGate) CheckControlTx(ctx context.Context, tx *registry.AuthorityTx, f registry.ControlFacts) error {
	return g.f.sourceGate.WithCurrentTx(ctx, tx, g.f.cfg.Remote, g.f.cfg.Local, func(context.Context) error { return nil })
}

// Explicit independently current operator ingress fixture. It deliberately reads
// the actual registry here, proving this port is called OUTSIDE ledger SQL.
type fixtureControlAuth struct {
	f    *ledgerFixture
	deny atomic.Bool
}

func (a *fixtureControlAuth) AuthenticateControl(ctx context.Context, c federation.Config, r federation.ControlRequest, accept func(context.Context, fabric.ExecutionContext) error) error {
	if a.deny.Load() {
		return fabric.NewError(fabric.CodeUnauthenticated, "fixture current session revoked")
	}
	if _, e := a.f.destination.CurrentAuthorityIdentity(ctx); e != nil {
		return e
	}
	raw, e := r.Proof.Frame.SigningBytes()
	if e != nil {
		return e
	}
	caller, e := fabric.NewAuthenticatedContext(r.Proof.Frame.Principal, a.f.destination.Namespace(), raw)
	if e != nil {
		return e
	}
	return accept(ctx, caller)
}

type fixtureControlResult struct{ deny atomic.Bool }

func (v *fixtureControlResult) VerifyControlResultTx(ctx context.Context, tx *registry.AuthorityTx, f federation.AdmissionFacts, r federation.ControlRequest, result federation.ControlResult) error {
	if v.deny.Load() {
		return fabric.NewError(fabric.CodeUnauthenticated, "fixture unverified source result denied")
	}
	_, e := tx.Get(registry.AuthorityKey{Kind: registry.AuthorityFederationInvocation, ID: "configuration-v1"})
	return e
}
func signedControl(t *testing.T, f *ledgerFixture, action, id, attempt string, p federation.ControlPayload) federation.ControlRequest {
	t.Helper()
	payload, _ := json.Marshal(p)
	now := time.Now().UTC().Add(-time.Millisecond)
	frame := fabric.ControlFrame{ProtocolVersion: "1", SourceDomain: f.source.Namespace(), SourceStoreID: f.cfg.Remote.Authority.StoreID, SourceKeyRevision: f.cfg.Remote.Authority.KeyRevision, DestinationDomain: f.destination.Namespace(), DestinationStoreID: f.cfg.Local.Authority.StoreID, SourcePeerBindingDigest: f.cfg.Remote.BindingDigest, DestinationPeerBindingDigest: f.cfg.Local.BindingDigest, Principal: f.bundle.Proof.Frame.Principal, OriginalPrincipal: f.bundle.Proof.Frame.Principal, InvocationID: f.bundle.Proof.Frame.InvocationID, ReceiptDigest: sha256.Sum256(mustEncodeBundle(t, f.bundle)), AttemptID: attempt, Action: action, PayloadDigest: sha256.Sum256(payload), ReplayID: id, IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(20 * time.Second).Format(time.RFC3339Nano), BindingProfile: federation.Profile}
	raw, e := frame.SigningBytes()
	if e != nil {
		t.Fatal(e)
	}
	caller, e := fabric.NewAuthenticatedContext(frame.Principal, f.source.Namespace(), raw)
	if e != nil {
		t.Fatal(e)
	}
	proof, e := f.source.SignControlExact(context.Background(), f.sourceOwner, caller, payload, frame, fixtureControlGate{f, caller})
	if e != nil {
		t.Fatal(e)
	}
	return federation.ControlRequest{Proof: proof, Payload: payload}
}
func mustEncodeBundle(t *testing.T, b federation.ForwardBundle) []byte {
	t.Helper()
	raw, e := federation.EncodeForwardBundle(b)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func newControlFixture(t *testing.T) (ledgerFixture, *federation.ControlLedger, *fixtureControlAuth, *fixtureControlResult) {
	return newControlFixtureCapacity(t, 16)
}
func newControlFixtureCapacity(t *testing.T, max uint64) (ledgerFixture, *federation.ControlLedger, *fixtureControlAuth, *fixtureControlResult) {
	t.Helper()
	f := newLedgerFixture(t, 8)
	ctx := context.Background()
	if _, _, e := f.ledger.Admit(ctx, f.cfg, f.bundle, f.caller); e != nil {
		t.Fatal(e)
	}
	auth := &fixtureControlAuth{f: &f}
	result := &fixtureControlResult{}
	cursor := federation.ConsumerCursor{Ordinal: 0, FrameDigest: sha256.Sum256([]byte("exact-original-frame"))}
	ledger, e := federation.BootstrapControlLedger(ctx, federation.ControlConfig{Ledger: f.ledger, Authenticator: auth, MaxControls: max, Cursors: knownFrameVerifier{cursor}, Results: result})
	if e != nil {
		t.Fatal(e)
	}
	return f, ledger, auth, result
}
func TestActualControlFullIntentReplayResultAndCurrentSession(t *testing.T) {
	f, l, auth, resultGate := newControlFixture(t)
	ctx := context.Background()
	request := signedControl(t, &f, "cancel", "fresh-control-global-id", "", federation.ControlPayload{})
	p, state, fresh, e := l.Begin(ctx, f.cfg, request)
	if e != nil || !fresh || !state.Status.CancelRequested || state.Result != nil {
		t.Fatal("durable stop intent", e)
	}
	_, state, fresh, e = l.Begin(ctx, f.cfg, request)
	if e != nil || fresh || state.Result != nil {
		t.Fatal("uncertain actuation authorized retry", e)
	}
	result := federation.ControlResult{State: "confirmed", ResponseDigest: sha256.Sum256([]byte("actual-original-stop-ACK-fixture")), StopAcknowledged: true}
	resultGate.deny.Store(true)
	if e = l.Complete(ctx, f.cfg, p, result); e == nil {
		t.Fatal("wire-only stop ACK accepted")
	}
	resultGate.deny.Store(false)
	if e = l.Complete(ctx, f.cfg, p, result); e != nil {
		t.Fatal(e)
	}
	if e = l.Complete(ctx, f.cfg, p, result); e != nil {
		t.Fatal("exact result checkpoint retry", e)
	}
	_, state, fresh, e = l.Begin(ctx, f.cfg, request)
	if e != nil || fresh || state.Result == nil || !state.Result.StopAcknowledged {
		t.Fatal("actual result not retained", e)
	}
	changed := result
	changed.ResponseDigest[0] ^= 1
	if e = l.Complete(ctx, f.cfg, p, changed); e == nil {
		t.Fatal("changed checkpoint accepted")
	}
	altered := signedControl(t, &f, "status", "fresh-control-global-id", "", federation.ControlPayload{})
	if _, _, _, e = l.Begin(ctx, f.cfg, altered); e == nil {
		t.Fatal("global control replay remapped action")
	}
	auth.deny.Store(true)
	if _, _, _, e = l.Begin(ctx, f.cfg, request); e == nil {
		t.Fatal("historical proof substituted for current session")
	}
}
func TestActualControlACKCommitsOriginalConsumerFloorBeforeActuation(t *testing.T) {
	f, l, _, _ := newControlFixture(t)
	ctx := context.Background()
	a, _, e := f.ledger.Admit(ctx, f.cfg, f.bundle, f.caller)
	if e != nil {
		t.Fatal(e)
	}
	permit, _, e := f.ledger.MarkAttempt(ctx, f.cfg, a, f.caller)
	if e != nil {
		t.Fatal(e)
	}
	association := federation.Association{Protocol: "native.local", BindingDigest: sha256.Sum256([]byte("original-binding")), PrivateReference: json.RawMessage(`{"originalCommand":"retained"}`)}
	if e = f.ledger.Associate(ctx, f.cfg, a, f.caller, permit, association); e != nil {
		t.Fatal(e)
	}
	floor := federation.ConsumerCursor{Ordinal: -1}
	next := federation.ConsumerCursor{Ordinal: 0, FrameDigest: sha256.Sum256([]byte("exact-original-frame"))}
	request := signedControl(t, &f, "ack", "exact-ACK-control", permit.ID(), federation.ControlPayload{Cursor: &floor, NextCursor: &next})
	_, state, fresh, e := l.Begin(ctx, f.cfg, request)
	if e != nil || !fresh || state.Status.Cursor != next {
		t.Fatal("floor not FULL before source ACK", e)
	}
	status, e := f.ledger.Status(ctx, f.cfg, a, f.caller)
	if e != nil || status.Cursor != next {
		t.Fatal("original consumer floor absent", e)
	}
	stale := signedControl(t, &f, "pull", "stale-pull", permit.ID(), federation.ControlPayload{Cursor: &floor, Credit: 4})
	if _, _, _, e = l.Begin(ctx, f.cfg, stale); e == nil {
		t.Fatal("pull silently resumed cursor zero")
	}
	request = signedControl(t, &f, "pull", "bounded-pull", permit.ID(), federation.ControlPayload{Cursor: &next, Credit: 4})
	if _, _, fresh, e = l.Begin(ctx, f.cfg, request); e != nil || !fresh {
		t.Fatal(e)
	}
	over := signedControl(t, &f, "pull", "excessive-credit", permit.ID(), federation.ControlPayload{Cursor: &next, Credit: 5})
	if _, _, _, e = l.Begin(ctx, f.cfg, over); e == nil {
		t.Fatal("unbounded pull credit")
	}
}

func TestActualControlRegistryRestartRetainsUnknownAndExactResult(t *testing.T) {
	f, l, auth, result := newControlFixture(t)
	ctx := context.Background()
	request := signedControl(t, &f, "status", "retained-control", "", federation.ControlPayload{})
	p, _, fresh, e := l.Begin(ctx, f.cfg, request)
	if e != nil || !fresh {
		t.Fatal(e)
	}
	completed := federation.ControlResult{State: "confirmed", ResponseDigest: sha256.Sum256([]byte("actual-status-result-fixture"))}
	if e = l.Complete(ctx, f.cfg, p, completed); e != nil {
		t.Fatal(e)
	}
	reopenLedgerFixture(t, &f)
	auth.f = &f
	config := federation.ControlConfig{Ledger: f.ledger, Authenticator: auth, MaxControls: 16, Cursors: knownFrameVerifier{federation.ConsumerCursor{Ordinal: 0, FrameDigest: sha256.Sum256([]byte("exact-original-frame"))}}, Results: result}
	l, e = federation.OpenControlLedger(ctx, config)
	if e != nil {
		t.Fatal(e)
	}
	if e = l.Complete(ctx, f.cfg, p, completed); e == nil {
		t.Fatal("opaque control from closed ledger accepted")
	}
	_, state, fresh, e := l.Begin(ctx, f.cfg, request)
	if e != nil || fresh || state.Result == nil || state.Result.ResponseDigest != completed.ResponseDigest {
		t.Fatal("retained control result lost/reexecuted", e)
	}
	if _, e = federation.BootstrapControlLedger(ctx, config); e == nil {
		t.Fatal("control replay fence reset")
	}
	config.MaxControls++
	if _, e = federation.OpenControlLedger(ctx, config); e == nil {
		t.Fatal("retained control quota silently changed")
	}
}

type controlRelaySpy struct {
	federation.PacketStream
	mu      sync.Mutex
	records [][]byte
}

func (s *controlRelaySpy) Write(ctx context.Context, p federation.Packet) error {
	raw, _ := json.Marshal(p)
	s.mu.Lock()
	s.records = append(s.records, raw)
	s.mu.Unlock()
	return s.PacketStream.Write(ctx, p)
}
func TestActualControlEncryptedBlindRelayAndPrivateAssociationOmission(t *testing.T) {
	f, l, _, _ := newControlFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sourceCfg := f.cfg
	sourceCfg.Local = f.cfg.Remote
	sourceCfg.Remote = f.cfg.Local
	sourceCfg.Keys = f.sourceKey
	sourceCfg.Trust = f.sourceGate
	sourceCfg.SourceRole = true
	left, relayLeft := net.Pipe()
	relayRight, right := net.Pipe()
	stream := func(c net.Conn) federation.PacketStream {
		s, e := federation.NewConnStream(c, 3*time.Second)
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	a, e := federation.NewDuplex(ctx, sourceCfg, stream(left), 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	b, e := federation.NewDuplex(ctx, f.cfg, stream(right), 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	source, _ := federation.NewForwardChannel(a)
	dest, _ := federation.NewForwardChannel(b)
	defer source.Close()
	defer dest.Close()
	spy := &controlRelaySpy{PacketStream: stream(relayRight)}
	relayDone := make(chan error, 1)
	go func() {
		relayDone <- federation.RelayOpaque(ctx, stream(relayLeft), spy, f.cfg.Channel, federation.RelayLimits{MaxPackets: 16, MaxBytes: 1 << 20, Lifetime: 4 * time.Second})
	}()
	request := signedControl(t, &f, "status", "private-control-replay", "", federation.ControlPayload{})
	sent := make(chan error, 1)
	go func() { sent <- source.SendControl(ctx, request) }()
	received, e := dest.ReceiveControl(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = <-sent; e != nil {
		t.Fatal(e)
	}
	_, state, fresh, e := l.Begin(ctx, f.cfg, received)
	if e != nil || !fresh {
		t.Fatal(e)
	}
	// Even trusted composition accidentally passing private association metadata
	// cannot put it on the control reply wire.
	state.Status.Association = &federation.Association{Protocol: "native.local", PrivateReference: json.RawMessage(`{"secret":"must-not-federate"}`)}
	go func() { sent <- dest.SendControlReply(ctx, received, state) }()
	reply, e := source.ReceiveControlReply(ctx, request)
	if e != nil {
		t.Fatal(e)
	}
	if e = <-sent; e != nil {
		t.Fatal(e)
	}
	encoded, _ := json.Marshal(reply)
	if bytes.Contains(encoded, []byte("must-not-federate")) || reply.Result != nil {
		t.Fatal("intent ACK exposed association or invented completed result")
	}
	spy.mu.Lock()
	for _, raw := range spy.records {
		for _, private := range [][]byte{[]byte(request.Proof.Frame.Principal.Ref), []byte(request.Proof.Frame.ReplayID), []byte(f.source.Namespace()), []byte("cursor")} {
			if bytes.Contains(raw, private) {
				t.Fatal("blind relay disclosed private control")
			}
		}
	}
	spy.mu.Unlock()
	source.Close()
	select {
	case <-relayDone:
	case <-time.After(time.Second):
		t.Fatal("owned relay did not join")
	}
}

type explicitOperatorPolicy struct{ operator, original fabric.Principal }

func (p explicitOperatorPolicy) AuthorizeTx(ctx context.Context, tx *registry.AuthorityTx, action federation.AdmissionAction, c fabric.ExecutionContext, f federation.AdmissionFacts) error {
	if f.Principal != p.original || c.PrincipalView() != p.original && c.PrincipalView() != p.operator {
		return fabric.NewError(fabric.CodeUnauthenticated, "explicit fixture operator grant denied")
	}
	_, e := tx.Get(registry.AuthorityKey{Kind: registry.AuthorityFederationInvocation, ID: "configuration-v1"})
	return e
}
func resignControl(t *testing.T, f *ledgerFixture, r federation.ControlRequest) federation.ControlRequest {
	t.Helper()
	raw, e := r.Proof.Frame.SigningBytes()
	if e != nil {
		t.Fatal(e)
	}
	caller, e := fabric.NewAuthenticatedContext(r.Proof.Frame.Principal, f.source.Namespace(), raw)
	if e != nil {
		t.Fatal(e)
	}
	r.Proof, e = f.source.SignControlExact(context.Background(), f.sourceOwner, caller, r.Payload, r.Proof.Frame, fixtureControlGate{f, caller})
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func TestActualControlOperatorUsesOwnIdentityForOriginalManagedSubject(t *testing.T) {
	f, l, auth, results := newControlFixture(t)
	ctx := context.Background()
	original := f.bundle.Proof.Frame.Principal
	operator := f.sourceOwner.PrincipalView()
	request := signedControl(t, &f, "cancel", "operator-own-control", "", federation.ControlPayload{})
	request.Proof.Frame.Principal = operator
	request = resignControl(t, &f, request)
	if _, _, _, e := l.Begin(ctx, f.cfg, request); e == nil {
		t.Fatal("owner identity inferred an original agent grant")
	}
	f.admissionConfig.Policy = explicitOperatorPolicy{operator, original}
	var e error
	f.ledger, e = federation.OpenAdmissionLedger(ctx, f.admissionConfig)
	if e != nil {
		t.Fatal(e)
	}
	auth.f = &f
	l, e = federation.OpenControlLedger(ctx, federation.ControlConfig{Ledger: f.ledger, Authenticator: auth, MaxControls: 16, Cursors: knownFrameVerifier{federation.ConsumerCursor{Ordinal: 0, FrameDigest: sha256.Sum256([]byte("exact-original-frame"))}}, Results: results})
	if e != nil {
		t.Fatal(e)
	}
	_, state, fresh, e := l.Begin(ctx, f.cfg, request)
	if e != nil || !fresh || !state.Status.CancelRequested {
		t.Fatal("explicit current operator grant failed", e)
	}
	if request.Proof.Frame.Principal != operator || request.Proof.Frame.OriginalPrincipal != original {
		t.Fatal("operator pretended to be agent")
	}
	changed := request
	changed.Proof.Frame.OriginalPrincipal.Issuer = "different-original-issuer"
	changed = resignControl(t, &f, changed)
	if _, _, _, e = l.Begin(ctx, f.cfg, changed); e == nil {
		t.Fatal("operator selected invented original subject")
	}
}
func TestActualControlExpiryForgeryAndCurrentHistoricalReadback(t *testing.T) {
	f, l, _, _ := newControlFixture(t)
	ctx := context.Background()
	request := signedControl(t, &f, "status", "exact-control-expiry", "", federation.ControlPayload{})
	cutoff := time.Now().UTC().Add(time.Second)
	request.Proof.Frame.ExpiresAt = cutoff.Format(time.RFC3339Nano)
	request = resignControl(t, &f, request)
	if _, _, fresh, e := l.Begin(ctx, f.cfg, request); e != nil || !fresh {
		t.Fatal(e)
	}
	neverAdmitted := request
	neverAdmitted.Proof.Frame.ReplayID = "never-admitted-expired-control"
	neverAdmitted = resignControl(t, &f, neverAdmitted)
	time.Sleep(time.Until(cutoff) + 20*time.Millisecond)
	if _, _, fresh, e := l.Begin(ctx, f.cfg, request); e != nil || fresh {
		t.Fatal("current-authenticated historical readback", e)
	}
	if _, _, _, e := l.Begin(ctx, f.cfg, neverAdmitted); e == nil {
		t.Fatal("valid signed but expired new control admitted")
	}
	// A fresh ReplayID with an expired signature is not an existing receipt.
	expired := request
	expired.Proof.Frame.ReplayID = "never-admitted-expired-control"
	// It cannot be signed by the real current root after expiry; mutate the ID
	// to additionally prove signature forgery is rejected before admission.
	if _, _, _, e := l.Begin(ctx, f.cfg, expired); e == nil {
		t.Fatal("forged or expired new control admitted")
	}
	altered := request
	altered.Payload = json.RawMessage(`{"credit":1}`)
	if _, _, _, e := l.Begin(ctx, f.cfg, altered); e == nil {
		t.Fatal("signed payload mutation admitted")
	}
}

func TestActualControlConcurrentChannelIndependentReplayAndCapacity(t *testing.T) {
	f, l, _, _ := newControlFixtureCapacity(t, 1)
	ctx := context.Background()
	request := signedControl(t, &f, "status", "global-control-on-two-channels", "", federation.ControlPayload{})
	var wg sync.WaitGroup
	var freshCount atomic.Int64
	errs := make(chan error, 4)
	for i := range 4 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := f.cfg
			c.Channel.ID[0] ^= byte(i + 1)
			_, _, fresh, e := l.Begin(ctx, c, request)
			if e != nil {
				errs <- e
				return
			}
			if fresh {
				freshCount.Add(1)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	if freshCount.Load() != 1 {
		t.Fatal("channel-scoped duplicate control", freshCount.Load())
	}
	next := signedControl(t, &f, "status", "second-control-over-capacity", "", federation.ControlPayload{})
	for range 2 {
		if _, _, _, e := l.Begin(ctx, f.cfg, next); e == nil {
			t.Fatal("control count exceeded or quota failure committed receipt")
		}
	}
	if _, _, fresh, e := l.Begin(ctx, f.cfg, request); e != nil || fresh {
		t.Fatal("capacity exhausted existing exact history", e)
	}
}

type panicControlAuth struct {
	accept func(context.Context, fabric.ExecutionContext) error
	caller fabric.ExecutionContext
}

func (a *panicControlAuth) AuthenticateControl(ctx context.Context, c federation.Config, r federation.ControlRequest, accept func(context.Context, fabric.ExecutionContext) error) error {
	raw, e := r.Proof.Frame.SigningBytes()
	if e != nil {
		return e
	}
	a.caller, e = fabric.NewAuthenticatedContext(r.Proof.Frame.Principal, c.Local.Authority.Namespace, raw)
	if e != nil {
		return e
	}
	a.accept = accept
	panic("private authenticator failure")
}
func TestActualControlRecoveredAuthenticatorPanicFencesRetainedCallback(t *testing.T) {
	f, _, _, results := newControlFixture(t)
	ctx := context.Background()
	auth := &panicControlAuth{}
	l, e := federation.OpenControlLedger(ctx, federation.ControlConfig{Ledger: f.ledger, Authenticator: auth, MaxControls: 16, Cursors: knownFrameVerifier{federation.ConsumerCursor{Ordinal: 0, FrameDigest: sha256.Sum256([]byte("exact-original-frame"))}}, Results: results})
	if e != nil {
		t.Fatal(e)
	}
	request := signedControl(t, &f, "cancel", "captured-panic-control", "", federation.ControlPayload{})
	recovered := false
	func() { defer func() { recovered = recover() != nil }(); l.Begin(ctx, f.cfg, request) }()
	if !recovered || auth.accept == nil {
		t.Fatal("authenticator did not capture/panic")
	}
	if e = auth.accept(ctx, auth.caller); e == nil {
		t.Fatal("retained authentication callback remained live")
	}
	a, fresh, e := f.ledger.Admit(ctx, f.cfg, f.bundle, f.caller)
	if e != nil || fresh {
		t.Fatal(e)
	}
	state, e := f.ledger.Status(ctx, f.cfg, a, f.caller)
	if e != nil || state.CancelRequested {
		t.Fatal("panicked/late control mutated original invocation", e)
	}
}
