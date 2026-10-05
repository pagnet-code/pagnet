package fabricservices

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// Trusted fixture policy exercises actual signed ledger/crypto/node boundaries.
// Kernel/live-managed authorization is the production LocalBoundary's separate
// conformance; no fixture policy is installed as product authority.
type aliasPolicyFixture struct {
	servicePolicyFixture
	denied  atomic.Bool
	mode    string
	escaped func(context.Context) error
}

func (p *aliasPolicyFixture) AuthorizeHistoryTx(ctx context.Context, tx *registry.AuthorityTx, c fabric.ExecutionContext, current, original InvocationFacts, action string) error {
	if p.denied.Load() || !semanticEqual(current, original) {
		return denied()
	}
	switch action {
	case "alias_admit", "alias_verify", "alias_pull":
	default:
		return denied()
	}
	return p.AuthorizeTx(ctx, tx, c, current, action)
}
func (p *aliasPolicyFixture) WithReplayRequest(ctx context.Context, c fabric.ExecutionContext, f InvocationFacts, next func(context.Context) error) error {
	if p.denied.Load() || c.PrincipalView() != f.Principal {
		return denied()
	}
	switch p.mode {
	case "none":
		return nil
	case "swallow":
		_ = next(ctx)
		return nil
	case "repeat":
		_ = next(ctx)
		return next(ctx)
	case "late":
		p.escaped = next
		return nil
	}
	return next(ctx)
}

type aliasSource struct {
	id      string
	ordinal uint64
}

func (s *aliasSource) Next(context.Context) (fabric.InvocationFrame, error) {
	f := fabric.InvocationFrame{InvocationID: s.id, Sequence: s.ordinal}
	switch s.ordinal {
	case 0:
		f.Kind = fabric.FrameStart
	case 1:
		f.Kind = fabric.FrameChunk
		f.ContentType = "application/json"
		f.Data = []byte(`{"n":9007199254740993123456789}`)
	case 2:
		f.Kind = fabric.FrameComplete
	default:
		return f, io.EOF
	}
	s.ordinal++
	return f, nil
}
func (*aliasSource) Close() error { return nil }
func aliasRequest(scope registry.DescriptorBatchScope, id string) fabric.InvokeRequest {
	return fabric.InvokeRequest{InvocationID: id, Target: scope.Endpoint, ExpectedRevision: scope.ExpectedEndpointRevision, Input: json.RawMessage(`{"input":"exact"}`), IdempotencyKey: "same-paid-attempt"}
}
func aliasExecute(ctx context.Context, p *ProfileStore, i *Invocations, fp [32]byte, scope registry.DescriptorBatchScope, r fabric.InvokeRequest, effects *atomic.Int32, unknown bool, modify func(*Receipt)) (node.Result, error) {
	dispatcher := serviceDispatcherFixture(func(ctx context.Context, c fabric.ExecutionContext, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
		receipt, fresh, e := i.Reserve(ctx, c, scope, fp, r)
		if e != nil {
			return nil, e
		}
		if !fresh {
			if !receipt.Terminal {
				return nil, &fabric.Error{Code: "service.REPLAY_UNKNOWN", Effect: fabric.EffectUnknown}
			}
			if modify != nil {
				modify(&receipt)
			}
			return newReplayStream(ctx, i, c, receipt), nil
		}
		effects.Add(1)
		if unknown {
			return nil, &fabric.Error{Code: "service.REPLAY_UNKNOWN", Effect: fabric.EffectUnknown}
		}
		return &retainedStream{InvocationStream: &aliasSource{id: r.InvocationID}, ledger: i, caller: c, receipt: receipt, ctx: ctx}, nil
	})
	service, e := node.New(node.Config{Audience: p.root.Namespace, Authenticator: serviceAuthFixture{p.root.Owner}, Dispatcher: dispatcher, ReplayVerifier: i})
	if e != nil {
		return node.Result{}, e
	}
	env := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: r.InvocationID, Operation: fabric.OperationInvoke, Principal: p.root.Owner, Source: p.root.Owner.Ref, Target: &r.Target, ExpectedRevision: r.ExpectedRevision, CreatedAt: time.Unix(1000, 0).UTC(), Payload: r.Input, Context: fabric.EnvelopeContext{Origin: p.root.Owner.Ref, Deadline: r.Deadline, IdempotencyKey: r.IdempotencyKey}}
	raw, _ := json.Marshal(env)
	return service.Execute(ctx, raw, nil)
}
func aliasDrain(t *testing.T, result node.Result) []fabric.InvocationFrame {
	t.Helper()
	defer result.Stream.Close()
	var frames []fabric.InvocationFrame
	for {
		f, e := result.Stream.Next(t.Context())
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		frames = append(frames, f)
	}
	return frames
}
func aliasSetup(t *testing.T, config InvocationConfig) (*ProfileStore, *Invocations, *aliasPolicyFixture, registry.DescriptorBatchScope, [32]byte, string) {
	t.Helper()
	p, scope, _, dir := serviceFixture(t)
	profile := serviceProfile()
	gen, e := p.Install(t.Context(), scope, profile)
	if e != nil {
		t.Fatal(e)
	}
	policy := &aliasPolicyFixture{servicePolicyFixture: servicePolicyFixture{p.root.Owner}}
	i, e := BootstrapInvocations(t.Context(), p, config, policy)
	if e != nil {
		t.Fatal(e)
	}
	return p, i, policy, scope, Fingerprint(scope, profile, gen), dir
}
func TestActualSignedAliasRestartExactNewIDRetryNoResendAndOriginalFrames(t *testing.T) {
	p, i, policy, scope, fp, dir := aliasSetup(t, DefaultInvocationConfig())
	var effects atomic.Int32
	original, e := aliasExecute(t.Context(), p, i, fp, scope, aliasRequest(scope, "original"), &effects, false, nil)
	if e != nil {
		t.Fatal(e)
	}
	frames := aliasDrain(t, original)
	current := aliasRequest(scope, "fresh-request")
	alias, e := aliasExecute(t.Context(), p, i, fp, scope, current, &effects, false, nil)
	if e != nil {
		t.Fatal(e)
	}
	if alias.Replay == nil || alias.Replay.RequestID != current.InvocationID || alias.Replay.ExecutionID != "original" {
		t.Fatal(alias)
	}
	replayed := aliasDrain(t, alias)
	a, _ := json.Marshal(frames)
	b, _ := json.Marshal(replayed)
	if string(a) != string(b) || effects.Load() != 1 {
		t.Fatal("frames relabeled or resent", effects.Load())
	}
	proof := alias.Replay.Clone()
	if e = p.store.Close(); e != nil {
		t.Fatal(e)
	}
	root, e := registry.Open(t.Context(), dir)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	p2, e := NewProfileStore(t.Context(), root, p.owner, p.protector)
	if e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenInvocations(t.Context(), p2, DefaultInvocationConfig(), policy)
	if e != nil {
		t.Fatal(e)
	}
	repeat, e := aliasExecute(t.Context(), p2, reopened, fp, scope, current, &effects, false, nil)
	if e != nil {
		t.Fatal(e)
	}
	again, _ := json.Marshal(repeat.Replay)
	old, _ := json.Marshal(proof)
	if string(again) != string(old) {
		t.Fatal("restart changed signed association")
	}
	aliasDrain(t, repeat)
	changed := current
	changed.Input = json.RawMessage(`{"input":"changed"}`)
	if _, e = aliasExecute(t.Context(), p2, reopened, fp, scope, changed, &effects, false, nil); e == nil {
		t.Fatal("same new-ID mutated current facts")
	}
	newer := aliasRequest(scope, "another-current")
	newer.Input = changed.Input
	if _, e = aliasExecute(t.Context(), p2, reopened, fp, scope, newer, &effects, false, nil); e == nil {
		t.Fatal("same key changed semantic input")
	}
	if effects.Load() != 1 {
		t.Fatal("replayed external effect")
	}
}
func TestAliasUnknownAndConcurrentFreshIDsNeverRepeatOriginalEffect(t *testing.T) {
	p, i, _, scope, fp, _ := aliasSetup(t, DefaultInvocationConfig())
	var effects atomic.Int32
	_, e := aliasExecute(t.Context(), p, i, fp, scope, aliasRequest(scope, "original"), &effects, true, nil)
	if e == nil {
		t.Fatal("unknown fixture")
	}
	var group sync.WaitGroup
	for n := 0; n < 8; n++ {
		group.Add(1)
		go func(n int) {
			defer group.Done()
			r := aliasRequest(scope, string(rune('a'+n)))
			_, e := aliasExecute(t.Context(), p, i, fp, scope, r, &effects, false, nil)
			var f *fabric.Error
			if !errors.As(e, &f) || f.Effect != fabric.EffectUnknown {
				t.Errorf("lost unknown original outcome: %v", e)
			}
		}(n)
	}
	group.Wait()
	if effects.Load() != 1 {
		t.Fatal("unknown original resent")
	}
}
func TestAliasProofCurrentPolicyQuotaAndRecordMutationFailClosed(t *testing.T) {
	p, i, policy, scope, fp, _ := aliasSetup(t, DefaultInvocationConfig())
	var effects atomic.Int32
	original, e := aliasExecute(t.Context(), p, i, fp, scope, aliasRequest(scope, "original"), &effects, false, nil)
	if e != nil {
		t.Fatal(e)
	}
	aliasDrain(t, original)
	for _, mutate := range []func(*fabric.ReplayAssociation){func(a *fabric.ReplayAssociation) { a.Proof[0] ^= 1 }, func(a *fabric.ReplayAssociation) { a.ExecutionID = "foreign-source" }, func(a *fabric.ReplayAssociation) { a.Principal.Issuer = "foreign" }, func(a *fabric.ReplayAssociation) { a.AuthorityStoreID = "foreign-store" }, func(a *fabric.ReplayAssociation) { a.BindingFingerprint[0] ^= 1 }, func(a *fabric.ReplayAssociation) { a.OriginalReceiptSHA[0] ^= 1 }} {
		_, e := aliasExecute(t.Context(), p, i, fp, scope, aliasRequest(scope, "alias"), &effects, false, func(r *Receipt) { a := r.Replay.Clone(); mutate(&a); r.Replay = &a })
		if e == nil {
			t.Fatal("forged association accepted")
		}
	}
	result, e := aliasExecute(t.Context(), p, i, fp, scope, aliasRequest(scope, "alias"), &effects, false, nil)
	if e != nil {
		t.Fatal(e)
	}
	policy.denied.Store(true)
	if _, e = result.Stream.Next(t.Context()); e == nil {
		t.Fatal("revoked policy delivered retained frame")
	}
	result.Stream.Close()
	policy.denied.Store(false)
	// A legitimate signed change to a retained alias invalidates the old proof;
	// no signature-only verifier may accept the superseded record.
	e = i.with(t.Context(), scope, func(_ context.Context, tx *registry.AuthorityTx) error {
		var alias aliasRecord
		row, e := i.decode(tx, aliasID(p.root.Owner, "alias"), &alias)
		if e != nil {
			return e
		}
		alias.ReceiptSHA[0] ^= 1
		value, e := i.encode(aliasID(p.root.Owner, "alias"), alias)
		if e != nil {
			return e
		}
		_, e = tx.CAS(row.Key, row.Revision, value, false)
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = aliasExecute(t.Context(), p, i, fp, scope, aliasRequest(scope, "alias"), &effects, false, nil); e == nil {
		t.Fatal("signed wrong receipt association accepted")
	}
	quota := DefaultInvocationConfig()
	quota.MaxInvocations = 2
	p3, i3, _, s3, f3, _ := aliasSetup(t, quota)
	var effects3 atomic.Int32
	out, e := aliasExecute(t.Context(), p3, i3, f3, s3, aliasRequest(s3, "original"), &effects3, false, nil)
	if e != nil {
		t.Fatal(e)
	}
	aliasDrain(t, out)
	if _, e = aliasExecute(t.Context(), p3, i3, f3, s3, aliasRequest(s3, "alias"), &effects3, false, nil); e == nil || effects3.Load() != 1 {
		t.Fatal("alias over budget retried original effect")
	}
}

func TestAliasChangedSelectionAndBrokenPolicyFencesFailClosed(t *testing.T) {
	p, i, policy, scope, fp, _ := aliasSetup(t, DefaultInvocationConfig())
	var effects atomic.Int32
	original, e := aliasExecute(t.Context(), p, i, fp, scope, aliasRequest(scope, "original"), &effects, false, nil)
	if e != nil {
		t.Fatal(e)
	}
	aliasDrain(t, original)
	for _, change := range []string{"target", "revision", "account", "key-current-id", "no-key-current-id"} {
		r := aliasRequest(scope, "current")
		selectedFP := fp
		switch change {
		case "target":
			r.Target, _ = fabric.NewEndpointRef(make([]byte, 32))
		case "revision":
			r.ExpectedRevision = "another-revision"
		case "account":
			selectedFP[0] ^= 1
		case "key-current-id", "no-key-current-id":
			out, e := aliasExecute(t.Context(), p, i, fp, scope, r, &effects, false, nil)
			if e != nil {
				t.Fatal(e)
			}
			out.Stream.Close()
			if change == "key-current-id" {
				r.IdempotencyKey = "different-key"
			} else {
				r.IdempotencyKey = ""
			}
		}
		if _, e := aliasExecute(t.Context(), p, i, selectedFP, scope, r, &effects, false, nil); e == nil {
			t.Fatal("changed selection/key accepted", change)
		}
	}
	for _, mode := range []string{"none", "repeat", "late", "swallow"} {
		policy.mode = mode
		var mutate func(*Receipt)
		if mode == "swallow" {
			mutate = func(r *Receipt) { a := r.Replay.Clone(); a.Proof[0] ^= 1; r.Replay = &a }
		}
		if _, e := aliasExecute(t.Context(), p, i, fp, scope, aliasRequest(scope, "policy-current"), &effects, false, mutate); e == nil {
			t.Fatal("broken policy callback accepted", mode)
		}
		if mode == "late" {
			if policy.escaped == nil || policy.escaped(t.Context()) == nil {
				t.Fatal("escaped callback remained active")
			}
		}
	}
	policy.mode = ""
	if effects.Load() != 1 {
		t.Fatal("bad replay fence resent original")
	}
	// Tombstoning the SAME signed index revokes old associations; no automatic
	// index regeneration or fresh execution may follow that retirement.
	e = i.with(t.Context(), scope, func(_ context.Context, tx *registry.AuthorityTx) error {
		row, e := tx.Get(serviceKey(idemID(p.root.Owner, sha256.Sum256([]byte("same-paid-attempt")))))
		if e != nil {
			return e
		}
		_, e = tx.CAS(row.Key, row.Revision, row.Value, true)
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = aliasExecute(t.Context(), p, i, fp, scope, aliasRequest(scope, "after-retirement"), &effects, false, nil); e == nil || effects.Load() != 1 {
		t.Fatal("retired index re-created original effect")
	}
}

func TestAliasFreshDeadlineDoesNotRenewExpiredOriginalPaidProof(t *testing.T) {
	p, i, _, scope, fp, _ := aliasSetup(t, DefaultInvocationConfig())
	var effects atomic.Int32
	r := aliasRequest(scope, "original-deadline")
	deadline := time.Now().UTC().Add(2 * time.Second)
	r.Deadline = &deadline
	out, e := aliasExecute(t.Context(), p, i, fp, scope, r, &effects, false, nil)
	if e != nil {
		t.Fatal(e)
	}
	aliasDrain(t, out)
	timer := time.NewTimer(time.Until(deadline) + 10*time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	r = aliasRequest(scope, "fresh-after-expiry")
	currentDeadline := time.Now().UTC().Add(time.Minute)
	r.Deadline = &currentDeadline
	replay, e := aliasExecute(t.Context(), p, i, fp, scope, r, &effects, false, nil)
	if e != nil {
		t.Fatal(e)
	}
	aliasDrain(t, replay)
	if effects.Load() != 1 {
		t.Fatal("expired original paid attempt was resent")
	}
	e = i.with(t.Context(), scope, func(_ context.Context, tx *registry.AuthorityTx) error {
		var original Receipt
		_, e := i.decode(tx, "invocation/"+invocationKey(p.root.Owner, "original-deadline"), &original)
		if e != nil {
			return e
		}
		if original.Dispatch.Deadline != deadline.Format(time.RFC3339Nano) {
			t.Fatal("original paid expiry renewed")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}
