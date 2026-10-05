package fabricservices

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

type servicePolicyFixture struct{ principal fabric.Principal }

func (p servicePolicyFixture) AuthorizeTx(_ context.Context, _ *registry.AuthorityTx, c fabric.ExecutionContext, f InvocationFacts, _ string) error {
	if c.PrincipalView() != p.principal || f.Principal != p.principal {
		return denied()
	}
	return nil
}
func invocationFixture(t *testing.T, p *ProfileStore) *Invocations {
	t.Helper()
	i, e := BootstrapInvocations(t.Context(), p, DefaultInvocationConfig(), servicePolicyFixture{p.root.Owner})
	if e != nil {
		t.Fatal(e)
	}
	return i
}

type serviceAuthFixture struct{ principal fabric.Principal }

func (a serviceAuthFixture) Authenticate(_ context.Context, r fabric.AuthenticationRequest) (fabric.ExecutionContext, error) {
	var e fabric.Envelope
	if fabric.DecodeJSON(r.ExactEnvelope, &e) != nil || e.Principal != a.principal {
		return fabric.ExecutionContext{}, denied()
	}
	return fabric.NewAuthenticatedContext(a.principal, r.Audience, r.ExactEnvelope)
}

type serviceDispatcherFixture func(context.Context, fabric.ExecutionContext, fabric.InvokeRequest) (fabric.InvocationStream, error)

func (f serviceDispatcherFixture) Invoke(c context.Context, p fabric.ExecutionContext, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
	return f(c, p, r)
}

// Actual node owns opaque original/final capabilities. The test authenticator
// explicitly pins the fixture owner; this does not claim kernel ingress coverage.
func executeServiceFixture(ctx context.Context, p *ProfileStore, r fabric.InvokeRequest, downstream serviceDispatcherFixture) (fabric.InvocationStream, error) {
	n, e := node.New(node.Config{Audience: p.root.Namespace, Authenticator: serviceAuthFixture{p.root.Owner}, Dispatcher: downstream})
	if e != nil {
		return nil, e
	}
	env := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: r.InvocationID, Operation: fabric.OperationInvoke, Principal: p.root.Owner, Source: p.root.Owner.Ref, Target: &r.Target, ExpectedRevision: r.ExpectedRevision, CreatedAt: time.Unix(1000, 0).UTC(), Payload: r.Input, Context: fabric.EnvelopeContext{Origin: p.root.Owner.Ref, Deadline: r.Deadline, IdempotencyKey: r.IdempotencyKey}}
	raw, _ := json.Marshal(env)
	out, e := n.Execute(ctx, raw, nil)
	return out.Stream, e
}

func TestSameRootServiceAttemptGlobalIdentityConcurrentUnknownAndQuota(t *testing.T) {
	p, scope, _, _ := serviceFixture(t)
	private := serviceProfile()
	gen, e := p.Install(t.Context(), scope, private)
	if e != nil {
		t.Fatal(e)
	}
	config := DefaultInvocationConfig()
	config.MaxInvocations = 1
	ledger, e := BootstrapInvocations(t.Context(), p, config, servicePolicyFixture{p.root.Owner})
	if e != nil {
		t.Fatal(e)
	}
	fp := Fingerprint(scope, private, gen)
	request := fabric.InvokeRequest{InvocationID: "original-unknown", Target: scope.Endpoint, ExpectedRevision: scope.ExpectedEndpointRevision, Input: json.RawMessage(`{"input":"original"}`)}
	var attempts atomic.Int32
	errs := make(chan error, 8)
	for range 8 {
		go func() {
			_, e := executeServiceFixture(t.Context(), p, request, func(ctx context.Context, c fabric.ExecutionContext, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
				_, fresh, e := ledger.Reserve(ctx, c, scope, fp, r)
				if e != nil {
					return nil, e
				}
				if fresh {
					attempts.Add(1)
				}
				return nil, errors.New("fixture simulated uncertain external result AFTER FULL intent")
			})
			errs <- e
		}()
	}
	for range 8 {
		if e := <-errs; e == nil {
			t.Fatal("fixture")
		}
	}
	if attempts.Load() != 1 {
		t.Fatal("uncertain original effect repeated", attempts.Load())
	}
	var admissionError error
	changed := request
	changed.Input = json.RawMessage(`{"input":"changed"}`)
	_, e = executeServiceFixture(t.Context(), p, changed, func(ctx context.Context, c fabric.ExecutionContext, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
		_, _, e := ledger.Reserve(ctx, c, scope, fp, r)
		admissionError = e
		return nil, e
	})
	if admissionError == nil {
		t.Fatal("same identity redirected to changed final input")
	}
	changed = request
	changed.InvocationID = "quota-overflow"
	_, e = executeServiceFixture(t.Context(), p, changed, func(ctx context.Context, c fabric.ExecutionContext, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
		_, fresh, e := ledger.Reserve(ctx, c, scope, fp, r)
		if fresh {
			attempts.Add(1)
		}
		return nil, e
	})
	if e == nil || attempts.Load() != 1 {
		t.Fatal("quota overflow allocated new effect", e)
	}
	if _, e := OpenInvocations(t.Context(), p, DefaultInvocationConfig(), servicePolicyFixture{p.root.Owner}); e == nil {
		t.Fatal("changed quota recreated fence")
	}
	if _, e := BootstrapInvocations(t.Context(), p, config, servicePolicyFixture{p.root.Owner}); e == nil {
		t.Fatal("bootstrap reset retained attempt fence")
	}
	if _, fresh, e := ledger.Reserve(t.Context(), fabric.ExecutionContext{}, scope, fp, request); e == nil || fresh {
		t.Fatal("wire/context-free request obtained admission")
	}
}
func TestActualNodeServiceFramesChunkedCheckpointAndInvalidSourceRollback(t *testing.T) {
	p, scope, _, _ := serviceFixture(t)
	private := serviceProfile()
	gen, e := p.Install(t.Context(), scope, private)
	if e != nil {
		t.Fatal(e)
	}
	ledger := invocationFixture(t, p)
	fp := Fingerprint(scope, private, gen)
	request := fabric.InvokeRequest{InvocationID: "chunked-original", Target: scope.Endpoint, ExpectedRevision: scope.ExpectedEndpointRevision, Input: json.RawMessage(`{"input":"exact"}`)}
	_, e = executeServiceFixture(t.Context(), p, request, func(ctx context.Context, c fabric.ExecutionContext, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
		receipt, fresh, e := ledger.Reserve(ctx, c, scope, fp, r)
		if e != nil || !fresh {
			t.Fatal("original reservation", fresh, e)
		}
		frames := []fabric.InvocationFrame{{InvocationID: r.InvocationID, Sequence: 0, Kind: fabric.FrameStart}, {InvocationID: r.InvocationID, Sequence: 1, Kind: fabric.FrameChunk, ContentType: "application/octet-stream", Data: bytes.Repeat([]byte{0, 255, 127}, (64<<10)/3)}, {InvocationID: r.InvocationID, Sequence: 2, Kind: fabric.FrameComplete}}
		wrong := frames[1]
		wrong.Sequence = 7
		if e = ledger.Append(ctx, c, receipt, wrong); e == nil {
			t.Fatal("out-of-order frame checkpointed")
		}
		for _, frame := range frames {
			if e = ledger.Append(ctx, c, receipt, frame); e != nil {
				t.Fatal(e)
			}
		}
		for ordinal, frame := range frames {
			got, e := ledger.Frame(ctx, c, receipt, uint64(ordinal))
			if e != nil || !reflect.DeepEqual(got, frame) {
				t.Fatal("chunked original frame changed", ordinal, e)
			}
		}
		if e = ledger.Append(ctx, c, receipt, frames[1]); e != nil {
			t.Fatal("exact checkpoint retry not idempotent", e)
		}
		changed := frames[1]
		changed.Data = []byte("changed")
		if e = ledger.Append(ctx, c, receipt, changed); e == nil {
			t.Fatal("old ordinal remapped to changed bytes")
		}
		beyond := frames[1]
		beyond.Sequence = 3
		if e = ledger.Append(ctx, c, receipt, beyond); e == nil {
			t.Fatal("content added after genuine terminal")
		}
		wrong = frames[1]
		wrong.InvocationID = "other-original"
		if e = ledger.Append(ctx, c, receipt, wrong); e == nil {
			t.Fatal("foreign source checkpointed")
		}
		if _, e = ledger.Frame(ctx, c, receipt, 3); e == nil {
			t.Fatal("EOF fabricated source completion")
		}
		return nil, errors.New("fixture complete")
	})
	if e == nil {
		t.Fatal("fixture")
	}
}

type revokedServicePolicy struct {
	principal fabric.Principal
	revoked   atomic.Bool
}

func (p *revokedServicePolicy) AuthorizeTx(_ context.Context, _ *registry.AuthorityTx, c fabric.ExecutionContext, f InvocationFacts, _ string) error {
	if p.revoked.Load() || c.PrincipalView() != p.principal || f.Principal != p.principal {
		return denied()
	}
	return nil
}
func TestServiceCurrentPolicyAndRetiredDescriptorNeverAuthorizeEffect(t *testing.T) {
	p, scope, owner, _ := serviceFixture(t)
	profile := serviceProfile()
	gen, e := p.Install(t.Context(), scope, profile)
	if e != nil {
		t.Fatal(e)
	}
	policy := &revokedServicePolicy{principal: p.root.Owner}
	ledger, e := BootstrapInvocations(t.Context(), p, DefaultInvocationConfig(), policy)
	if e != nil {
		t.Fatal(e)
	}
	fp := Fingerprint(scope, profile, gen)
	request := fabric.InvokeRequest{InvocationID: "policy-original", Target: scope.Endpoint, ExpectedRevision: scope.ExpectedEndpointRevision, Input: json.RawMessage(`{}`)}
	attempts := 0
	run := func(request fabric.InvokeRequest) (bool, error) {
		accepted := false
		_, e := executeServiceFixture(t.Context(), p, request, func(ctx context.Context, c fabric.ExecutionContext, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
			_, fresh, e := ledger.Reserve(ctx, c, scope, fp, r)
			accepted = e == nil
			if fresh {
				attempts++
			}
			if e != nil {
				return nil, e
			}
			return nil, errors.New("fixture records admission only")
		})
		return accepted, e
	}
	if accepted, _ := run(request); !accepted {
		t.Fatal("first actual admission refused")
	}
	policy.revoked.Store(true)
	if accepted, e := run(request); accepted || e == nil {
		t.Fatal("retained receipt reused revoked current caller policy")
	}
	fresh := request
	fresh.InvocationID = "revoked-fresh"
	if accepted, e := run(fresh); accepted || e == nil {
		t.Fatal("revoked policy admitted fresh effect")
	}
	if attempts != 1 {
		t.Fatal("revocation effect", attempts)
	}
	policy.revoked.Store(false)
	if _, e = p.store.Retire(t.Context(), owner, scope.Endpoint, scope.ExpectedEndpointRevision); e != nil {
		t.Fatal(e)
	}
	fresh.InvocationID = "retired-fresh"
	if accepted, e := run(fresh); accepted || e == nil {
		t.Fatal("retired descriptor admitted new effect")
	}
	if attempts != 1 {
		t.Fatal("retired source created new effect")
	}
}
