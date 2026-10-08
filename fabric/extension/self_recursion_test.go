package extension

import (
	"context"
	"encoding/json"
	"reflect"
	"sync"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
)

// selfRecursionEngine composes a real engine over the executing extension
// ("acme.security", with an explicit AllowSelfRecursion registration) and a
// foreign extension ("other.audit"), both matching the same dispatch stage.
// The resolver mirrors the production node match(): ExecutingInterceptors is
// derived only from the node-minted context value, never from the caller's
// provenance.
func selfRecursionEngine(t *testing.T, handler Handler) *Engine {
	t.Helper()
	self := manifestWith("a", "b")
	self.Interceptors[1].AllowSelfRecursion = true
	foreign := manifestWith("c")
	foreign.ID = "other.audit"
	foreign.Interceptors[0].ID = "other.audit.c"
	plan, err := Compile([]ExtensionManifest{self, foreign}, 100)
	if err != nil {
		t.Fatal(err)
	}
	registry := NewHandlerRegistry()
	if err := registry.Set("private.binding", handler); err != nil {
		t.Fatal(err)
	}
	executor, _ := NewExecutor(16)
	resolver := func(ctx context.Context, _ fabric.ExecutionContext, _ fabric.Envelope, _ string, _ Placement) (MatchContext, error) {
		return MatchContext{TargetKind: "service.mcp", ExecutingInterceptors: ExecutingExtensionsFrom(ctx)}, nil
	}
	validator := func(context.Context, fabric.ExecutionContext, fabric.Envelope) error { return nil }
	engine, err := NewEngine(plan, registry, executor, resolver, validator, nil, 8)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

// selfRecursionCalls drives one full invocation through the two-extension
// engine and returns the exact ordered interceptor calls plus the downstream
// effect count.
func selfRecursionCalls(t *testing.T, ctx context.Context, caller fabric.ExecutionContext, raw []byte, handler Handler) (int, []string, error) {
	t.Helper()
	var mu sync.Mutex
	var calls []string
	recording := handlerFunc(func(ctx context.Context, r InterceptRequest) (Decision, error) {
		decision, err := handler.Intercept(ctx, r)
		mu.Lock()
		calls = append(calls, r.InterceptorID+":"+string(r.Phase))
		mu.Unlock()
		return decision, err
	})
	engine := selfRecursionEngine(t, recording)
	targetCalls := 0
	_, err := engine.ExecuteStage(ctx, caller, raw, "test.audience", "invoke.dispatch", PlacementSource, func(context.Context, fabric.ExecutionContext, fabric.Envelope) (Outcome, error) {
		targetCalls++
		return Outcome{Response: json.RawMessage(`{"ok":true}`)}, nil
	})
	mu.Lock()
	snapshot := append([]string(nil), calls...)
	mu.Unlock()
	return targetCalls, snapshot, err
}
func TestNodeMintedExecutingExtensionSuppressesSelfOnly(t *testing.T) {
	handler := handlerFunc(func(context.Context, InterceptRequest) (Decision, error) {
		return Decision{Action: Continue}, nil
	})
	caller, raw, _ := engineEnvelope(t)
	// No node-minted evidence: every matching interceptor executes.
	target, calls, err := selfRecursionCalls(t, context.Background(), caller, raw, handler)
	if err != nil || target != 1 || !reflect.DeepEqual(calls, []string{
		"acme.security.a:request", "acme.security.b:request", "other.audit.c:request",
		"other.audit.c:response", "acme.security.b:response", "acme.security.a:response",
	}) {
		t.Fatal(target, err, calls)
	}
	// Node-minted self: the executing extension cannot re-trigger its
	// interceptors, the explicit AllowSelfRecursion registration still runs,
	// and the foreign extension is not suppressed.
	minted := WithExecutingExtensions(context.Background(), []string{"acme.security"})
	target, calls, err = selfRecursionCalls(t, minted, caller, raw, handler)
	if err != nil || target != 1 || !reflect.DeepEqual(calls, []string{
		"acme.security.b:request", "other.audit.c:request",
		"other.audit.c:response", "acme.security.b:response",
	}) {
		t.Fatal(target, err, calls)
	}
	// Node-minted foreign: symmetric — only the foreign extension is
	// suppressed.
	minted = WithExecutingExtensions(context.Background(), []string{"other.audit"})
	target, calls, err = selfRecursionCalls(t, minted, caller, raw, handler)
	if err != nil || target != 1 || !reflect.DeepEqual(calls, []string{
		"acme.security.a:request", "acme.security.b:request",
		"acme.security.b:response", "acme.security.a:response",
	}) {
		t.Fatal(target, err, calls)
	}
}
func TestNodeMintedExecutingExtensionPersistsAcrossRedirectPass(t *testing.T) {
	// The node-minted value is set once per invocation, not per pass: the
	// executing extension stays suppressed on the redirect re-selection, while
	// the foreign extension's redirect still reselects the chain and reaches
	// the target.
	caller, raw, original := engineEnvelope(t)
	other, err := fabric.NewEndpointRef(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	self := manifestWith("a")
	foreign := manifestWith("b")
	foreign.ID = "other.audit"
	foreign.Interceptors[0].ID = "other.audit.b"
	plan, err := Compile([]ExtensionManifest{self, foreign}, 100)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var calls []string
	handler := handlerFunc(func(_ context.Context, r InterceptRequest) (Decision, error) {
		mu.Lock()
		calls = append(calls, r.InterceptorID+":"+string(r.Phase))
		mu.Unlock()
		if r.Phase == PhaseRequest && r.InterceptorID == "other.audit.b" && *r.Envelope.Target == original {
			return Decision{Action: Redirect, Redirect: &RedirectTarget{Ref: other}}, nil
		}
		return Decision{Action: Continue}, nil
	})
	registry := NewHandlerRegistry()
	if err := registry.Set("private.binding", handler); err != nil {
		t.Fatal(err)
	}
	executor, _ := NewExecutor(16)
	resolver := func(ctx context.Context, _ fabric.ExecutionContext, _ fabric.Envelope, _ string, _ Placement) (MatchContext, error) {
		return MatchContext{TargetKind: "service.mcp", ExecutingInterceptors: ExecutingExtensionsFrom(ctx)}, nil
	}
	engine, err := NewEngine(plan, registry, executor, resolver, func(context.Context, fabric.ExecutionContext, fabric.Envelope) error { return nil }, nil, 8)
	if err != nil {
		t.Fatal(err)
	}
	targetCalls := 0
	seenTarget := fabric.EndpointRef{}
	minted := WithExecutingExtensions(context.Background(), []string{"acme.security"})
	out, err := engine.ExecuteStage(minted, caller, raw, "test.audience", "invoke.dispatch", PlacementSource, func(_ context.Context, _ fabric.ExecutionContext, e fabric.Envelope) (Outcome, error) {
		targetCalls++
		seenTarget = *e.Target
		return Outcome{Response: json.RawMessage(`{}`)}, nil
	})
	if err != nil || out.Response == nil || targetCalls != 1 || seenTarget != other {
		t.Fatal(err, targetCalls, seenTarget)
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(calls, []string{
		"other.audit.b:request", "other.audit.b:request",
		"other.audit.b:response", "other.audit.b:response",
	}) {
		t.Fatal(calls)
	}
}
