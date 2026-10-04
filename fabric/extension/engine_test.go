package extension

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

func engineEnvelope(t *testing.T) (fabric.ExecutionContext, []byte, fabric.EndpointRef) {
	t.Helper()
	var pub [32]byte
	rand.Read(pub[:])
	ref, err := fabric.NewEndpointRef(pub[:])
	if err != nil {
		t.Fatal(err)
	}
	envelope := patchEnvelope()
	envelope.Operation = fabric.OperationInvoke
	envelope.Target = &ref
	raw, _ := json.Marshal(envelope)
	caller, err := fabric.NewAuthenticatedContext(envelope.Principal, "test.audience", raw)
	if err != nil {
		t.Fatal(err)
	}
	return caller, raw, ref
}
func makeEngine(t *testing.T, m ExtensionManifest, handler Handler, validator FinalValidator, store ContinuationRecorder) *Engine {
	t.Helper()
	plan, err := Compile([]ExtensionManifest{m}, 100)
	if err != nil {
		t.Fatal(err)
	}
	registry := NewHandlerRegistry()
	if err := registry.Set("private.binding", handler); err != nil {
		t.Fatal(err)
	}
	executor, _ := NewExecutor(16)
	if validator == nil {
		validator = func(context.Context, fabric.ExecutionContext, fabric.Envelope) error { return nil }
	}
	engine, err := NewEngine(plan, registry, executor, func(_ context.Context, _ fabric.ExecutionContext, e fabric.Envelope, stage string, placement Placement) (MatchContext, error) {
		return MatchContext{TargetKind: "service.mcp"}, nil
	}, validator, store, 8)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}
func TestEngineNestedModifyRespondRejectAndUnwind(t *testing.T) {
	for _, action := range []Action{Continue, Respond, Reject} {
		t.Run(string(action), func(t *testing.T) {
			caller, raw, _ := engineEnvelope(t)
			var mu sync.Mutex
			var calls []string
			targetCalls := 0
			handler := handlerFunc(func(_ context.Context, r InterceptRequest) (Decision, error) {
				mu.Lock()
				calls = append(calls, r.InterceptorID+":"+string(r.Phase))
				mu.Unlock()
				if r.Phase != PhaseRequest {
					return Decision{Action: Continue}, nil
				}
				if r.InterceptorID == "acme.security.a" {
					return Decision{Action: Modify, Patch: json.RawMessage(`[{"op":"add","path":"/payload/classified","value":true}]`)}, nil
				}
				switch action {
				case Respond:
					return Decision{Action: Respond, Response: json.RawMessage(`{"cached":true}`)}, nil
				case Reject:
					return Decision{Action: Reject, Failure: fabric.NewError(fabric.CodeInterceptorRejected, "Policy denied")}, nil
				default:
					return Decision{Action: Continue}, nil
				}
			})
			engine := makeEngine(t, manifestWith("a", "b"), handler, nil, nil)
			outcome, err := engine.ExecuteStage(context.Background(), caller, raw, "test.audience", "invoke.dispatch", PlacementSource, func(_ context.Context, _ fabric.ExecutionContext, e fabric.Envelope) (Outcome, error) {
				targetCalls++
				var body map[string]any
				fabric.DecodeJSON(e.Payload, &body)
				if body["classified"] != true {
					t.Error("mutation not delivered")
				}
				return Outcome{Response: json.RawMessage(`{"ok":true}`)}, nil
			})
			expected := []string{"acme.security.a:request", "acme.security.b:request"}
			switch action {
			case Continue:
				expected = append(expected, "acme.security.b:response", "acme.security.a:response")
				if targetCalls != 1 || err != nil {
					t.Fatal(targetCalls, err)
				}
			case Respond:
				expected = append(expected, "acme.security.a:response")
				if targetCalls != 0 || err != nil || string(outcome.Response) != `{"cached":true}` {
					t.Fatal(outcome, err)
				}
			case Reject:
				expected = append(expected, "acme.security.a:error")
				if targetCalls != 0 || err == nil {
					t.Fatal(targetCalls, err)
				}
			}
			if !reflect.DeepEqual(calls, expected) {
				t.Fatal(calls, expected)
			}
		})
	}
}
func TestRedirectRerunsDispatchAndFinalGate(t *testing.T) {
	caller, raw, _ := engineEnvelope(t)
	other, err := fabric.NewEndpointRef(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	m := manifestWith("auth", "redirect")
	m.Interceptors[1].Match.Stage = "invoke.endpoint"
	var calls []string
	targetCalls := 0
	handler := handlerFunc(func(_ context.Context, r InterceptRequest) (Decision, error) {
		calls = append(calls, r.InterceptorID+":"+string(r.Phase))
		if r.InterceptorID == "acme.security.redirect" && r.Phase == PhaseRequest {
			return Decision{Action: Redirect, Redirect: &RedirectTarget{Ref: other}}, nil
		}
		return Decision{Action: Continue}, nil
	})
	engine := makeEngine(t, m, handler, func(_ context.Context, _ fabric.ExecutionContext, e fabric.Envelope) error {
		if e.Target == nil || *e.Target != other {
			t.Fatal("final gate saw original target")
		}
		return nil
	}, nil)
	_, err = engine.ExecuteStage(context.Background(), caller, raw, "test.audience", "invoke.endpoint", PlacementSource, func(_ context.Context, _ fabric.ExecutionContext, e fabric.Envelope) (Outcome, error) {
		targetCalls++
		if *e.Target != other {
			t.Fatal("redirect not dispatched")
		}
		return Outcome{Response: json.RawMessage(`{}`)}, nil
	})
	if err != nil || targetCalls != 1 {
		t.Fatal(err, targetCalls)
	}
	if !reflect.DeepEqual(calls, []string{"acme.security.redirect:request", "acme.security.auth:request", "acme.security.auth:response", "acme.security.redirect:response"}) {
		t.Fatal(calls)
	}
}
func TestRedirectCycleNeverReachesTarget(t *testing.T) {
	caller, raw, original := engineEnvelope(t)
	other, _ := fabric.NewEndpointRef(make([]byte, 32))
	engine := makeEngine(t, manifestWith("a"), handlerFunc(func(_ context.Context, r InterceptRequest) (Decision, error) {
		if r.Phase != PhaseRequest {
			return Decision{Action: Continue}, nil
		}
		ref := other
		if *r.Envelope.Target == other {
			ref = original
		}
		return Decision{Action: Redirect, Redirect: &RedirectTarget{Ref: ref}}, nil
	}), nil, nil)
	targetCalls := 0
	_, err := engine.ExecuteStage(context.Background(), caller, raw, "test.audience", "invoke.dispatch", PlacementSource, func(context.Context, fabric.ExecutionContext, fabric.Envelope) (Outcome, error) {
		targetCalls++
		return Outcome{}, nil
	})
	var failure *fabric.Error
	if !errors.As(err, &failure) || failure.Code != fabric.CodeRedirectLoop || targetCalls != 0 {
		t.Fatal(err, targetCalls)
	}
}

type recorderFunc func(context.Context, fabric.ExecutionContext, []byte, PipelineState, Deferral, CompiledRegistration) (string, error)

func (f recorderFunc) Save(ctx context.Context, c fabric.ExecutionContext, b []byte, s PipelineState, d Deferral, r CompiledRegistration) (string, error) {
	return f(ctx, c, b, s, d, r)
}
func TestDeferredSnapshotResumesAfterInterceptorAndFinalGate(t *testing.T) {
	caller, raw, _ := engineEnvelope(t)
	var saved PipelineState
	var calls []string
	targetCalls := 0
	gateCalls := 0
	engine := makeEngine(t, manifestWith("a", "b"), handlerFunc(func(_ context.Context, r InterceptRequest) (Decision, error) {
		calls = append(calls, r.InterceptorID+":"+string(r.Phase))
		if r.InterceptorID == "acme.security.a" && r.Phase == PhaseRequest {
			return Decision{Action: Defer, Deferral: &Deferral{ExpiresAt: time.Now().Add(time.Hour), ResumePrincipals: []string{"human"}, Durable: true}}, nil
		}
		return Decision{Action: Continue}, nil
	}), func(context.Context, fabric.ExecutionContext, fabric.Envelope) error { gateCalls++; return nil }, recorderFunc(func(_ context.Context, _ fabric.ExecutionContext, original []byte, s PipelineState, _ Deferral, _ CompiledRegistration) (string, error) {
		saved = s
		if string(original) != string(raw) || s.DeferralID == "" {
			t.Fatal("original or stable deferral lost")
		}
		return "continuation", nil
	}))
	downstream := func(context.Context, fabric.ExecutionContext, fabric.Envelope) (Outcome, error) {
		targetCalls++
		return Outcome{Response: json.RawMessage(`{}`)}, nil
	}
	out, err := engine.ExecuteStage(context.Background(), caller, raw, "test.audience", "invoke.dispatch", PlacementSource, downstream)
	if err != nil || out.DeferredID != "continuation" || targetCalls != 0 || gateCalls != 0 {
		t.Fatal(out, err)
	}
	permit, permitErr := NewVerifiedResumePermit(caller, raw, saved)
	if permitErr != nil {
		t.Fatal(permitErr)
	}
	out, err = engine.ResumeStage(context.Background(), permit, caller, raw, saved, downstream)
	if err != nil || targetCalls != 1 || gateCalls != 1 {
		t.Fatal(out, err, targetCalls, gateCalls)
	}
	if !reflect.DeepEqual(calls, []string{"acme.security.a:request", "acme.security.b:request", "acme.security.b:response", "acme.security.a:response"}) {
		t.Fatal(calls)
	}
	if _, err = engine.ResumeStage(context.Background(), permit, caller, raw, saved, downstream); err == nil {
		t.Fatal("claim executed twice")
	}
	saved.PlanRevision = "changed"
	if _, err = engine.ResumeStage(context.Background(), permit, caller, raw, saved, downstream); err == nil {
		t.Fatal("changed plan resumed")
	}
}

func TestExpiredEnvelopeNeverEntersInterceptorOrTarget(t *testing.T) {
	caller, raw, _ := engineEnvelope(t)
	var envelope fabric.Envelope
	fabric.DecodeJSON(raw, &envelope)
	past := time.Now().Add(-time.Second)
	envelope.Context.Deadline = &past
	raw, _ = json.Marshal(envelope)
	caller, _ = fabric.NewAuthenticatedContext(envelope.Principal, "test.audience", raw)
	calls := 0
	engine := makeEngine(t, manifestWith("a"), handlerFunc(func(context.Context, InterceptRequest) (Decision, error) {
		calls++
		return Decision{Action: Continue}, nil
	}), nil, nil)
	_, err := engine.ExecuteStage(context.Background(), caller, raw, "test.audience", "invoke.dispatch", PlacementSource, func(context.Context, fabric.ExecutionContext, fabric.Envelope) (Outcome, error) {
		calls++
		return Outcome{}, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) || calls != 0 {
		t.Fatal(err, calls)
	}
}
func TestResumePermitRejectsChangedIdentityAndState(t *testing.T) {
	caller, raw, _ := engineEnvelope(t)
	var envelope fabric.Envelope
	fabric.DecodeJSON(raw, &envelope)
	state := PipelineState{Format: "pagnet.pipeline.v1", Envelope: envelope, PlanRevision: "plan", DeferralID: "deferral"}
	changed := state
	changed.Envelope.Principal.Ref = "forged"
	if _, err := NewVerifiedResumePermit(caller, raw, changed); err == nil {
		t.Fatal("immutable identity replaced")
	}
	permit, err := NewVerifiedResumePermit(caller, raw, state)
	if err != nil {
		t.Fatal(err)
	}
	changed = state
	changed.Cursor = 1
	if err := permit.consume(caller, raw, changed); err == nil {
		t.Fatal("changed cursor admitted")
	}
	if _, err := json.Marshal(permit); err == nil {
		t.Fatal("opaque permit serialized")
	}
	if err := permit.consume(caller, raw, state); err != nil {
		t.Fatal(err)
	}
	if err := permit.consume(caller, raw, state); err == nil {
		t.Fatal("permit reused")
	}
}
