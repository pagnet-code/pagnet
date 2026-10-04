package node

import (
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/extension"
)

type inlineHandler func(context.Context, extension.InterceptRequest) (extension.Decision, error)

func (f inlineHandler) Intercept(ctx context.Context, r extension.InterceptRequest) (extension.Decision, error) {
	return f(ctx, r)
}

type deferRecorder struct{ saved bool }

func (r *deferRecorder) Save(context.Context, fabric.ExecutionContext, []byte, extension.PipelineState, extension.Deferral, extension.CompiledRegistration) (string, error) {
	r.saved = true
	return "saved-continuation", nil
}
func installEngine(t *testing.T, s *Service, handler inlineHandler, recorder extension.ContinuationRecorder) {
	t.Helper()
	manifest := extension.ExtensionManifest{ManifestVersion: "1.0", ID: "test.extension", Version: "1.0.0", MinProtocol: "1.0", MaxProtocol: "1.0", Interceptors: []extension.Registration{{ID: "test.extension.interceptor", Binding: "private", Placement: extension.PlacementSource, Match: extension.Match{Operation: fabric.OperationInvoke, Stage: "invoke.dispatch"}, Phases: []extension.Phase{extension.PhaseRequest}, TimeoutMillis: 1000}}}
	plan, err := extension.Compile([]extension.ExtensionManifest{manifest}, 10)
	if err != nil {
		t.Fatal(err)
	}
	handlers := extension.NewHandlerRegistry()
	handlers.Set("private", handler)
	executor, _ := extension.NewExecutor(2)
	engine, err := extension.NewEngine(plan, handlers, executor, func(_ context.Context, _ fabric.ExecutionContext, _ fabric.Envelope, _ string, _ extension.Placement) (extension.MatchContext, error) {
		return extension.MatchContext{TargetKind: "actor.agent"}, nil
	}, func(context.Context, fabric.ExecutionContext, fabric.Envelope) error { return nil }, recorder, 8)
	if err != nil {
		t.Fatal(err)
	}
	s.config.Interceptors = engine
}
func TestNodeComposesMutationWithVerifiedCaller(t *testing.T) {
	service, envelope, _, store, dispatcher := setup(t)
	envelope.Operation = fabric.OperationInvoke
	ref := store.endpoint.Ref
	envelope.Target = &ref
	envelope.Payload = json.RawMessage(`{"text":"original"}`)
	installEngine(t, service, func(ctx context.Context, r extension.InterceptRequest) (extension.Decision, error) {
		caller, ok := CallerFromContext(ctx)
		if !ok || caller.PrincipalView() != envelope.Principal {
			t.Error("missing verified caller")
		}
		return extension.Decision{Action: extension.Modify, Patch: json.RawMessage(`[{"op":"replace","path":"/payload/text","value":"modified"}]`)}, nil
	}, nil)
	result, err := execute(t, service, envelope)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Stream.Close()
	if len(dispatcher.requests) != 1 || string(dispatcher.requests[0].Input) != `{"text":"modified"}` {
		t.Fatal(dispatcher.requests)
	}
}
func TestNodeShortCircuitAndDeferredResultDoNotDispatch(t *testing.T) {
	for _, deferCall := range []bool{false, true} {
		service, envelope, _, store, dispatcher := setup(t)
		envelope.Operation = fabric.OperationInvoke
		ref := store.endpoint.Ref
		envelope.Target = &ref
		envelope.Payload = json.RawMessage(`{}`)
		recorder := &deferRecorder{}
		installEngine(t, service, func(context.Context, extension.InterceptRequest) (extension.Decision, error) {
			if deferCall {
				return extension.Decision{Action: extension.Defer, Deferral: &extension.Deferral{ExpiresAt: time.Now().Add(time.Hour), ResumePrincipals: []string{"human"}, Durable: true}}, nil
			}
			return extension.Decision{Action: extension.Respond, Response: json.RawMessage(`{"cached":true}`)}, nil
		}, recorder)
		deadline := time.Now().Add(time.Minute)
		envelope.Context.Deadline = &deadline
		result, err := execute(t, service, envelope)
		if err != nil || len(dispatcher.requests) != 0 {
			t.Fatal(err, dispatcher.requests)
		}
		if deferCall {
			if result.Stream != nil || result.DeferredID != "saved-continuation" || !recorder.saved {
				t.Fatal(result)
			}
			continue
		}
		var content []byte
		for {
			frame, err := result.Stream.Next(context.Background())
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			content = append(content, frame.Data...)
		}
		if string(content) != `{"cached":true}` {
			t.Fatal(string(content))
		}
		result.Stream.Close()
	}
}
