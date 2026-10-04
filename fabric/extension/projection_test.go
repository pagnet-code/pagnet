package extension

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
)

func TestReadProjectionKeepsOriginalIdentityAndCannotProduceInvocations(t *testing.T) {
	for _, action := range []Action{Continue, Redirect, Defer} {
		t.Run(string(action), func(t *testing.T) {
			_, initial, ref := engineEnvelope(t)
			var env fabric.Envelope
			if err := fabric.DecodeJSON(initial, &env); err != nil {
				t.Fatal(err)
			}
			env.Operation, env.Target, env.Payload = fabric.OperationDiscover, nil, json.RawMessage(`{"query":"invoice","scope":{},"limit":10}`)
			raw, _ := json.Marshal(env)
			caller, _ := fabric.NewAuthenticatedContext(env.Principal, "test.audience", raw)
			manifest := manifestWith("a")
			manifest.Interceptors[0].Match.Operation, manifest.Interceptors[0].Match.Stage = fabric.OperationDiscover, "discover.candidates"
			manifest.Interceptors[0].Phases = []Phase{PhaseRequest}
			calls := 0
			engine := makeEngine(t, manifest, handlerFunc(func(_ context.Context, r InterceptRequest) (Decision, error) {
				if r.Envelope.Principal != env.Principal || r.Envelope.Source != env.Source || r.Envelope.ID != env.ID || string(r.Envelope.Payload) != `{"candidates":[]}` {
					t.Error("original binding/projection changed")
				}
				if action == Redirect {
					return Decision{Action: Redirect, Redirect: &RedirectTarget{Ref: ref}}, nil
				}
				if action == Defer {
					return Decision{Action: Defer, Deferral: &Deferral{}}, nil
				}
				return Decision{Action: Continue}, nil
			}), func(ctx context.Context, _ fabric.ExecutionContext, current fabric.Envelope) error {
				if ValidationStage(ctx) != "discover.candidates" || current.Operation != fabric.OperationDiscover {
					t.Error("validation stage lost or caller-controlled")
				}
				return nil
			}, nil)
			_, err := engine.ExecuteReadProjection(context.Background(), caller, raw, "test.audience", "discover.candidates", PlacementSource, json.RawMessage(`{"candidates":[]}`), func(context.Context, fabric.ExecutionContext, fabric.Envelope) (Outcome, error) {
				calls++
				return Outcome{Response: json.RawMessage(`[]`)}, nil
			})
			if action == Continue && (err != nil || calls != 1) {
				t.Fatal(err, calls)
			}
			if action != Continue && (err == nil || calls != 0) {
				t.Fatal("read projection created effects", err, calls)
			}
			if _, err := engine.ExecuteReadProjection(context.Background(), caller, raw, "test.audience", "invoke.dispatch", PlacementSource, json.RawMessage(`{}`), func(context.Context, fabric.ExecutionContext, fabric.Envelope) (Outcome, error) {
				t.Error("operation stage changed")
				return Outcome{}, nil
			}); err == nil {
				t.Error("foreign operation projection accepted")
			}
		})
	}
}
