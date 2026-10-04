package extension

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

func TestFailOpenNeverIgnoresInvalidControlOrMutation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler handlerFunc
		allowed bool
	}{
		{"outage", func(context.Context, InterceptRequest) (Decision, error) {
			return Decision{}, fabric.NewError(fabric.CodeTargetUnavailable, "private provider details")
		}, true},
		{"timeout", func(ctx context.Context, _ InterceptRequest) (Decision, error) {
			<-ctx.Done()
			return Decision{}, ctx.Err()
		}, true},
		{"contradictory", func(context.Context, InterceptRequest) (Decision, error) {
			return Decision{Action: Continue, Patch: json.RawMessage(`[]`)}, nil
		}, false},
		{"unknown-action", func(context.Context, InterceptRequest) (Decision, error) { return Decision{Action: "FORGED"}, nil }, false},
		{"target-patch", func(context.Context, InterceptRequest) (Decision, error) {
			return Decision{Action: Modify, Patch: json.RawMessage(`[{"op":"remove","path":"/target"}]`)}, nil
		}, false},
		{"principal-patch", func(context.Context, InterceptRequest) (Decision, error) {
			return Decision{Action: Modify, Patch: json.RawMessage(`[{"op":"remove","path":"/principal"}]`)}, nil
		}, false},
		{"panic", func(context.Context, InterceptRequest) (Decision, error) { panic("private") }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caller, raw, _ := engineEnvelope(t)
			manifest := manifestWith("a")
			manifest.Interceptors[0].FailureMode = FailOpen
			manifest.Interceptors[0].Phases = []Phase{PhaseRequest}
			manifest.Interceptors[0].TimeoutMillis = 5
			engine := makeEngine(t, manifest, tc.handler, nil, nil)
			calls := 0
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := engine.ExecuteStage(ctx, caller, raw, "test.audience", "invoke.dispatch", PlacementSource, func(context.Context, fabric.ExecutionContext, fabric.Envelope) (Outcome, error) {
				calls++
				return Outcome{Response: json.RawMessage(`{}`)}, nil
			})
			if tc.allowed && (err != nil || calls != 1) {
				t.Fatalf("outage policy not applied: %v, calls=%d", err, calls)
			}
			if !tc.allowed && (err == nil || calls != 0) {
				t.Fatalf("invalid control bypassed dispatch: %v, calls=%d", err, calls)
			}
		})
	}
}
