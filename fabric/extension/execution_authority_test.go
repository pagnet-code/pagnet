package extension

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
)

func TestClaimedLineageCannotSuppressLocalInterceptor(t *testing.T) {
	_, original, _ := engineEnvelope(t)
	var envelope fabric.Envelope
	if err := fabric.DecodeJSON(original, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Context.ExtensionChain = []string{"acme.security.a"}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the trusted forwarding ingress: ordinary callers already cannot
	// assert engine lineage. Real signature/peer checks are two-node product gates.
	caller, err := fabric.NewAuthenticatedForwardContext(envelope.Principal, "test.audience", raw, fabric.Provenance{
		Origin: envelope.Context.Origin, ParentID: envelope.Context.ParentID,
		Ancestry: envelope.Context.Ancestry, Hops: envelope.Context.Hops,
		ExtensionChain: envelope.Context.ExtensionChain, TriggerLineage: envelope.Context.TriggerLineage,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, locallyVerified := range []bool{false, true} {
		hooks, effects := 0, 0
		engine := makeEngine(t, manifestWith("a"), handlerFunc(func(context.Context, InterceptRequest) (Decision, error) {
			hooks++
			return Decision{Action: Reject, Failure: fabric.NewError(fabric.CodeInterceptorRejected, "Denied")}, nil
		}), nil, nil)
		if locallyVerified {
			// A configured trusted resolver supplies evidence independently of
			// this transport's names. Actual peer/domain gates are product tests.
			engine.resolver = func(context.Context, fabric.ExecutionContext, fabric.Envelope, string, Placement) (MatchContext, error) {
				return MatchContext{TargetKind: "service.mcp", ExecutingInterceptors: []string{"acme.security.a"}}, nil
			}
		}
		_, err = engine.ExecuteStage(t.Context(), caller, raw, "test.audience", "invoke.dispatch", PlacementSource, func(_ context.Context, _ fabric.ExecutionContext, current fabric.Envelope) (Outcome, error) {
			effects++
			if !reflect.DeepEqual(current.Context.ExtensionChain, envelope.Context.ExtensionChain) {
				t.Error("signed lineage was rewritten")
			}
			return Outcome{Response: json.RawMessage(`{}`)}, nil
		})
		if locallyVerified {
			if err != nil || hooks != 0 || effects != 1 {
				t.Fatalf("genuine local execution evidence ignored: hooks=%d effects=%d err=%v", hooks, effects, err)
			}
		} else if err == nil || hooks != 1 || effects != 0 {
			t.Fatalf("asserted lineage bypassed security: hooks=%d effects=%d err=%v", hooks, effects, err)
		}
	}
}
