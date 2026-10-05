package a2a

import (
	"encoding/json"
	sdk "github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/pagnet-code/pagnet/fabric"
	"testing"
)

func TestRootIdempotencyRequiresActualOptInStoreAndDefaultDeniesBeforeEffects(t *testing.T) {
	f := setup(t, sdk.TaskStateCompleted, false)
	r := fabric.InvokeRequest{InvocationID: "attempt", Target: f.endpoint.Ref, ExpectedRevision: f.endpoint.Revision, Input: json.RawMessage(`{"operation":"send","mode":"unary","parts":[{"text":"original"}]}`), IdempotencyKey: "same-original"}
	if _, e := f.adapter.Invoke(t.Context(), f.caller, f.endpoint, r); e == nil || f.calls.Load() != 0 {
		t.Fatal("standalone implicitly claimed root idempotency")
	}
	config := f.adapter.config
	config.Card = f.adapter.card
	config.RootIdempotency = true
	if _, e := New(config); e == nil || f.calls.Load() != 0 {
		t.Fatal("unsigned standalone association store opted into signed root aliases")
	}
	r.IdempotencyKey = ""
	d := f.endpoint
	d.Bindings = append([]fabric.BindingSummary(nil), d.Bindings...)
	d.Bindings[0].Idempotency = true
	if _, e := f.adapter.Invoke(t.Context(), f.caller, d, r); e == nil || f.calls.Load() != 0 {
		t.Fatal("caller descriptor claim enabled idempotency")
	}
}
