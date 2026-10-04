package extension

import (
	"context"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/telemetry"
	"go.opentelemetry.io/otel/codes"
	sdk "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestFailOpenTimeoutRemainsVisibleAsFailedInterceptorAttempt(t *testing.T) {
	caller, original, _ := engineEnvelope(t)
	manifest := manifestWith("outage")
	manifest.Interceptors[0].FailureMode = FailOpen
	manifest.Interceptors[0].TimeoutMillis = 10
	recorder := tracetest.NewSpanRecorder()
	provider := sdk.NewTracerProvider(sdk.WithSpanProcessor(recorder))
	defer provider.Shutdown(context.Background())
	tracing, _ := telemetry.New(telemetry.Config{Tracer: provider.Tracer("pagnet/fabric")})
	engine := makeEngine(t, manifest, handlerFunc(func(ctx context.Context, request InterceptRequest) (Decision, error) {
		if request.Phase == PhaseRequest {
			<-ctx.Done()
			return Decision{}, ctx.Err()
		}
		return Decision{Action: Continue}, nil
	}), nil, nil)
	engine.tracing = tracing
	calls := 0
	_, err := engine.ExecuteStage(context.Background(), caller, original, "test.audience", "invoke.dispatch", PlacementSource, func(context.Context, fabric.ExecutionContext, fabric.Envelope) (Outcome, error) {
		calls++
		return Outcome{Response: []byte(`{"ok":true}`)}, nil
	})
	if err != nil || calls != 1 {
		t.Fatal(err, calls)
	}
	spans := recorder.Ended()
	if len(spans) != 2 {
		t.Fatal("missing request/response attempts", len(spans))
	}
	if spans[0].Status().Code != codes.Error || spans[0].Status().Description != "operation timed out" || spans[1].Status().Code != codes.Ok {
		t.Fatal("outage hidden by allowed continuation", spans)
	}
	want := []string{"request", "response"}
	for i, span := range spans {
		found := false
		for _, attribute := range span.Attributes() {
			if string(attribute.Key) == "pagnet.interceptor.phase" && attribute.Value.AsString() == want[i] {
				found = true
			}
		}
		if !found {
			t.Fatal("phase omitted", span.Attributes())
		}
	}
}
