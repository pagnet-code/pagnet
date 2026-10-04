package node

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/telemetry"
	sdk "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestNodeSpanOwnsActualPullStreamLifetimeAndNoContent(t *testing.T) {
	s, envelope, _, store, _ := setup(t)
	recorder := tracetest.NewSpanRecorder()
	provider := sdk.NewTracerProvider(sdk.WithSpanProcessor(recorder))
	defer provider.Shutdown(context.Background())
	s.config.Tracing, _ = telemetry.New(telemetry.Config{Tracer: provider.Tracer("pagnet/fabric")})
	envelope.Operation, envelope.Target = fabric.OperationInvoke, &store.endpoint.Ref
	envelope.Payload = json.RawMessage(`{"message":"private instruction"}`)
	result, err := execute(t, s, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if len(recorder.Ended()) != 0 {
		t.Fatal("method return ended an active invocation span")
	}
	if _, err := result.Stream.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(recorder.Ended()) != 0 {
		t.Fatal("start frame invented completion")
	}
	if _, err := result.Stream.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := result.Stream.Close(); err != nil {
		t.Fatal(err)
	}
	spans := recorder.Ended()
	if len(spans) != 1 || spans[0].Name() != "pagnet.invoke" {
		t.Fatal(spans)
	}
	for _, attr := range spans[0].Attributes() {
		if attr.Value.AsString() == "private instruction" {
			t.Fatal("instruction leaked to tracing")
		}
	}
}
