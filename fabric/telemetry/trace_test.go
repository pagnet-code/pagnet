package telemetry

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/codes"
	sdk "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestDefaultBoundaryStripsAlreadyExtractedRemoteParentAndBaggage(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	provider := sdk.NewTracerProvider(sdk.WithSpanProcessor(recorder))
	defer provider.Shutdown(context.Background())
	tracing, err := New(Config{Tracer: provider.Tracer("pagnet/fabric")})
	if err != nil {
		t.Fatal(err)
	}
	traceID, _ := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	spanID, _ := trace.SpanIDFromHex("00f067aa0ba902b7")
	ctx := trace.ContextWithRemoteSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{TraceID: traceID, SpanID: spanID, Remote: true, TraceFlags: trace.FlagsSampled}))
	member, _ := baggage.NewMember("private", "secret")
	bag, _ := baggage.New(member)
	ctx = baggage.ContextWithBaggage(ctx, bag)
	ctx, span := tracing.Start(ctx, Specification{Name: "pagnet.invoke"})
	if trace.SpanContextFromContext(ctx).TraceID() == traceID || baggage.FromContext(ctx).Len() != 0 {
		t.Fatal("transport-preloaded remote tracing bypassed explicit trust")
	}
	// A local child retains the trusted in-process operation parent.
	_, child := tracing.Start(ctx, Specification{Name: "pagnet.interceptor"})
	child.End("completed")
	span.End("completed")
	ended := recorder.Ended()
	if len(ended) != 2 || ended[0].Parent().SpanID() != ended[1].SpanContext().SpanID() || ended[1].Parent().IsValid() {
		t.Fatal("local nesting or independent root violated", ended)
	}
}

func TestOfficialOpenTelemetryUsesW3CAndOmitsBaggage(t *testing.T) {
	for _, accept := range []bool{false, true} {
		r := tracetest.NewSpanRecorder()
		s := sdk.NewTracerProvider(sdk.WithSpanProcessor(r))
		defer s.Shutdown(context.Background())
		provider, err := New(Config{Tracer: s.Tracer("pagnet/fabric"), AcceptRemoteParent: accept})
		if err != nil {
			t.Fatal(err)
		}
		incoming := fabric.TraceContext{TraceParent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", TraceState: "vendor=value", Baggage: "password=private"}
		ctx, span := provider.Start(context.Background(), Specification{Name: "pagnet.discover", InvocationID: "id", Incoming: incoming})
		out := Outgoing(ctx)
		if out.TraceParent == "" || out.Baggage != "" {
			t.Fatal("W3C context or baggage boundary invalid", out)
		}
		if accept != strings.Contains(out.TraceParent, "4bf92f3577b34da6a3ce929d0e0e4736") {
			t.Fatal("remote trust selection ignored", out)
		}
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() { defer wg.Done(); span.End("completed") }()
		}
		wg.Wait()
		ended := r.Ended()
		if len(ended) != 1 || ended[0].Name() != "pagnet.discover" || ended[0].Status().Code != codes.Ok {
			t.Fatal("span did not finish once", ended)
		}
		for _, attr := range ended[0].Attributes() {
			if strings.Contains(attr.Value.AsString(), "private") {
				t.Fatal("baggage leaked", attr)
			}
		}
	}
}

func TestTraceNamesAndTargetsCannotBecomeArbitraryContentAttributes(t *testing.T) {
	r := tracetest.NewSpanRecorder()
	s := sdk.NewTracerProvider(sdk.WithSpanProcessor(r))
	defer s.Shutdown(context.Background())
	p, _ := New(Config{Tracer: s.Tracer("pagnet/fabric")})
	_, span := p.Start(context.Background(), Specification{Name: "secret prompt", Target: "http://credential:password@provider/", InvocationID: strings.Repeat("x", 257)})
	span.End("provider-error-with-secret")
	ended := r.Ended()
	if len(ended) != 1 || ended[0].Name() != "pagnet.operation" || ended[0].Status().Description != "operation failed" {
		t.Fatal(ended)
	}
	if attrs := ended[0].Attributes(); len(attrs) != 1 || attrs[0].Value.AsString() != "failed" {
		t.Fatal("unbounded/private attributes", attrs)
	}
}
