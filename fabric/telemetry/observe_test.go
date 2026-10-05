package telemetry

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	sdk "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

type observationSearch struct{}

func (observationSearch) Search(context.Context, fabric.DiscoverRequest) (fabric.DiscoverResult, error) {
	return fabric.DiscoverResult{}, errors.New("private-needle")
}

type observationAdapter struct {
	calls  int
	stream *observationStream
}

func (a *observationAdapter) Invoke(ctx context.Context, _ fabric.ExecutionContext, _ fabric.EndpointDescriptor, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
	a.calls++
	a.stream.id = r.InvocationID
	a.stream.started = trace.SpanContextFromContext(ctx).IsValid()
	return a.stream, nil
}

type observationStream struct {
	id                         string
	remaining, calls           int
	data                       []byte
	started, closed, premature bool
}

func (s *observationStream) Next(ctx context.Context) (fabric.InvocationFrame, error) {
	s.calls++
	if !trace.SpanContextFromContext(ctx).IsValid() {
		return fabric.InvocationFrame{}, errors.New("missing adapter trace")
	}
	if s.premature {
		return fabric.InvocationFrame{}, io.EOF
	}
	kind := fabric.FrameChunk
	if s.remaining == 0 {
		kind = fabric.FrameComplete
	} else {
		s.remaining--
	}
	return fabric.InvocationFrame{InvocationID: s.id, Sequence: uint64(s.calls), Kind: kind, Data: s.data}, nil
}
func (s *observationStream) Close() error { s.closed = true; return nil }

func TestActualTracingDoesNotBufferStreamsExportContentOrInventEOFCompletion(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	provider := sdk.NewTracerProvider(sdk.WithSpanProcessor(recorder))
	defer provider.Shutdown(context.Background())
	p, err := New(Config{Tracer: provider.Tracer("pagnet/observation")})
	if err != nil {
		t.Fatal(err)
	}
	search := ObserveSearch(observationSearch{}, p)
	if _, err = search.Search(t.Context(), fabric.DiscoverRequest{Query: "private-needle", Limit: 1}); err == nil {
		t.Fatal("search outcome changed")
	}
	data := bytes.Repeat([]byte("private-needle"), 1000)
	upstream := &observationAdapter{stream: &observationStream{remaining: 10000, data: data}}
	adapter := ObserveAdapter(upstream, "service.mcp", p)
	stream, err := adapter.Invoke(t.Context(), fabric.ExecutionContext{}, fabric.EndpointDescriptor{}, fabric.InvokeRequest{InvocationID: "stream", Input: []byte(`{"prompt":"private-needle"}`)})
	if err != nil || upstream.calls != 1 || upstream.stream.calls != 0 || !upstream.stream.started {
		t.Fatal("adapter not demand-driven", err)
	}
	if len(recorder.Ended()) != 1 {
		t.Fatal("stream span ended before consumption")
	}
	for range 10000 {
		frame, err := stream.Next(t.Context())
		if err != nil || frame.Kind != fabric.FrameChunk || !bytes.Equal(frame.Data, data) {
			t.Fatal("original output changed", err)
		}
	}
	if upstream.stream.calls != 10000 || len(recorder.Ended()) != 1 {
		t.Fatal("hidden read or buffered completion")
	}
	frame, err := stream.Next(t.Context())
	if err != nil || frame.Kind != fabric.FrameComplete {
		t.Fatal("original terminal missing", err)
	}
	if err = stream.Close(); err != nil || !upstream.stream.closed {
		t.Fatal("producer close lost", err)
	}
	if len(recorder.Ended()) != 2 {
		t.Fatal("completion span ended more than once")
	}
	broken := &observationAdapter{stream: &observationStream{premature: true}}
	bad, _ := ObserveAdapter(broken, "service.mcp", p).Invoke(t.Context(), fabric.ExecutionContext{}, fabric.EndpointDescriptor{}, fabric.InvokeRequest{InvocationID: "broken"})
	if _, err = bad.Next(t.Context()); !errors.Is(err, io.EOF) {
		t.Fatal("observation changed original EOF", err)
	}
	_ = bad.Close()
	ended := recorder.Ended()
	if len(ended) != 3 {
		t.Fatal("unexpected observed operation count")
	}
	for i, span := range ended {
		state := ""
		for _, attr := range span.Attributes() {
			if strings.Contains(attr.Value.AsString(), "private-needle") {
				t.Fatal("content leaked", attr)
			}
			if string(attr.Key) == "pagnet.operation.disposition" {
				state = attr.Value.AsString()
			}
		}
		want := "failed"
		if i == 1 {
			want = "completed"
		}
		if state != want {
			t.Fatal("false completion/disposition", i, state)
		}
	}
}
