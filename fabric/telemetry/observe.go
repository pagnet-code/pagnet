package telemetry

import (
	"context"
	"errors"
	"sync"

	"github.com/pagnet-code/pagnet/fabric"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/trace"
)

type SearchReader interface {
	Search(context.Context, fabric.DiscoverRequest) (fabric.DiscoverResult, error)
}

// ObserveSearch measures the actual search backend without exporting queries,
// candidate names, schemas or external provider errors. Nil tracing is inert.
func ObserveSearch(reader SearchReader, tracing Provider) SearchReader {
	if tracing == nil || reader == nil {
		return reader
	}
	return &observedSearch{reader, tracing}
}

type observedSearch struct {
	reader  SearchReader
	tracing Provider
}

func (s *observedSearch) Search(ctx context.Context, request fabric.DiscoverRequest) (result fabric.DiscoverResult, err error) {
	if ctx == nil {
		return result, fabric.NewError(fabric.CodeInvalidInput, "Missing search context")
	}
	ctx, span := s.tracing.Start(ctx, Specification{Name: "pagnet.search"})
	returned := false
	defer func() {
		if returned {
			span.End(disposition(err))
		} else {
			span.End("failed")
		}
	}()
	result, err = s.reader.Search(ctx, request)
	returned = true
	return result, err
}

// ObserveAdapter retains demand-driven streaming and measures until a genuine
// terminal frame, cancellation or failure. It never drains/buffers a stream or
// retries an adapter. Only bounded infrastructure metadata enters tracing.
func ObserveAdapter(adapter fabric.EndpointAdapter, protocol string, tracing Provider) fabric.EndpointAdapter {
	if tracing == nil || adapter == nil {
		return adapter
	}
	return &observedAdapter{adapter, protocol, tracing}
}

type observedAdapter struct {
	adapter  fabric.EndpointAdapter
	protocol string
	tracing  Provider
}

func (a *observedAdapter) Invoke(ctx context.Context, caller fabric.ExecutionContext, endpoint fabric.EndpointDescriptor, request fabric.InvokeRequest) (fabric.InvocationStream, error) {
	if ctx == nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Missing adapter context")
	}
	ctx, span := a.tracing.Start(ctx, Specification{Name: "pagnet.adapter", AdapterProtocol: a.protocol, InvocationID: request.InvocationID, Target: request.Target.String()})
	transferred := false
	defer func() {
		if !transferred {
			span.End("failed")
		}
	}()
	stream, err := a.adapter.Invoke(ctx, caller, endpoint, request)
	if err != nil || stream == nil {
		state := disposition(err)
		if stream == nil && err == nil {
			state = "failed"
		}
		span.End(state)
		transferred = true
		// Observation never changes the adapter result or owns a failed stream.
		// The dispatcher handles protocol validation and resource cleanup.
		return stream, err
	}
	transferred = true
	return &observedAdapterStream{upstream: stream, span: span, parent: ctx, invocation: request.InvocationID}, nil
}

type observedAdapterStream struct {
	upstream   fabric.InvocationStream
	span       Span
	parent     context.Context
	invocation string
	end        sync.Once
}

func (s *observedAdapterStream) finish(state string) { s.end.Do(func() { s.span.End(state) }) }
func (s *observedAdapterStream) Next(ctx context.Context) (fabric.InvocationFrame, error) {
	if ctx == nil {
		return fabric.InvocationFrame{}, fabric.NewError(fabric.CodeInvalidInput, "Missing stream context")
	}
	// Preserve this demand's deadlines, cancellation and private admission data;
	// propagate only the local adapter span, never caller baggage.
	ctx = trace.ContextWithSpanContext(baggage.ContextWithoutBaggage(ctx), trace.SpanContextFromContext(s.parent))
	frame, err := s.upstream.Next(ctx)
	if err != nil {
		s.finish(disposition(err))
	} else if frame.Kind == fabric.FrameComplete && frame.InvocationID == s.invocation {
		s.finish("completed")
	} else if frame.Kind == fabric.FrameError {
		s.finish(disposition(frame.Error))
	}
	return frame, err
}
func (s *observedAdapterStream) Close() error {
	err := s.upstream.Close()
	if err != nil {
		s.finish(disposition(err))
	} else {
		s.finish("cancelled")
	}
	return err
}
func disposition(err error) string {
	if err == nil {
		return "completed"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var typed *fabric.Error
	if errors.As(err, &typed) && typed != nil {
		switch typed.Code {
		case fabric.CodeCancelled:
			return "cancelled"
		case fabric.CodeDeadlineExceeded, fabric.CodeInterceptorTimeout:
			return "timeout"
		case fabric.CodeInterceptorRejected:
			return "rejected"
		}
	}
	return "failed"
}
