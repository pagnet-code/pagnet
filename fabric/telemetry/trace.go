// Package telemetry implements metadata-only tracing with OpenTelemetry and
// W3C Trace Context. Exporters and remote trust are explicit operator choices.
package telemetry

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// Specification has no application payload, provider error, credential, prompt,
// descriptive endpoint name, workspace, or baggage export surface.
type Specification struct {
	Name            string
	InvocationID    string
	Target          string
	InterceptorID   string
	Stage           string
	Phase           string
	AdapterProtocol string
	Incoming        fabric.TraceContext
}

type Span interface{ End(string) }
type Provider interface {
	Start(context.Context, Specification) (context.Context, Span)
}

type Config struct {
	Tracer trace.Tracer
	// Meter is optional and explicitly supplied by trusted composition. Metric
	// dimensions exclude invocation IDs and target refs to bound cardinality.
	Meter metric.Meter
	// A verified caller's trace is still caller-selected correlation data.
	// Default false does not join an unselected remote parent's trace.
	AcceptRemoteParent bool
}
type OpenTelemetry struct {
	config     Config
	duration   metric.Float64Histogram
	operations metric.Int64Counter
}

func New(config Config) (*OpenTelemetry, error) {
	if config.Tracer == nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Tracing requires an explicit OpenTelemetry tracer")
	}
	p := &OpenTelemetry{config: config}
	if config.Meter != nil {
		var err error
		p.duration, err = config.Meter.Float64Histogram("pagnet.operation.duration", metric.WithUnit("s"), metric.WithDescription("Time until actual operation or stream termination"))
		if err != nil {
			return nil, fabric.NewError(fabric.CodeInvalidInput, "Operation duration instrument unavailable")
		}
		p.operations, err = config.Meter.Int64Counter("pagnet.operation.completed", metric.WithUnit("{operation}"), metric.WithDescription("Terminated operations by infrastructure disposition"))
		if err != nil {
			return nil, fabric.NewError(fabric.CodeInvalidInput, "Operation counter instrument unavailable")
		}
	}
	return p, nil
}

func (p *OpenTelemetry) Start(ctx context.Context, spec Specification) (context.Context, Span) {
	ctx = baggage.ContextWithoutBaggage(ctx)
	if !p.config.AcceptRemoteParent && trace.SpanContextFromContext(ctx).IsRemote() {
		ctx = trace.ContextWithSpanContext(ctx, trace.SpanContext{})
	}
	if p.config.AcceptRemoteParent && len(spec.Incoming.TraceParent) <= 512 && len(spec.Incoming.TraceState) <= 512 {
		// Baggage is deliberately absent: a caller's arbitrary baggage must not
		// leak into downstream headers or telemetry through this core boundary.
		carrier := propagation.MapCarrier{"traceparent": spec.Incoming.TraceParent, "tracestate": spec.Incoming.TraceState}
		ctx = propagation.TraceContext{}.Extract(ctx, carrier)
	}
	name := "pagnet.operation"
	if len(spec.Name) <= 128 && strings.HasPrefix(spec.Name, "pagnet.") && fabric.ValidNamespacedName(spec.Name) {
		name = spec.Name
	}
	attrs := []attribute.KeyValue{}
	if len(spec.InvocationID) > 0 && len(spec.InvocationID) <= 256 {
		attrs = append(attrs, attribute.String("pagnet.invocation.id", spec.InvocationID))
	}
	if ref, err := fabric.ParseEndpointRef(spec.Target); err == nil {
		attrs = append(attrs, attribute.String("pagnet.endpoint.ref", ref.String()))
	}
	if len(spec.InterceptorID) <= 256 && fabric.ValidNamespacedName(spec.InterceptorID) {
		attrs = append(attrs, attribute.String("pagnet.interceptor.id", spec.InterceptorID))
	}
	if len(spec.Stage) <= 128 && fabric.ValidNamespacedName(spec.Stage) {
		attrs = append(attrs, attribute.String("pagnet.operation.stage", spec.Stage))
	}
	switch spec.Phase {
	case "request", "response", "error", "chunk", "completion":
		attrs = append(attrs, attribute.String("pagnet.interceptor.phase", spec.Phase))
	}
	if len(spec.AdapterProtocol) <= 128 && fabric.ValidNamespacedName(spec.AdapterProtocol) {
		attrs = append(attrs, attribute.String("pagnet.adapter.protocol", spec.AdapterProtocol))
	}
	ctx, span := p.config.Tracer.Start(ctx, name, trace.WithSpanKind(trace.SpanKindInternal), trace.WithAttributes(attrs...))
	return ctx, &otelSpan{span: span, provider: p, context: ctx, name: name, started: time.Now()}
}

type otelSpan struct {
	span     trace.Span
	once     sync.Once
	provider *OpenTelemetry
	context  context.Context
	name     string
	started  time.Time
}

func (s *otelSpan) End(disposition string) {
	s.once.Do(func() {
		switch disposition {
		case "completed", "deferred":
			s.span.SetStatus(codes.Ok, "")
		case "cancelled":
			s.span.SetStatus(codes.Error, "operation cancelled")
		case "timeout":
			s.span.SetStatus(codes.Error, "operation timed out")
		case "rejected":
			s.span.SetStatus(codes.Error, "operation rejected")
		default:
			disposition = "failed"
			s.span.SetStatus(codes.Error, "operation failed")
		}
		s.span.SetAttributes(attribute.String("pagnet.operation.disposition", disposition))
		if s.provider.operations != nil {
			// No caller-controlled identity/target, metadata or baggage dimensions.
			attrs := metric.WithAttributes(attribute.String("pagnet.operation", s.name), attribute.String("pagnet.operation.disposition", disposition))
			s.provider.operations.Add(s.context, 1, attrs)
			s.provider.duration.Record(s.context, time.Since(s.started).Seconds(), attrs)
		}
		s.span.End()
	})
}

// Outgoing returns standard trace identifiers only. Baggage is never added.
func Outgoing(ctx context.Context) fabric.TraceContext {
	carrier := propagation.MapCarrier{}
	propagation.TraceContext{}.Inject(ctx, carrier)
	return fabric.TraceContext{TraceParent: carrier.Get("traceparent"), TraceState: carrier.Get("tracestate")}
}

var _ Provider = (*OpenTelemetry)(nil)
