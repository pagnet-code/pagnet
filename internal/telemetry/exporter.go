// Package telemetry composes the daemon's configured OpenTelemetry
// observability stack: an explicit OTLP exporter (empty endpoint = the
// no-op default, backward compatible) plus the bounded durable
// metadata-only trace store. The stack ships only what fabric/telemetry
// already sanitizes — no payload, secret, prompt, credential or baggage
// reaches the exported spans, the metrics, or the stored rows.
package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	fabrictelemetry "github.com/pagnet-code/pagnet/fabric/telemetry"
)

// OTLP protocol selections.
const (
	ProtocolGRPC = "grpc"
	ProtocolHTTP = "http"
)

// tracePruneInterval is the periodic retention sweep while a daemon runs.
const tracePruneInterval = time.Hour

// metricExportInterval / metricExportTimeout bound the periodic metric
// export; both are finite and operator-facing (never unbounded).
const (
	metricExportInterval = 30 * time.Second
	metricExportTimeout  = 10 * time.Second
)

// Config is the daemon's observability surface (from the daemon config's
// Telemetry field). ExporterEndpoint empty keeps the no-op export default;
// the durable trace store (TraceDir) is independent of export and is
// bounded by Retention and MaxTraces.
type Config struct {
	// ExporterEndpoint is the OTLP collector endpoint (http:// or
	// https://, no embedded credentials). Empty = no export.
	ExporterEndpoint string
	// ExporterProtocol selects OTLP gRPC ("grpc", the default) or OTLP
	// HTTP/protobuf ("http").
	ExporterProtocol string
	// Headers are the OTLP request headers (e.g. authorization). They
	// ride on the export transport only and never enter telemetry.
	Headers map[string]string
	// AcceptRemoteParent joins an incoming W3C trace parent (default
	// false: the node never continues a caller-selected remote trace).
	AcceptRemoteParent bool
	// TraceDir is the durable trace store directory. Empty = no local
	// durable trace store.
	TraceDir string
	// Retention bounds the durable trace store (zero = the 30d default).
	Retention time.Duration
	// MaxTraces bounds the durable trace store's row count (zero = the
	// 100000 default).
	MaxTraces int
}

// Stack is one composed daemon observability stack. Provider is the
// fabric telemetry provider the installed node runs with; Store is the
// durable metadata-only trace store (nil when TraceDir is empty).
type Stack struct {
	Provider    fabrictelemetry.Provider
	Store       *TraceStore
	tracer      *sdktrace.TracerProvider
	meter       *sdkmetric.MeterProvider
	pruneCancel context.CancelFunc

	shutdownOnce sync.Once
	shutdownErr  error
}

// Compose builds the configured observability stack. It never contacts the
// collector eagerly (the gRPC connection is lazy; the HTTP exporter dials
// per export), so composition is safe before any traffic. A misconfigured
// exporter is a composition error, never a silent no-op: explicit operator
// configuration fails closed.
func Compose(ctx context.Context, cfg Config) (*Stack, error) {
	if ctx == nil {
		return nil, errors.New("observability composition requires a context")
	}
	protocol := strings.TrimSpace(cfg.ExporterProtocol)
	if protocol == "" {
		protocol = ProtocolGRPC
	}
	if protocol != ProtocolGRPC && protocol != ProtocolHTTP {
		return nil, fmt.Errorf("exporter protocol must be %q or %q (got %q)", ProtocolGRPC, ProtocolHTTP, cfg.ExporterProtocol)
	}
	endpoint := strings.TrimSpace(cfg.ExporterEndpoint)
	var endpointURL *url.URL
	if endpoint != "" {
		parsed, err := url.Parse(endpoint)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
			parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, errors.New("exporter endpoint must be an http(s) URL with a host and no embedded credentials, query or fragment")
		}
		endpointURL = parsed
	}

	var store *TraceStore
	if cfg.TraceDir != "" {
		var err error
		store, err = OpenTraceStore(cfg.TraceDir, StoreConfig{Retention: cfg.Retention, MaxTraces: cfg.MaxTraces})
		if err != nil {
			return nil, err
		}
	}
	// Every composition error path closes a store it already opened
	// (explicitly, below): a failed composition never leaks the file.
	cleanup := func() {
		if store != nil {
			_ = store.Close()
		}
	}
	stack := &Stack{Store: store}

	var processors []sdktrace.SpanProcessor
	if store != nil {
		processors = append(processors, &storeSpanProcessor{store: store})
	}
	var tracerProvider *sdktrace.TracerProvider
	var meterProvider *sdkmetric.MeterProvider
	if endpointURL != nil {
		traceExporter, err := newOTLPTraceExporter(ctx, endpointURL, protocol, cfg.Headers)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("compose OTLP trace exporter: %w", err)
		}
		processors = append(processors, sdktrace.NewBatchSpanProcessor(traceExporter))
		metricExporter, err := newOTLPMetricExporter(ctx, endpointURL, protocol, cfg.Headers)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("compose OTLP metric exporter: %w", err)
		}
		meterProvider = sdkmetric.NewMeterProvider(sdkmetric.WithReader(
			sdkmetric.NewPeriodicReader(metricExporter,
				sdkmetric.WithInterval(metricExportInterval),
				sdkmetric.WithTimeout(metricExportTimeout)),
		))
	}
	if len(processors) > 0 {
		var tracerOpts []sdktrace.TracerProviderOption
		for _, p := range processors {
			tracerOpts = append(tracerOpts, sdktrace.WithSpanProcessor(p))
		}
		tracerProvider = sdktrace.NewTracerProvider(tracerOpts...)
	}
	var tracer trace.Tracer
	if tracerProvider != nil {
		tracer = tracerProvider.Tracer("pagnet/fabric")
	} else {
		tracer = noop.NewTracerProvider().Tracer("pagnet/fabric")
	}
	var meter = metricnoop.MeterProvider{}.Meter("pagnet/fabric")
	if meterProvider != nil {
		meter = meterProvider.Meter("pagnet/fabric")
	}
	provider, err := fabrictelemetry.New(fabrictelemetry.Config{
		Tracer:             tracer,
		Meter:              meter,
		AcceptRemoteParent: cfg.AcceptRemoteParent,
	})
	if err != nil {
		// Join the tracer provider first (its processors reference the
		// store), then release the store.
		if tracerProvider != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = tracerProvider.Shutdown(shutdownCtx)
			cancel()
		}
		if meterProvider != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = meterProvider.Shutdown(shutdownCtx)
			cancel()
		}
		cleanup()
		return nil, err
	}
	stack.Provider = provider
	stack.tracer = tracerProvider
	stack.meter = meterProvider
	if store != nil {
		stack.pruneCancel = startPruneLoop(ctx, store)
	}
	return stack, nil
}

// Shutdown joins the stack: the periodic prune stops, the tracer provider
// flushes its batched spans through the exporter, the meter provider
// flushes its metric reader, and the durable store closes. It is
// idempotent: a second call returns the first shutdown's result, so a
// daemon error path and the deferred clean-up can both call it.
func (s *Stack) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.shutdownOnce.Do(func() {
		if s.pruneCancel != nil {
			s.pruneCancel()
			s.pruneCancel = nil
		}
		var errs []error
		if s.tracer != nil {
			errs = append(errs, s.tracer.Shutdown(ctx))
		}
		if s.meter != nil {
			errs = append(errs, s.meter.Shutdown(ctx))
		}
		if s.Store != nil {
			errs = append(errs, s.Store.Close())
		}
		s.shutdownErr = errors.Join(errs...)
	})
	return s.shutdownErr
}

// startPruneLoop sweeps the durable store's retention on a periodic
// interval until the daemon context (or its derived cancel) fires. The
// sweep is best-effort: a failed prune is retried on the next tick, and a
// store failure must never take the daemon down.
func startPruneLoop(ctx context.Context, store *TraceStore) context.CancelFunc {
	loopCtx, cancel := context.WithCancel(ctx)
	go func() {
		ticker := time.NewTicker(tracePruneInterval)
		defer ticker.Stop()
		for {
			select {
			case <-loopCtx.Done():
				return
			case <-ticker.C:
				sweep, sweepCancel := context.WithTimeout(context.WithoutCancel(context.Background()), time.Minute)
				_, _ = store.Prune(sweep)
				sweepCancel()
			}
		}
	}()
	return cancel
}

// The OTLP HTTP endpoint selection: a URL with no path (the standard OTLP
// HTTP root, e.g. https://collector:4318) selects the SDK's default service
// paths (/v1/traces, /v1/metrics) via WithEndpoint; an explicit path is
// honored as-is via WithEndpointURL. The scheme selects transport security
// (http = insecure, https = TLS).
func httpRoot(endpoint *url.URL) bool { return endpoint.Path == "" || endpoint.Path == "/" }

func insecure(endpoint *url.URL) bool { return endpoint.Scheme == "http" }

// newOTLPTraceExporter builds the canonical OTLP span exporter for the
// selected protocol. The gRPC dial is lazy, so composition never blocks on
// the collector.
func newOTLPTraceExporter(ctx context.Context, endpoint *url.URL, protocol string, headers map[string]string) (sdktrace.SpanExporter, error) {
	switch protocol {
	case ProtocolGRPC:
		opts := []otlptracegrpc.Option{otlptracegrpc.WithEndpointURL(endpoint.String())}
		if len(headers) > 0 {
			opts = append(opts, otlptracegrpc.WithHeaders(headers))
		}
		return otlptracegrpc.New(ctx, opts...)
	case ProtocolHTTP:
		var opts []otlptracehttp.Option
		if httpRoot(endpoint) {
			opts = []otlptracehttp.Option{otlptracehttp.WithEndpoint(endpoint.Host)}
		} else {
			opts = []otlptracehttp.Option{otlptracehttp.WithEndpointURL(endpoint.String())}
		}
		if insecure(endpoint) {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		if len(headers) > 0 {
			opts = append(opts, otlptracehttp.WithHeaders(headers))
		}
		return otlptracehttp.New(ctx, opts...)
	}
	return nil, fmt.Errorf("unsupported exporter protocol %q", protocol)
}

// newOTLPMetricExporter builds the canonical OTLP metric exporter for the
// selected protocol.
func newOTLPMetricExporter(ctx context.Context, endpoint *url.URL, protocol string, headers map[string]string) (sdkmetric.Exporter, error) {
	switch protocol {
	case ProtocolGRPC:
		opts := []otlpmetricgrpc.Option{otlpmetricgrpc.WithEndpointURL(endpoint.String())}
		if len(headers) > 0 {
			opts = append(opts, otlpmetricgrpc.WithHeaders(headers))
		}
		return otlpmetricgrpc.New(ctx, opts...)
	case ProtocolHTTP:
		var opts []otlpmetrichttp.Option
		if httpRoot(endpoint) {
			opts = []otlpmetrichttp.Option{otlpmetrichttp.WithEndpoint(endpoint.Host)}
		} else {
			opts = []otlpmetrichttp.Option{otlpmetrichttp.WithEndpointURL(endpoint.String())}
		}
		if insecure(endpoint) {
			opts = append(opts, otlpmetrichttp.WithInsecure())
		}
		if len(headers) > 0 {
			opts = append(opts, otlpmetrichttp.WithHeaders(headers))
		}
		return otlpmetrichttp.New(ctx, opts...)
	}
	return nil, fmt.Errorf("unsupported exporter protocol %q", protocol)
}

// storeSpanProcessor persists ended spans into the durable metadata-only
// trace store. It is an SDK span processor, so it sees every span the
// node's tracer ends — it re-applies the metadata-only invariants (the
// pagnet.* key restriction, the field bounds, the allowlists) and drops
// anything that does not pass. Store failures are dropped, never
// propagated: observability must not fail an operation.
type storeSpanProcessor struct {
	store *TraceStore
}

var _ sdktrace.SpanProcessor = (*storeSpanProcessor)(nil)

func (p *storeSpanProcessor) OnStart(context.Context, sdktrace.ReadWriteSpan) {}
func (p *storeSpanProcessor) Shutdown(context.Context) error                  { return nil }
func (p *storeSpanProcessor) ForceFlush(context.Context) error                { return nil }

func (p *storeSpanProcessor) OnEnd(s sdktrace.ReadOnlySpan) {
	rec, ok := spanRecord(s)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), 5*time.Second)
	defer cancel()
	_ = p.store.Record(ctx, rec)
}

// spanRecord extracts one bounded metadata-only record from an ended
// span. A span without an invocation id is not addressable by
// `pagnet trace <invocation>` and is not stored (it is still exported to
// the configured collector, where correlation applies).
func spanRecord(s sdktrace.ReadOnlySpan) (SpanRecord, bool) {
	sc := s.SpanContext()
	if !sc.IsValid() {
		return SpanRecord{}, false
	}
	rec := SpanRecord{
		TraceID:           sc.TraceID().String(),
		SpanID:            sc.SpanID().String(),
		Name:              s.Name(),
		StatusCode:        int(s.Status().Code),
		StatusDescription: s.Status().Description,
		Start:             s.StartTime().UnixNano(),
		End:               s.EndTime().UnixNano(),
	}
	if rec.End < rec.Start {
		rec.End = rec.Start
	}
	if parent := s.Parent(); parent.IsValid() {
		rec.ParentSpanID = parent.SpanID().String()
	}
	attrs := map[string]string{}
	for _, a := range s.Attributes() {
		// The pagnet.* key restriction, re-asserted at the persistence
		// boundary: whatever upstream lets through, only the bounded
		// pagnet.* metadata string values are ever persisted.
		key := string(a.Key)
		if !strings.HasPrefix(key, "pagnet.") {
			continue
		}
		val := a.Value.AsString()
		if val == "" {
			continue
		}
		attrs[key] = val
	}
	// json.Marshal emits map keys in sorted order: deterministic rows.
	attrsJSON, err := json.Marshal(attrs)
	if err != nil {
		return SpanRecord{}, false
	}
	rec.Attributes = string(attrsJSON)
	rec.InvocationID = attrs["pagnet.invocation.id"]
	if rec.InvocationID == "" {
		return SpanRecord{}, false
	}
	rec.Stage = attrs["pagnet.operation.stage"]
	rec.Phase = attrs["pagnet.interceptor.phase"]
	rec.Disposition = attrs["pagnet.operation.disposition"]
	if err := rec.validate(); err != nil {
		return SpanRecord{}, false
	}
	return rec, true
}
