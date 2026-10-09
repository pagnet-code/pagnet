package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	collectormetric "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/pagnet-code/pagnet/fabric"
	fabrictelemetry "github.com/pagnet-code/pagnet/fabric/telemetry"
)

// --- no-op default ----------------------------------------------------------------

// TestComposeNoopDefault: the empty configuration composes the no-op
// export default (the previous behavior) with no durable store, and the
// provider runs spans through without error.
func TestComposeNoopDefault(t *testing.T) {
	stack, err := Compose(context.Background(), Config{})
	if err != nil {
		t.Fatal(err)
	}
	if stack.Store != nil {
		t.Fatal("no trace dir: a durable store was composed")
	}
	if stack.Provider == nil {
		t.Fatal("no provider composed")
	}
	_, span := stack.Provider.Start(context.Background(), fabrictelemetry.Specification{Name: "pagnet.invoke"})
	span.End("completed")
	if err := stack.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Double shutdown is a no-op (idempotent join).
	if err := stack.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestComposeRejectsInvalidConfig: explicit operator configuration fails
// closed at composition — never a silent no-op.
func TestComposeRejectsInvalidConfig(t *testing.T) {
	t.Run("valid no-op combination", func(t *testing.T) {
		// No endpoint and no store: the plain no-op default must compose.
		stack, err := Compose(context.Background(), Config{})
		if err != nil {
			t.Fatalf("no-op default rejected: %v", err)
		}
		stack.Shutdown(context.Background())
	})
	for name, cfg := range map[string]Config{
		"bad protocol":            {ExporterEndpoint: "http://collector:4317", ExporterProtocol: "thrift"},
		"non-http scheme":         {ExporterEndpoint: "ftp://collector:4317"},
		"missing host":            {ExporterEndpoint: "https://"},
		"embedded credentials":    {ExporterEndpoint: "http://token:secret@collector:4317"},
		"query string":            {ExporterEndpoint: "http://collector:4317?x=1"},
		"retention below bound":   {TraceDir: t.TempDir(), Retention: time.Minute},
		"retention above bound":   {TraceDir: t.TempDir(), Retention: 100 * 24 * time.Hour},
		"max traces beyond bound": {TraceDir: t.TempDir(), MaxTraces: 10_000_001},
	} {
		t.Run(name, func(t *testing.T) {
			stack, err := Compose(context.Background(), cfg)
			if err == nil {
				stack.Shutdown(context.Background())
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

// --- real OTLP export over the wire -------------------------------------------------

// stubTraceCollector is a minimal real OTLP gRPC trace collector: it
// records every trace export request (spans + the request metadata), like
// a real collector would receive them.
type stubTraceCollector struct {
	collectortrace.UnimplementedTraceServiceServer
	mu      sync.Mutex
	spans   []*collectorSpan
	headers map[string]string
}

// stubMetricCollector accepts OTLP gRPC metric exports, like a real
// collector would. (The trace and metric services each define an Export
// method with a different signature, so they cannot share one struct.)
type stubMetricCollector struct {
	collectormetric.UnimplementedMetricsServiceServer
}

func (s *stubMetricCollector) Export(ctx context.Context, req *collectormetric.ExportMetricsServiceRequest) (*collectormetric.ExportMetricsServiceResponse, error) {
	return &collectormetric.ExportMetricsServiceResponse{}, nil
}

type collectorSpan struct {
	name    string
	status  string
	attrs   []attribute.KeyValue
	traceID string
	spanID  string
}

func (s *stubTraceCollector) Export(ctx context.Context, req *collectortrace.ExportTraceServiceRequest) (*collectortrace.ExportTraceServiceResponse, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		s.mu.Lock()
		if s.headers == nil {
			s.headers = map[string]string{}
		}
		for k, v := range md {
			s.headers[k] = strings.Join(v, ",")
		}
		s.mu.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rs := range req.ResourceSpans {
		for _, ss := range rs.ScopeSpans {
			for _, sp := range ss.Spans {
				attrs := make([]attribute.KeyValue, 0, len(sp.Attributes))
				for _, kv := range sp.Attributes {
					attrs = append(attrs, attribute.KeyValue{
						Key:   attribute.Key(kv.Key),
						Value: attribute.StringValue(kv.Value.GetStringValue()),
					})
				}
				s.spans = append(s.spans, &collectorSpan{
					name:    sp.Name,
					status:  sp.Status.GetMessage(),
					attrs:   attrs,
					traceID: fmt.Sprintf("%x", sp.TraceId),
					spanID:  fmt.Sprintf("%x", sp.SpanId),
				})
			}
		}
	}
	return &collectortrace.ExportTraceServiceResponse{}, nil
}

func (s *stubTraceCollector) all() []*collectorSpan {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*collectorSpan, len(s.spans))
	copy(out, s.spans)
	return out
}

// allText returns every exported string field (names, statuses, ids,
// attribute keys and values): the complete exported-text surface a leak
// would have to appear in.
func (s *stubTraceCollector) allText() []string {
	var out []string
	for _, sp := range s.all() {
		out = append(out, sp.name, sp.status, sp.traceID, sp.spanID)
		for _, a := range sp.attrs {
			out = append(out, string(a.Key), a.Value.AsString())
		}
	}
	return out
}

func (s *stubTraceCollector) header(k string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.headers[k]
}

func startGRPCCollector(t *testing.T) (*stubTraceCollector, string) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	collector := &stubTraceCollector{}
	srv := grpc.NewServer()
	collectortrace.RegisterTraceServiceServer(srv, collector)
	collectormetric.RegisterMetricsServiceServer(srv, &stubMetricCollector{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return collector, "http://" + lis.Addr().String()
}

// TestComposeOTLPGRPCRealExport: with a configured endpoint the factory
// composes a REAL OTLP gRPC exporter + BatchSpanProcessor: a span ended on
// the provider is exported over the wire on shutdown, and the configured
// headers ride on the export request.
func TestComposeOTLPGRPCRealExport(t *testing.T) {
	collector, endpoint := startGRPCCollector(t)
	stack, err := Compose(context.Background(), Config{
		ExporterEndpoint: endpoint,
		ExporterProtocol: "grpc",
		Headers:          map[string]string{"authorization": "Bearer export-token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, span := stack.Provider.Start(context.Background(), fabrictelemetry.Specification{Name: "pagnet.invoke"})
	span.End("completed")
	// Shutdown flushes the BatchSpanProcessor through the exporter.
	if err := stack.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	spans := collector.all()
	if len(spans) != 1 {
		t.Fatalf("exported %d spans, want 1", len(spans))
	}
	if spans[0].name != "pagnet.invoke" {
		t.Fatalf("exported span name = %q", spans[0].name)
	}
	if got := collector.header("authorization"); got != "Bearer export-token" {
		t.Fatalf("export header authorization = %q, want the configured token", got)
	}
}

// TestComposeOTLPHTTPRealExport: the http protocol composes the OTLP HTTP
// exporter + the PeriodicReader metric reader: on shutdown both the spans
// and the metrics are exported to their endpoints, with the headers.
func TestComposeOTLPHTTPRealExport(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	authSeen := ""
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		authSeen = r.Header.Get("Authorization")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	stack, err := Compose(context.Background(), Config{
		ExporterEndpoint: ts.URL,
		ExporterProtocol: "http",
		Headers:          map[string]string{"authorization": "Bearer http-token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, span := stack.Provider.Start(context.Background(), fabrictelemetry.Specification{Name: "pagnet.invoke"})
	span.End("completed")
	if err := stack.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	hasTraces, hasMetrics := false, false
	for _, p := range paths {
		if p == "/v1/traces" {
			hasTraces = true
		}
		if p == "/v1/metrics" {
			hasMetrics = true
		}
	}
	if !hasTraces {
		t.Fatalf("spans were not exported over OTLP HTTP: paths = %v", paths)
	}
	if !hasMetrics {
		t.Fatalf("metrics were not exported over OTLP HTTP: paths = %v", paths)
	}
	if authSeen != "Bearer http-token" {
		t.Fatalf("export header authorization = %q, want the configured token", authSeen)
	}
}

// --- the secret-scrubbing invariant --------------------------------------------------

const scrubSecret = "super-secret-sentinel-0f1e2d3c"

// TestComposeSecretScrubbingEndToEnd is the dedicated scrubbing proof: a
// trace carrying a secret in the baggage, in the incoming HTTP header
// surface (tracestate + baggage), in a target URL credential, in a span
// name and in the termination reason does NOT leak the secret into the
// exported span attributes (over real OTLP) or into the durable trace
// store. The metadata-only invariants are the invariant; this test is the
// proof.
func TestComposeSecretScrubbingEndToEnd(t *testing.T) {
	collector, endpoint := startGRPCCollector(t)
	dir := t.TempDir()
	stack, err := Compose(context.Background(), Config{
		ExporterEndpoint: endpoint,
		ExporterProtocol: "grpc",
		TraceDir:         dir,
		// The WIDEST remote-trust setting: the incoming headers are
		// honored, so this is the highest-leak-risk configuration.
		AcceptRemoteParent: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// (1) The secret in the in-process baggage.
	member, err := baggage.NewMember("x-api-key", scrubSecret)
	if err != nil {
		t.Fatal(err)
	}
	bag, err := baggage.New(member)
	if err != nil {
		t.Fatal(err)
	}
	ctx := baggage.ContextWithBaggage(context.Background(), bag)

	// (2) The secret in the incoming W3C header surface (tracestate and
	// baggage header). AcceptRemoteParent injects traceparent + tracestate;
	// the baggage header must never be injected.
	spec := fabrictelemetry.Specification{
		Name:         "pagnet.invoke",
		InvocationID: "inv-scrub",
		Incoming: fabric.TraceContext{
			TraceParent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
			TraceState:  "vendor=" + scrubSecret,
			Baggage:     "x-api-key=" + scrubSecret,
		},
	}

	// (3) The secret in a target URL credential: the endpoint-ref parser
	// must not accept it, so no attribute may carry it.
	spec.Target = "https://user:" + scrubSecret + "@collector.example/endpoint"

	// (4) The secret in the span name: a name that is not a valid
	// pagnet.* namespaced name (the space invalidates it) must fall back
	// to the neutral "pagnet.operation" — never stored verbatim.
	spec.Name = "pagnet. " + scrubSecret
	_, span := stack.Provider.Start(ctx, spec)
	span.End("completed")

	// (5) A caller-controlled termination reason must map to the fixed
	// status vocabulary, not be exported verbatim.
	neutral := fabrictelemetry.Specification{Name: "pagnet.invoke", InvocationID: "inv-scrub"}
	ctx2, span2 := stack.Provider.Start(context.Background(), neutral)
	span2.End("failed-with-" + scrubSecret)
	_ = ctx2

	if err := stack.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}

	// The exported span surface (real OTLP over the wire).
	for _, text := range collector.allText() {
		if strings.Contains(text, scrubSecret) {
			t.Fatalf("secret leaked into the exported span surface: %q", text)
		}
	}

	// The durable trace store surface: every stored byte.
	store, err := OpenTraceStoreReadonly(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	spans, err := store.SpansForInvocation(context.Background(), "inv-scrub", MaxTraceQueryLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) == 0 {
		t.Fatal("no spans were durably recorded")
	}
	for _, sp := range spans {
		row, err := json.Marshal(sp)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(row), scrubSecret) {
			t.Fatalf("secret leaked into the durable trace store row: %s", row)
		}
		// The status vocabulary held: fixed descriptions only.
		switch sp.StatusDescription {
		case "", "operation cancelled", "operation timed out", "operation rejected", "operation failed":
		default:
			t.Fatalf("non-vocabulary status description stored: %q", sp.StatusDescription)
		}
	}
	// The neutral fallback name is what the invalid secret name became.
	fallback := 0
	for _, sp := range spans {
		if sp.Name == "pagnet.operation" {
			fallback++
		}
	}
	if fallback == 0 {
		t.Fatal("the invalid secret span name did not fall back to pagnet.operation")
	}
}

// TestComposeOutgoingCarriesNoBaggage: the outgoing W3C context the node
// forwards downstream carries only traceparent/tracestate — never the
// (stripped) baggage.
func TestComposeOutgoingCarriesNoBaggage(t *testing.T) {
	stack, err := Compose(context.Background(), Config{AcceptRemoteParent: true})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Shutdown(context.Background())
	member, err := baggage.NewMember("x-api-key", scrubSecret)
	if err != nil {
		t.Fatal(err)
	}
	bag, err := baggage.New(member)
	if err != nil {
		t.Fatal(err)
	}
	spec := fabrictelemetry.Specification{
		Name:         "pagnet.invoke",
		InvocationID: "inv-outgoing",
		Incoming: fabric.TraceContext{
			TraceParent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
			Baggage:     "x-api-key=" + scrubSecret,
		},
	}
	ctx, span := stack.Provider.Start(baggage.ContextWithBaggage(context.Background(), bag), spec)
	out := fabrictelemetry.Outgoing(ctx)
	if out.Baggage != "" {
		t.Fatalf("baggage leaked into the outgoing context: %q", out.Baggage)
	}
	if !strings.Contains(out.TraceParent, "4bf92f3577b34da6a3ce929d0e0e4736") {
		t.Fatalf("the accepted remote parent was not continued: %q", out.TraceParent)
	}
	span.End("completed")
}
