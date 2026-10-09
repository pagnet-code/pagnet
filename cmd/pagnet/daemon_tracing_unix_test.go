//go:build linux || darwin

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	collectormetric "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/internal/fabricclient"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
	"github.com/pagnet-code/pagnet/internal/fabricnode"
	otel "github.com/pagnet-code/pagnet/internal/telemetry"
)

// wiringMetricCollector accepts the OTLP gRPC metric exports the stack's
// meter reader sends to the same collector, like a real collector would.
type wiringMetricCollector struct {
	collectormetric.UnimplementedMetricsServiceServer
}

func (c *wiringMetricCollector) Export(ctx context.Context, req *collectormetric.ExportMetricsServiceRequest) (*collectormetric.ExportMetricsServiceResponse, error) {
	return &collectormetric.ExportMetricsServiceResponse{}, nil
}

// wiringCollector is a real OTLP gRPC trace collector for the wiring test:
// it records the names and attribute key/value text of every exported span.
type wiringCollector struct {
	collectortrace.UnimplementedTraceServiceServer
	mu    sync.Mutex
	spans []wiringSpan
}

type wiringSpan struct {
	name  string
	attrs map[string]string
}

func (c *wiringCollector) Export(ctx context.Context, req *collectortrace.ExportTraceServiceRequest) (*collectortrace.ExportTraceServiceResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, rs := range req.ResourceSpans {
		for _, ss := range rs.ScopeSpans {
			for _, sp := range ss.Spans {
				attrs := map[string]string{}
				for _, kv := range sp.Attributes {
					attrs[kv.Key] = kv.Value.GetStringValue()
				}
				c.spans = append(c.spans, wiringSpan{name: sp.Name, attrs: attrs})
			}
		}
	}
	return &collectortrace.ExportTraceServiceResponse{}, nil
}

func (c *wiringCollector) find(name string) *wiringSpan {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.spans {
		if c.spans[i].name == name {
			return &c.spans[i]
		}
	}
	return nil
}

// TestDaemonWiringRecordsAndExportsFabricSpans is the wiring proof for E4.4
// sub-item 4: the installed node's InstalledConfig.Tracing carries the
// REAL composed provider (not the noop default), so a genuine owner
// discover call served by the installed node is (a) durably recorded in
// the state-dir trace store and (b) exported over the real OTLP gRPC wire.
func TestDaemonWiringRecordsAndExportsFabricSpans(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// A real OTLP gRPC collector on a loopback port records the export.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	collector := &wiringCollector{}
	srv := grpc.NewServer()
	collectortrace.RegisterTraceServiceServer(srv, collector)
	collectormetric.RegisterMetricsServiceServer(srv, &wiringMetricCollector{})
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()
	endpoint := "http://" + lis.Addr().String()

	// A real local installation, bootstrapped and closed (the fused
	// serve reopens it, exactly as pagnet serve does).
	parent := t.TempDir()
	dir := filepath.Join(parent, "authority")
	run := filepath.Join(parent, "run")
	if err := os.Mkdir(run, 0o700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(run, "node.sock")
	installation, err := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if err != nil {
		t.Fatal(err)
	}
	if err := installation.Close(); err != nil {
		t.Fatal(err)
	}

	// The daemon's observability stack: the configured OTLP gRPC exporter
	// + the bounded durable metadata-only trace store in the state dir.
	stack, err := otel.Compose(ctx, otel.Config{
		ExporterEndpoint: endpoint,
		ExporterProtocol: "grpc",
		TraceDir:         filepath.Join(parent, "telemetry"),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Teardown in flush order, run exactly once: the node closes first
	// (final spans end), then the stack shuts down (the BatchSpanProcessor
	// flushes the exporter and the store closes). Deferred as a safety net
	// for the set-up failures below.
	var node *fabricnode.InstalledNode
	cleaned := false
	cleanup := func() {
		if cleaned {
			return
		}
		cleaned = true
		if node != nil {
			_ = node.Close()
		}
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()
		_ = stack.Shutdown(shutdownCtx)
	}
	defer cleanup()

	// The wiring under test: the fused installation opens with the real
	// provider, so InstalledConfig.Tracing is no longer the noop default.
	node, err = openFusedInstallation(ctx, dir, stack.Provider)
	if err != nil {
		t.Fatalf("openFusedInstallation: %v", err)
	}
	if node == nil || node.Hosted == nil {
		t.Fatal("the installed hosted product was not composed")
	}

	// A genuine owner call served by the installed node.
	client, err := fabricclient.Dial(ctx, socket, fabrichost.Authentication{Type: "fabric.auth", Mode: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Call(ctx, fabric.OperationDiscover, json.RawMessage(`{"query":"hello","limit":1}`))
	if err != nil || result.IsError {
		t.Fatalf("installed node did not serve the discover call: %v %v", err, result)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	// Teardown NOW, before the assertions: the BatchSpanProcessor flushes
	// on the stack shutdown, so the export (and the durable record) must
	// be complete before the surfaces are checked.
	cleanup()

	// The exported span surface (real OTLP gRPC over the wire): the node's
	// Execute span is pagnet.discover, keyed by the envelope invocation id.
	span := collector.find("pagnet.discover")
	if span == nil {
		var names []string
		collector.mu.Lock()
		for _, s := range collector.spans {
			names = append(names, s.name)
		}
		collector.mu.Unlock()
		t.Fatalf("the pagnet.discover span was not exported; exported spans = %v", names)
	}
	invocation := span.attrs["pagnet.invocation.id"]
	if invocation == "" {
		t.Fatalf("the exported span carries no pagnet.invocation.id: %v", span.attrs)
	}
	if len(invocation) > 256 {
		t.Fatalf("the invocation id exceeds the bound: %d bytes", len(invocation))
	}

	// The durable trace store surface: the same span is durably recorded,
	// keyed by the invocation id — this is what `pagnet trace <invocation>`
	// reads.
	store, err := otel.OpenTraceStoreReadonly(filepath.Join(parent, "telemetry"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	spans, err := store.SpansForInvocation(ctx, invocation, 100)
	if err != nil {
		t.Fatal(err)
	}
	stored := 0
	for _, s := range spans {
		if s.Name == "pagnet.discover" {
			stored++
			if s.Disposition != "completed" {
				t.Fatalf("the recorded discover span disposition = %q, want completed", s.Disposition)
			}
			// The stored row is metadata only: bounded pagnet.* fields.
			for k := range jsonMap(t, s.Attributes) {
				if !strings.HasPrefix(k, "pagnet.") {
					t.Fatalf("stored attribute outside the pagnet.* restriction: %q", k)
				}
			}
		}
	}
	if stored == 0 {
		t.Fatalf("the discover span was not durably recorded (invocation %s, %d spans)", invocation, len(spans))
	}
}

func jsonMap(t *testing.T, raw string) map[string]any {
	t.Helper()
	out := map[string]any{}
	if raw == "" || raw == "null" {
		return out
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("stored attributes are not a JSON object: %v (%s)", err, fmt.Sprintf("%.64s", raw))
	}
	return out
}
