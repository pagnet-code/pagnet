package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestLoadDaemonTelemetryEnvAndFile: the telemetry surface loads with the
// documented precedence (env wins over the state file) and the no-export
// default holds when nothing is set.
func TestLoadDaemonTelemetryEnvAndFile(t *testing.T) {
	dir := t.TempDir()

	// The default: nothing set = the no-op (backward-compatible) config.
	cfg, err := LoadDaemon(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Telemetry.ExporterEndpoint != "" || cfg.Telemetry.ExporterProtocol != "" ||
		len(cfg.Telemetry.Headers) != 0 || cfg.Telemetry.AcceptRemoteParent ||
		cfg.Telemetry.TraceRetention != 0 || cfg.Telemetry.MaxTraces != 0 {
		t.Fatalf("non-default telemetry loaded from nothing: %+v", cfg.Telemetry)
	}

	// The state file fills the telemetry subset.
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(
		"serverUrl: https://control.example\n"+
			"telemetry:\n"+
			"  exporterEndpoint: https://collector.example:4317\n"+
			"  exporterProtocol: grpc\n"+
			"  headers:\n"+
			"    authorization: Bearer file-token\n"+
			"  acceptRemoteParent: true\n"+
			"  traceRetention: \"72h\"\n"+
			"  maxTraces: 5000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = LoadDaemon(dir)
	if err != nil {
		t.Fatal(err)
	}
	tl := cfg.Telemetry
	if tl.ExporterEndpoint != "https://collector.example:4317" || tl.ExporterProtocol != "grpc" {
		t.Fatalf("file endpoint/protocol not loaded: %+v", tl)
	}
	if tl.Headers["authorization"] != "Bearer file-token" {
		t.Fatalf("file headers not loaded: %+v", tl.Headers)
	}
	if !tl.AcceptRemoteParent || tl.TraceRetention != 72*time.Hour || tl.MaxTraces != 5000 {
		t.Fatalf("file retention/max/remote-parent not loaded: %+v", tl)
	}

	// Env wins over the file for every field.
	t.Setenv("PAGNET_OTLP_ENDPOINT", "https://env-collector.example:4317")
	t.Setenv("PAGNET_OTLP_PROTOCOL", "http")
	t.Setenv("PAGNET_OTLP_HEADERS", "authorization=Bearer env-token, x-scope=traces")
	t.Setenv("PAGNET_OTEL_ACCEPT_REMOTE_PARENT", "0") // env false must not override file true...
	cfg, err = LoadDaemon(dir)
	if err != nil {
		t.Fatal(err)
	}
	tl = cfg.Telemetry
	if tl.ExporterEndpoint != "https://env-collector.example:4317" || tl.ExporterProtocol != "http" {
		t.Fatalf("env did not win for endpoint/protocol: %+v", tl)
	}
	if tl.Headers["authorization"] != "Bearer env-token" || tl.Headers["x-scope"] != "traces" {
		t.Fatalf("env headers wrong: %+v", tl.Headers)
	}
	// acceptRemoteParent: env only ever turns it ON; the file's true stands.
	if !tl.AcceptRemoteParent {
		t.Fatalf("file acceptRemoteParent lost: %+v", tl)
	}
	if tl.TraceRetention != 72*time.Hour || tl.MaxTraces != 5000 {
		t.Fatalf("unrelated file fields disturbed: %+v", tl)
	}

	// Env turns the flag on explicitly.
	t.Setenv("PAGNET_OTEL_ACCEPT_REMOTE_PARENT", "true")
	cfg, err = LoadDaemon(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Telemetry.AcceptRemoteParent {
		t.Fatalf("env did not enable acceptRemoteParent: %+v", cfg.Telemetry)
	}
}

// TestLoadDaemonTelemetryFailsClosed: invalid explicit telemetry
// configuration is a load failure, never a silent default.
func TestLoadDaemonTelemetryFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		file string
	}{
		{"bad protocol env", map[string]string{"PAGNET_OTLP_PROTOCOL": "thrift"}, ""},
		{"bad endpoint env", map[string]string{"PAGNET_OTLP_ENDPOINT": "ftp://collector:4317"}, ""},
		{"credentials in endpoint", map[string]string{"PAGNET_OTLP_ENDPOINT": "http://user:pass@collector:4317"}, ""},
		{"retention below bound", map[string]string{"PAGNET_TRACE_RETENTION": "10m"}, ""},
		{"retention above bound", map[string]string{"PAGNET_TRACE_RETENTION": "10000h"}, ""},
		{"max traces beyond bound", map[string]string{"PAGNET_MAX_TRACES": "20000000"}, ""},
		{"bad protocol file", nil, "telemetry:\n  exporterProtocol: thrift\n"},
		{"bad endpoint file", nil, "telemetry:\n  exporterEndpoint: not a url\n"},
		{"bad retention file", nil, "telemetry:\n  traceRetention: \"not-a-duration\"\n"},
		{"out-of-bounds retention file", nil, "telemetry:\n  traceRetention: \"10000h\"\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.file != "" {
				if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(tc.file), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if _, err := LoadDaemon(dir); err == nil {
				t.Fatal("invalid telemetry configuration accepted")
			}
		})
	}
}
