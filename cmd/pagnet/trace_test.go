//go:build linux || darwin

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	otel "github.com/pagnet-code/pagnet/internal/telemetry"
)

// seedTraceStore durably records the given metadata-only spans in the
// state-dir trace store (the layout the daemon composes).
func seedTraceStore(t *testing.T, dir string, spans ...otel.SpanRecord) {
	t.Helper()
	store, err := otel.OpenTraceStore(dir, otel.StoreConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	for _, sp := range spans {
		if err := store.Record(ctx, sp); err != nil {
			t.Fatal(err)
		}
	}
}

// TestTraceCommandPrintsRecordedSpansMetadataOnly: `pagnet trace
// <invocation>` reads the durable trace store and prints the recorded
// spans' bounded metadata (names, stage, phase, disposition, duration) —
// nothing else exists in the store to print.
func TestTraceCommandPrintsRecordedSpansMetadataOnly(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC().UnixNano()
	attrs := `{"pagnet.invocation.id":"inv-cli","pagnet.operation.stage":"pagnet.dispatch","pagnet.interceptor.phase":"response","pagnet.operation.disposition":"completed"}`
	seedTraceStore(t, filepath.Join(root, "telemetry"),
		otel.SpanRecord{
			InvocationID: "inv-cli",
			TraceID:      "4bf92f3577b34da6a3ce929d0e0e4736",
			SpanID:       "a1a1a1a1a1a1a1a1",
			Name:         "pagnet.invoke",
			Stage:        "pagnet.dispatch",
			Phase:        "response",
			Disposition:  "completed",
			StatusCode:   1,
			Attributes:   attrs,
			Start:        now,
			End:          now + int64(1200*time.Millisecond),
		},
		otel.SpanRecord{
			InvocationID:      "inv-cli",
			TraceID:           "4bf92f3577b34da6a3ce929d0e0e4736",
			SpanID:            "b2b2b2b2b2b2b2b2",
			ParentSpanID:      "a1a1a1a1a1a1a1a1",
			Name:              "pagnet.adapter",
			Disposition:       "failed",
			StatusCode:        2,
			StatusDescription: "operation failed",
			Attributes:        `{"pagnet.invocation.id":"inv-cli","pagnet.operation.disposition":"failed"}`,
			Start:             now + int64(100*time.Millisecond),
			End:               now + int64(1300*time.Millisecond),
		},
	)

	savedJSON := jsonOut
	jsonOut = false
	defer func() { jsonOut = savedJSON }()

	cmd := traceCmd()
	cmd.SetArgs([]string{"inv-cli", "--state-dir", root})
	out, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err != nil {
		t.Fatalf("trace: %v", err)
	}
	for _, want := range []string{
		"invocation inv-cli (2 recorded spans):",
		"pagnet.invoke", "pagnet.dispatch", "response", "completed", "1.2s", "a1a1a1a1a1a1a1a1",
		"pagnet.adapter", "failed", "1.2s", "b2b2b2b2b2b2b2b2",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	// The metadata-only store has no payload surface: the private fields
	// never exist in the store, so they cannot be printed.
	if strings.Contains(out, "payload") || strings.Contains(out, "secret") {
		t.Fatalf("output carried non-metadata content:\n%s", out)
	}
}

// TestTraceCommandJSON: `pagnet trace --json` renders the machine-readable
// span records exactly (the stored metadata fields only).
func TestTraceCommandJSON(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC().UnixNano()
	seedTraceStore(t, filepath.Join(root, "telemetry"),
		otel.SpanRecord{
			InvocationID: "inv-json",
			TraceID:      "4bf92f3577b34da6a3ce929d0e0e4736",
			SpanID:       "c3c3c3c3c3c3c3c3",
			Name:         "pagnet.discover",
			Disposition:  "completed",
			StatusCode:   1,
			Attributes:   `{"pagnet.invocation.id":"inv-json","pagnet.operation.disposition":"completed"}`,
			Start:        now,
			End:          now + int64(250*time.Millisecond),
		},
	)

	savedJSON := jsonOut
	jsonOut = true
	defer func() { jsonOut = savedJSON }()

	cmd := traceCmd()
	cmd.SetArgs([]string{"inv-json", "--state-dir", root})
	out, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err != nil {
		t.Fatalf("trace --json: %v", err)
	}
	var rows []struct {
		InvocationID string `json:"invocationId"`
		TraceID      string `json:"traceId"`
		SpanID       string `json:"spanId"`
		Name         string `json:"name"`
		Disposition  string `json:"disposition"`
		StatusCode   int    `json:"statusCode"`
		Start        int64  `json:"startNano"`
		End          int64  `json:"endNano"`
		RetainUntil  int64  `json:"retainUntilNano"`
	}
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("trace --json output is not JSON: %v\n%s", err, out)
	}
	if len(rows) != 1 {
		t.Fatalf("trace --json rows = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.InvocationID != "inv-json" || r.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" ||
		r.SpanID != "c3c3c3c3c3c3c3c3" || r.Name != "pagnet.discover" ||
		r.Disposition != "completed" || r.StatusCode != 1 {
		t.Fatalf("trace --json row wrong: %+v", r)
	}
	if r.RetainUntil <= r.End {
		t.Fatalf("retain_until %d not beyond end %d (retention not applied)", r.RetainUntil, r.End)
	}
}

// TestTraceCommandNoStoreYet: a state dir without a trace store is the
// honest no-traces state (a message, not an error).
func TestTraceCommandNoStoreYet(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(root, 0o700)

	savedJSON := jsonOut
	jsonOut = false
	defer func() { jsonOut = savedJSON }()

	cmd := traceCmd()
	cmd.SetArgs([]string{"inv-none", "--state-dir", root})
	out, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err != nil {
		t.Fatalf("trace with no store: %v", err)
	}
	if !strings.Contains(out, "no recorded spans for invocation inv-none") {
		t.Fatalf("missing the no-traces message:\n%s", out)
	}
}

// TestEventsListCommandJSON: `pagnet events list --json` renders the
// network's event envelope metadata exactly (id, type, target, time — the
// E2EE payload is never fetched or rendered).
func TestEventsListCommandJSON(t *testing.T) {
	ts := newStubV2Server(t, map[string]string{
		"/api/v1/networks":              `[{"ID":"net-1","Name":"default","Slug":"default"}]`,
		"/api/v1/networks/net-1/events": `[{"id":"ev-1","type":"build.completed","targetPrincipalId":"agent-atlas","createdAt":"2026-10-08T10:00:00Z"},{"id":"ev-2","type":"deploy.started"}]`,
	})
	cliEnv(t, ts.ts)
	savedJSON := jsonOut
	jsonOut = true
	defer func() { jsonOut = savedJSON }()

	cmd := eventsCmd()
	cmd.SetArgs([]string{"list"})
	out, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err != nil {
		t.Fatalf("events list: %v", err)
	}
	want := `[
  {
    "id": "ev-1",
    "ID": "",
    "type": "build.completed",
    "Type": "",
    "targetPrincipalId": "agent-atlas",
    "TargetAgentName": null,
    "createdAt": "2026-10-08T10:00:00Z",
    "Timestamp": null
  },
  {
    "id": "ev-2",
    "ID": "",
    "type": "deploy.started",
    "Type": "",
    "targetPrincipalId": null,
    "TargetAgentName": null,
    "createdAt": null,
    "Timestamp": null
  }
]
`
	if out != want {
		t.Fatalf("events list --json golden mismatch:\n--- got ---\n%s\n--- want ---\n%s", out, want)
	}
}

// TestEventsListCommandHuman: `pagnet events list` (without --json) prints
// the metadata table; an empty network prints the honest empty state.
func TestEventsListCommandHuman(t *testing.T) {
	t.Run("rows", func(t *testing.T) {
		ts := newStubV2Server(t, map[string]string{
			"/api/v1/networks":              `[{"ID":"net-1","Name":"default","Slug":"default"}]`,
			"/api/v1/networks/net-1/events": `[{"id":"ev-1","type":"build.completed","createdAt":"2026-10-08T10:00:00Z"}]`,
		})
		cliEnv(t, ts.ts)
		savedJSON := jsonOut
		jsonOut = false
		defer func() { jsonOut = savedJSON }()
		cmd := eventsCmd()
		cmd.SetArgs([]string{"list"})
		out, err := captureStdoutErr(t, func() error { return cmd.Execute() })
		if err != nil {
			t.Fatalf("events list: %v", err)
		}
		for _, want := range []string{"ID", "TYPE", "TARGET", "TIME", "ev-1", "build.completed", "-"} {
			if !strings.Contains(out, want) {
				t.Fatalf("output missing %q:\n%s", want, out)
			}
		}
	})
	t.Run("empty", func(t *testing.T) {
		ts := newStubV2Server(t, map[string]string{
			"/api/v1/networks":              `[{"ID":"net-1","Name":"default","Slug":"default"}]`,
			"/api/v1/networks/net-1/events": `[]`,
		})
		cliEnv(t, ts.ts)
		savedJSON := jsonOut
		jsonOut = false
		defer func() { jsonOut = savedJSON }()
		cmd := eventsCmd()
		cmd.SetArgs([]string{"list"})
		out, err := captureStdoutErr(t, func() error { return cmd.Execute() })
		if err != nil {
			t.Fatalf("events list: %v", err)
		}
		if out != "no events in this network yet\n" {
			t.Fatalf("empty-state output = %q", out)
		}
	})
}

// TestEventsWatchIsTheSharedBody: `pagnet events watch` is the SAME
// live-tail as `pagnet event watch` (the shared runEventWatch body): it
// mints the stream ticket, opens the real SSE stream, and renders the
// envelope metadata of the streamed events.
func TestEventsWatchIsTheSharedBody(t *testing.T) {
	ts := newStubV2Server(t, map[string]string{
		"/api/v1/networks":      `[{"ID":"net-1","Name":"default","Slug":"default"}]`,
		"/api/v1/stream/ticket": `{"ticket":"t-1"}`,
		"/api/v1/events/stream": "data: {\"id\":\"ev-9\",\"eventType\":\"build.completed\",\"networkId\":\"net-1\",\"timestamp\":\"2026-10-08T10:00:00Z\"}\n\n",
	})
	cliEnv(t, ts.ts)
	savedJSON := jsonOut
	jsonOut = false
	defer func() { jsonOut = savedJSON }()

	cmd := eventsCmd()
	cmd.SetArgs([]string{"watch"})
	out, _ := captureStdoutErr(t, func() error { return cmd.Execute() })
	// The stub's stream closes after one event: the watch's returned
	// error (stream closed) is expected; the rendered line is the contract.
	for _, want := range []string{"2026-10-08T10:00:00Z", "build.completed", "net-1", "ev-9"} {
		if !strings.Contains(out, want) {
			t.Fatalf("watch output missing %q:\n%s", want, out)
		}
	}
	if !ts.hasCall("POST /api/v1/stream/ticket") {
		t.Fatal("events watch did not mint the stream ticket")
	}
	if !ts.hasCall("GET /api/v1/events/stream") {
		t.Fatal("events watch did not open the SSE stream")
	}
}
