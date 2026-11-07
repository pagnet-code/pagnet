package runtimeconnect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type inboundFixture struct {
	workspace             string
	features              []string
	trusted               bool
	sessionWorkspace      string
	anonymous             bool
	posts, streams, turns atomic.Int32
	admissionStatus       int
	admission             string
	events                string
	turn                  map[string]any
	wantCursor            string
	streamDelay           time.Duration
}

func newInboundFixture(t *testing.T) (*Qwen, *inboundFixture) {
	t.Helper()
	f := &inboundFixture{workspace: t.TempDir(), trusted: true,
		features:        []string{"mcp_server_runtime_mutation", "workspace_qualified_rest_core", "session_prompt", "session_turn_status"},
		admissionStatus: 202, admission: `{"promptId":"live########1","lastEventId":42,"eventEpoch":"epoch"}`,
		events: "data: {\"v\":1,\"id\":43,\"type\":\"turn_complete\",\"data\":{\"promptId\":\"live########1\"}}\n\n",
		turn:   map[string]any{"promptId": "live########1", "state": "completed", "resultText": "native answer"}, wantCursor: "42"}
	f.sessionWorkspace = f.workspace
	const token = "private-operator-test-token"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" && !f.anonymous {
			w.WriteHeader(401)
			return
		}
		if !f.anonymous && r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("operator bearer not preserved")
		}
		if !f.anonymous && r.Header.Get("X-Qwen-Client-Id") != "client" {
			t.Error("client binding not preserved")
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /capabilities":
			json.NewEncoder(w).Encode(map[string]any{"v": 1, "mode": "http-bridge", "features": f.features, "workspaces": []any{map[string]any{"id": "owned", "cwd": f.workspace, "trusted": f.trusted}}})
		case "GET /session/live/status":
			json.NewEncoder(w).Encode(map[string]any{"sessionId": "live", "workspaceCwd": f.sessionWorkspace})
		case "POST /session/live/prompt":
			f.posts.Add(1)
			var payload struct {
				Prompt         []struct{ Type, Text string }
				IdempotencyKey string
			}
			if json.NewDecoder(r.Body).Decode(&payload) != nil || len(payload.Prompt) != 1 || payload.Prompt[0].Type != "text" || payload.Prompt[0].Text != "question" || payload.IdempotencyKey != "ask-stable" {
				t.Error("unexpected native prompt payload")
			}
			if f.admissionStatus == 0 {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				conn.Close()
				return
			}
			w.WriteHeader(f.admissionStatus)
			fmt.Fprint(w, f.admission)
		case "GET /session/live/events":
			f.streams.Add(1)
			if r.Header.Get("Last-Event-ID") != f.wantCursor || r.Header.Get("X-Qwen-Event-Epoch") != "epoch" || r.Header.Get("Accept") != "text/event-stream" {
				t.Error("event receipt cursor or epoch not preserved")
			}
			w.Header().Set("Content-Type", "text/event-stream")
			if f.streamDelay > 0 {
				w.(http.Flusher).Flush()
				select {
				case <-time.After(f.streamDelay):
				case <-r.Context().Done():
					return
				}
			}
			fmt.Fprint(w, f.events)
		case "GET /session/live/turns/live########1":
			f.turns.Add(1)
			json.NewEncoder(w).Encode(f.turn)
		default:
			t.Errorf("unexpected lifecycle operation: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	t.Cleanup(srv.Close)
	q, err := NewQwen(Binding{URL: srv.URL, Workspace: f.workspace, Session: "live", Client: "client", Name: "owned"}, token)
	if err != nil {
		t.Fatal(err)
	}
	return q, f
}

func TestQwenInboundSSEUsesCallerContextAndFrameCursor(t *testing.T) {
	q, f := newInboundFixture(t)
	q.http.Timeout = 100 * time.Millisecond
	f.streamDelay = 250 * time.Millisecond
	f.events = "id: 43\nevent: turn_complete\ndata: {\"v\":1,\"type\":\"turn_complete\",\"data\":{\"promptId\":\"live########1\"}}\n\n"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := q.Prompt(ctx, "ask-stable", "question")
	if err != nil || result.Uncertain || result.LastEventID != 43 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	q, f = newInboundFixture(t)
	f.streamDelay = time.Second
	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result, err = q.Prompt(ctx, "ask-stable", "question")
	if err == nil || !result.Accepted || !result.Uncertain || f.turns.Load() != 0 {
		t.Fatalf("context ignored: result=%+v err=%v", result, err)
	}
}

func TestQwenInboundSSERejectsMismatchedCursors(t *testing.T) {
	q, f := newInboundFixture(t)
	f.events = "id: 44\ndata: {\"v\":1,\"id\":43,\"type\":\"turn_complete\",\"data\":{\"promptId\":\"live########1\"}}\n\n"
	result, err := q.Prompt(context.Background(), "ask-stable", "question")
	if err == nil || !result.Uncertain || f.turns.Load() != 0 {
		t.Fatalf("cursor mismatch accepted: %+v %v", result, err)
	}
}

func TestQwenInboundAdmitReturnsReceiptBeforeObservation(t *testing.T) {
	q, f := newInboundFixture(t)
	result, err := q.AdmitPrompt(context.Background(), "ask-stable", "question")
	if err != nil || !result.Accepted || !result.Uncertain || result.PromptID != "live########1" || result.LastEventID != 42 || result.EventEpoch != "epoch" || result.ResultText != "" {
		t.Fatalf("admission receipt=%+v err=%v", result, err)
	}
	if f.posts.Load() != 1 || f.streams.Load() != 0 || f.turns.Load() != 0 {
		t.Fatalf("admission observed completion: posts=%d streams=%d turns=%d", f.posts.Load(), f.streams.Load(), f.turns.Load())
	}
	result, err = q.ResumePrompt(context.Background(), result)
	if err != nil || result.Uncertain || result.ResultText != "native answer" || f.posts.Load() != 1 || f.streams.Load() != 1 || f.turns.Load() != 1 {
		t.Fatalf("receipt observation=%+v err=%v", result, err)
	}
}

func TestQwenInboundPromptCorrelatesFinalText(t *testing.T) {
	q, f := newInboundFixture(t)
	f.events = "data: {\"v\":1,\"id\":43,\"type\":\"turn_complete\",\"data\":{\"promptId\":\"unrelated\",\"resultText\":\"wrong\"}}\n\n" +
		"data: {\"v\":1,\"id\":44,\"type\":\"session_update\",\"data\":{\"text\":\"not a result\"}}\n\n" +
		"data: {\"v\":1,\"id\":45,\"type\":\"turn_complete\",\"data\":{\"promptId\":\"live########1\"}}\n\n"
	result, err := q.Prompt(context.Background(), "ask-stable", "question")
	if err != nil || !result.Accepted || result.Uncertain || result.ResultText != "native answer" || result.LastEventID != 45 || f.posts.Load() != 1 || f.turns.Load() != 1 {
		t.Fatalf("result=%+v err=%v counts=%d/%d", result, err, f.posts.Load(), f.turns.Load())
	}
}

func TestQwenInboundPreflightAndValidationNeverPost(t *testing.T) {
	for _, scenario := range []string{"anonymous", "untrusted", "foreign-session", "missing-prompt", "missing-turn-status", "empty-id", "long-id", "empty-text", "long-text"} {
		t.Run(scenario, func(t *testing.T) {
			q, f := newInboundFixture(t)
			id, text := "ask-stable", "question"
			switch scenario {
			case "anonymous":
				f.anonymous = true
			case "untrusted":
				f.trusted = false
			case "foreign-session":
				f.sessionWorkspace = "/foreign"
			case "missing-prompt":
				f.features = f.features[:2]
			case "missing-turn-status":
				f.features = f.features[:3]
			case "empty-id":
				id = ""
			case "long-id":
				id = strings.Repeat("i", 201)
			case "empty-text":
				text = ""
			case "long-text":
				text = strings.Repeat("t", 65537)
			}
			if _, err := q.Prompt(context.Background(), id, text); err == nil || f.posts.Load() != 0 {
				t.Fatal("unsafe prompt was admitted")
			}
		})
	}
}

func TestQwenInboundUncertainAdmissionNeverRetries(t *testing.T) {
	for _, scenario := range []string{"connection-lost", "bad-json", "missing-cursor", "missing-prompt", "negative-cursor", "not-202"} {
		t.Run(scenario, func(t *testing.T) {
			q, f := newInboundFixture(t)
			switch scenario {
			case "connection-lost":
				f.admissionStatus = 0
			case "bad-json":
				f.admission = "{"
			case "missing-cursor":
				f.admission = `{"promptId":"p"}`
			case "missing-prompt":
				f.admission = `{"lastEventId":42}`
			case "negative-cursor":
				f.admission = `{"promptId":"p","lastEventId":-1}`
			case "not-202":
				f.admissionStatus = 200
			}
			result, err := q.Prompt(context.Background(), "ask-stable", "question")
			if err == nil || f.posts.Load() != 1 || f.streams.Load() != 0 || result.Uncertain != (scenario != "not-202") {
				t.Fatalf("result=%+v err=%v posts=%d", result, err, f.posts.Load())
			}
		})
	}
}

func TestQwenInboundResumeObservesWithoutPosting(t *testing.T) {
	q, f := newInboundFixture(t)
	f.events = "data: {\"v\":1,\"id\":43,\"type\":\"turn_complete\",\"data\":{\"promptId\":\"unrelated\"}}\n\n"
	result, err := q.Prompt(context.Background(), "ask-stable", "question")
	if err == nil || !result.Accepted || !result.Uncertain || result.PromptID != "live########1" || result.LastEventID != 43 || f.turns.Load() != 0 {
		t.Fatalf("lost admission: %+v %v", result, err)
	}
	f.wantCursor = "43"
	f.events = "data: {\"v\":1,\"id\":44,\"type\":\"turn_complete\",\"data\":{\"promptId\":\"live########1\"}}\n\n"
	result, err = q.ResumePrompt(context.Background(), result)
	if err != nil || result.Uncertain || result.ResultText != "native answer" || f.posts.Load() != 1 || f.turns.Load() != 1 {
		t.Fatalf("resume=%+v err=%v", result, err)
	}
	f.trusted = false
	if _, err = q.ResumePrompt(context.Background(), result); err == nil || f.streams.Load() != 2 {
		t.Fatal("resume ignored revoked workspace trust")
	}
}

func TestQwenInboundResultBoundsAndCorrelation(t *testing.T) {
	for _, scenario := range []string{"missing", "truncated", "truncated-code", "oversize", "foreign-prompt", "escaped-boundary"} {
		t.Run(scenario, func(t *testing.T) {
			q, f := newInboundFixture(t)
			switch scenario {
			case "missing":
				delete(f.turn, "resultText")
			case "truncated":
				f.turn["resultTruncated"] = true
			case "truncated-code":
				f.turn["resultCode"] = "RESULT_TEXT_TRUNCATED"
			case "oversize":
				f.turn["resultText"] = strings.Repeat("a", 65537)
			case "foreign-prompt":
				f.turn["promptId"] = "foreign"
			case "escaped-boundary":
				f.turn["resultText"] = strings.Repeat("\n", 65536)
			}
			result, err := q.Prompt(context.Background(), "ask-stable", "question")
			if scenario == "escaped-boundary" {
				if err != nil || len(result.ResultText) != 65536 {
					t.Fatalf("boundary rejected: %v", err)
				}
			} else if err == nil || !result.Uncertain || result.ResultText != "" || result.LastEventID != 42 {
				t.Fatalf("unsafe result: %+v err=%v", result, err)
			}
			if f.turns.Load() != 1 || f.posts.Load() != 1 {
				t.Fatal("retried final result or prompt")
			}
		})
	}
}

func TestQwenInboundTerminalErrorAndResync(t *testing.T) {
	for _, event := range []string{"turn_error", "state_resync_required", "client_evicted", "stream_error", "session_died"} {
		t.Run(event, func(t *testing.T) {
			q, f := newInboundFixture(t)
			f.events = fmt.Sprintf("data: {\"v\":1,\"type\":%q,\"data\":{\"promptId\":\"live########1\",\"message\":\"failed\"}}\n\n", event)
			result, err := q.Prompt(context.Background(), "ask-stable", "question")
			if err == nil || !result.Accepted || result.Uncertain != (event != "turn_error") || f.turns.Load() != 0 {
				t.Fatalf("result=%+v err=%v", result, err)
			}
		})
	}
}
