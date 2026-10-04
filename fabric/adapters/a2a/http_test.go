package a2a

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/pagnet-code/pagnet/fabric"
)

func endpointServer(f *fixture, target string) {
	f.adapter.config.Interface.URL = target
	f.adapter.card.SupportedInterfaces[0].URL = target
}
func TestPrivateHeadersNeverFollowRedirect(t *testing.T) {
	f := setup(t, sdk.TaskStateCompleted, true)
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("private credential leaked")
		}
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer redirect.Close()
	endpointServer(f, redirect.URL)
	s, e := f.invoke("redirect", `{"operation":"send","mode":"unary","parts":[{"text":"private-content"}]}`)
	if e != nil {
		t.Fatal(e)
	}
	_, end := consume(t, s)
	if calls.Load() != 0 || end.Kind != fabric.FrameError || strings.Contains(end.Error.Message, "private-content") {
		t.Fatal("redirect replay/leak", calls.Load(), end)
	}
}
func TestOwnedDefaultTransportIgnoresEnvironmentProxy(t *testing.T) {
	var proxyCalls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxyCalls.Add(1); w.WriteHeader(502) }))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	f := setup(t, sdk.TaskStateCompleted, true)
	original := http.DefaultTransport
	stock := original.(*http.Transport).Clone()
	p, _ := url.Parse(proxy.URL)
	stock.Proxy = func(*http.Request) (*url.URL, error) { return p, nil }
	target := strings.TrimPrefix(f.server.URL, "http://")
	stock.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", target)
	}
	http.DefaultTransport = stock
	t.Cleanup(func() { http.DefaultTransport = original; stock.CloseIdleConnections() })
	base, owned, e := transportClient(nil, f.adapter.config.Limits.Lifetime)
	if e != nil {
		t.Fatal(e)
	}
	f.adapter.baseClient = base
	f.adapter.ownedTransport = owned
	endpointServer(f, "http://explicit-a2a.example")
	s, e := f.invoke("proxy", `{"operation":"send","mode":"unary","parts":[{"text":"work"}]}`)
	if e != nil {
		t.Fatal(e)
	}
	_, end := consume(t, s)
	if end.Kind != fabric.FrameComplete || proxyCalls.Load() != 0 {
		t.Fatal("environment proxy intercepted selected credential", proxyCalls.Load(), end)
	}
}
func TestOversizedWireRecordFailsBeforeSDKUnboundedDecode(t *testing.T) {
	f := setup(t, sdk.TaskStateCompleted, true)
	f.adapter.config.Limits.MaxEventBytes = 1024
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID json.RawMessage `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(request.ID)+`,"result":{"message":{"messageId":"x","role":"ROLE_AGENT","parts":[{"text":"`+strings.Repeat("x", 8192)+`"}]}}}`)
	}))
	defer server.Close()
	endpointServer(f, server.URL)
	s, e := f.invoke("oversized", `{"operation":"send","mode":"unary","parts":[{"text":"work"}]}`)
	if e != nil {
		t.Fatal(e)
	}
	raw, end := consume(t, s)
	if end.Kind != fabric.FrameError || len(raw) != 0 || len(end.Error.Message) > 128 {
		t.Fatal("oversized result silently delivered/completed", len(raw), end)
	}
}
func TestUnknownInitialEffectIsNeverResent(t *testing.T) {
	f := setup(t, sdk.TaskStateCompleted, true)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		connection, _, _ := w.(http.Hijacker).Hijack()
		connection.Close()
	}))
	defer server.Close()
	endpointServer(f, server.URL)
	input := `{"operation":"send","mode":"stream","parts":[{"text":"work"}]}`
	s, e := f.invoke("unknown", input)
	if e != nil {
		t.Fatal(e)
	}
	_, end := consume(t, s)
	if end.Kind != fabric.FrameError || end.Error.Effect != fabric.EffectUnknown {
		t.Fatal(end)
	}
	if _, e = f.invoke("unknown", input); e == nil || calls.Load() != 1 {
		t.Fatal("ambiguous send retried", e, calls.Load())
	}
}

func TestCompleteUnaryWireRejectsTrailingChunkBeforePublication(t *testing.T) {
	for _, suffix := range []string{"\n{}", "\nnot-json"} {
		t.Run(suffix, func(t *testing.T) {
			f := setup(t, sdk.TaskStateCompleted, true)
			prefixWritten := make(chan struct{})
			release := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request struct {
					ID json.RawMessage `json:"id"`
				}
				if json.NewDecoder(r.Body).Decode(&request) != nil {
					return
				}
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(request.ID)+`,"result":{"message":{"messageId":"reply","role":"ROLE_AGENT","parts":[{"text":"valid prefix"}]}}}`)
				w.(http.Flusher).Flush()
				close(prefixWritten)
				<-release
				io.WriteString(w, suffix)
			}))
			defer server.Close()
			endpointServer(f, server.URL)
			s, e := f.invoke("trailing", `{"operation":"send","mode":"unary","parts":[{"text":"work"}]}`)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			start, e := s.Next(context.Background())
			if e != nil || start.Kind != fabric.FrameStart {
				t.Fatal(start, e)
			}
			type reply struct {
				f fabric.InvocationFrame
				e error
			}
			done := make(chan reply, 1)
			go func() { frame, e := s.Next(context.Background()); done <- reply{frame, e} }()
			<-prefixWritten
			select {
			case got := <-done:
				close(release)
				t.Fatal("SDK published prefix before unary body ended", got)
			case <-time.After(50 * time.Millisecond):
			}
			close(release)
			got := <-done
			if got.e != nil || got.f.Kind != fabric.FrameError || len(got.f.Data) != 0 {
				t.Fatal("trailing unary document accepted", got)
			}
		})
	}
}
func TestUnaryDocumentAllowsOnlyTrailingWhitespace(t *testing.T) {
	f := setup(t, sdk.TaskStateCompleted, true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID json.RawMessage `json:"id"`
		}
		json.NewDecoder(r.Body).Decode(&request)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(request.ID)+`,"result":{"message":{"messageId":"reply","role":"ROLE_AGENT","parts":[{"text":"ok"}]}}}`+"\n \t")
	}))
	defer server.Close()
	endpointServer(f, server.URL)
	s, e := f.invoke("whitespace", `{"operation":"send","mode":"unary","parts":[{"text":"work"}]}`)
	if e != nil {
		t.Fatal(e)
	}
	_, end := consume(t, s)
	if end.Kind != fabric.FrameComplete {
		t.Fatal(end)
	}
}
