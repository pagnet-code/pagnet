package semantic

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestOllamaSelectedProtocolDigestAndPrivateCredentials(t *testing.T) {
	digest := strings.Repeat("a", 64)
	embedCalls, tags := 0, 0
	cpu := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer private-fixture-token" {
			t.Error("credential not confined to configured adapter")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/tags":
			tags++
			_ = json.NewEncoder(w).Encode(map[string]any{"models": []any{map[string]any{"name": "fixture:1", "model": "fixture:1", "digest": digest}}})
		case "/api/embed":
			embedCalls++
			var body struct {
				Model     string
				Input     []string
				Truncate  bool
				KeepAlive string `json:"keep_alive"`
				Options   map[string]int
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Model != "fixture:1" || body.Truncate || body.KeepAlive != "0" || body.Options["num_gpu"] != 0 {
				t.Error("incorrect explicit model request")
			}
			vectors := make([][]float32, len(body.Input))
			for i := range vectors {
				vectors[i] = []float32{1, 2}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"model": "fixture:1", "embeddings": vectors})
		default:
			t.Error("adapter attempted unsupported route/model download")
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	o, e := NewOllama(OllamaConfig{BaseURL: server.URL, Model: "fixture:1", Version: "v1", Digest: digest, Dimensions: 2, Token: "private-fixture-token", NumGPU: &cpu})
	if e != nil {
		t.Fatal(e)
	}
	vs, e := o.Embed(context.Background(), []string{"private compact input"})
	if e != nil || len(vs) != 1 || embedCalls != 1 || tags != 2 {
		t.Fatal(e)
	}
	digest = strings.Repeat("b", 64)
	if _, e = o.Embed(context.Background(), []string{"another input"}); e == nil || embedCalls != 1 {
		t.Fatal("changed digest reached model", e)
	}
}
func TestAdapterRedirectCancellationAndErrorDoNotLeak(t *testing.T) {
	hits := 0
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer redirect.Close()
	o, e := NewOllama(OllamaConfig{BaseURL: redirect.URL, Model: "fixture", Version: "v1", Dimensions: 2, Token: "fixture-secret"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = o.Embed(context.Background(), []string{"fixture-private-input"}); e == nil || hits != 0 || strings.Contains(e.Error(), "fixture-secret") {
		t.Fatal("redirect disclosed", e, hits)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = o.Embed(ctx, []string{"input"}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	failure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte("fixture-secret fixture-private-input"))
	}))
	defer failure.Close()
	o, e = NewOllama(OllamaConfig{BaseURL: failure.URL, Model: "fixture", Version: "v1", Dimensions: 2})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = o.Embed(context.Background(), []string{"input"}); e == nil || strings.Contains(e.Error(), "fixture-secret") || strings.Contains(e.Error(), "fixture-private-input") {
		t.Fatal(e)
	}
	if _, e = NewOllama(OllamaConfig{BaseURL: "http://remote.example", Model: "fixture", Version: "v1", Dimensions: 2}); e == nil {
		t.Fatal("implicit plaintext remote endpoint accepted")
	}
	if _, e = NewQdrant(QdrantConfig{BaseURL: failure.URL, Collection: "../other", Dimensions: 2}); e == nil {
		t.Fatal("path-injection collection accepted")
	}
}
func TestQdrantIndexedQueryAndDeadlineBoundary(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/collections/fixture/points/query" || r.URL.Query().Get("timeout") != "1" {
			t.Error("bounded exact query route", r.URL)
		}
		if r.Header.Get("api-key") != "private-fixture-token" {
			t.Error("missing private API credential")
		}
		var raw map[string]any
		if json.NewDecoder(r.Body).Decode(&raw) != nil {
			t.Error("invalid request")
			return
		}
		params := raw["params"].(map[string]any)
		if params["exact"] != false || params["indexed_only"] != true || params["hnsw_ef"] != float64(128) || raw["limit"] != float64(10) || raw["with_vector"] != false {
			t.Error("unindexed/unbounded vector query")
		}
		_, _ = w.Write([]byte(`{"result":{"points":[]},"usage":{"hardware":{"cpu":42,"vector_io_read":128}}}`))
	}))
	defer server.Close()
	q, e := NewQdrant(QdrantConfig{BaseURL: server.URL, Collection: "fixture", Dimensions: 2, Token: "private-fixture-token"})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	r, e := q.Query(ctx, VectorQuery{Vector: []float32{1, 2}, Generation: 1, Model: "model", Limit: 10, Ef: 128})
	if e != nil || !r.Usage.Reported || r.Usage.CPU != 42 {
		t.Fatal(r, e)
	}
}

func TestExplicitTransportRejectsNegativeTimeout(t *testing.T) {
	if _, err := newTransport("http://127.0.0.1:1", "", &http.Client{Timeout: -time.Second}, false); err == nil {
		t.Fatal("unbounded negative timeout accepted")
	}
}

func TestDefaultTransportDoesNotUseEnvironmentProxy(t *testing.T) {
	proxyCalls := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxyCalls++; w.WriteHeader(502) }))
	defer proxy.Close()
	selected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{}`)) }))
	defer selected.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	previous := http.DefaultTransport
	stock := previous.(*http.Transport).Clone()
	proxyURL, _ := url.Parse(proxy.URL)
	stock.Proxy = func(*http.Request) (*url.URL, error) { return proxyURL, nil }
	target := strings.TrimPrefix(selected.URL, "http://")
	stock.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", target)
	}
	http.DefaultTransport = stock
	t.Cleanup(func() { http.DefaultTransport = previous; stock.CloseIdleConnections() })
	tr, err := newTransport("http://explicit-provider.example", "", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = tr.request(context.Background(), http.MethodGet, "/", nil, nil, ""); err != nil {
		t.Fatal(err)
	}
	if proxyCalls != 0 {
		t.Fatal("private adapter disclosure used environment proxy")
	}
	tr.client.CloseIdleConnections()
}
