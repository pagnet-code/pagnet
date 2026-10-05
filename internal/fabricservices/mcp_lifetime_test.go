package fabricservices

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestStatefulSDKCloseCancelsOperationAndDeletesOnlyOwnedSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	started, joined := make(chan struct{}), make(chan struct{})
	lifeFixtureDone := ctx.Done()
	server := sdk.NewServer(&sdk.Implementation{Name: "actual-stateful-close", Version: "1"}, &sdk.ServerOptions{SupportedProtocolVersions: []string{"2025-11-25"}})
	server.AddTool(&sdk.Tool{Name: "blocked", InputSchema: json.RawMessage(`{"type":"object"}`)}, func(ctx context.Context, _ *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		close(started)
		select {
		case <-ctx.Done():
		case <-lifeFixtureDone:
		}
		close(joined)
		return nil, ctx.Err()
	})
	var deletes atomic.Int32
	handler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, &sdk.StreamableHTTPOptions{Stateless: false})
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			if r.Header.Get("Mcp-Session-Id") == "" {
				t.Error("missing exact SDK session")
			}
			deletes.Add(1)
		}
		handler.ServeHTTP(w, r)
	}))
	defer remote.Close()
	life, stop := context.WithCancel(ctx)
	defer stop()
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil
	defer base.CloseIdleConnections()
	owned := &lifetimeTransport{ctx: life, base: base, endpoint: remote.URL}
	client := sdk.NewClient(&sdk.Implementation{Name: "owned", Version: "1"}, nil)
	session, e := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: remote.URL, HTTPClient: &http.Client{Transport: owned, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, MaxRetries: -1}, &sdk.ClientSessionOptions{ProtocolVersion: "2025-11-25"})
	if e != nil {
		t.Fatal(e)
	}
	callCtx, cancelCall := context.WithCancel(ctx)
	defer cancelCall()
	done := make(chan error, 1)
	go func() {
		_, e := session.CallTool(callCtx, &sdk.CallToolParams{Name: "blocked", Arguments: map[string]any{}})
		done <- e
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("SDK tool never entered")
	}
	cancelCall()
	select {
	case <-joined:
	case <-ctx.Done():
		t.Fatal("SDK cancellation did not join actual tool handler")
	}
	stop()
	if e = session.Close(); e != nil {
		t.Fatal("owned cleanup falsely incomplete", e)
	}
	select {
	case e = <-done:
		if e == nil {
			t.Fatal("cancelled operation completed")
		}
	case <-ctx.Done():
		t.Fatal("client operation not joined")
	}
	select {
	case <-joined:
	case <-ctx.Done():
		t.Fatal("actual cancelled server tool not joined")
	}
	if deletes.Load() != 1 {
		t.Fatal("missing/duplicate session cleanup", deletes.Load())
	}
	for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodDelete} {
		r, _ := http.NewRequestWithContext(ctx, method, remote.URL, nil)
		// DELETE without genuine SDK session is not a cleanup escape.
		if _, e = owned.RoundTrip(r); !errors.Is(e, context.Canceled) {
			t.Fatal("ordinary cancelled request escaped", method, e)
		}
	}
}
