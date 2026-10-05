package fabricservices

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/adapters/mcp"
	"github.com/pagnet-code/pagnet/fabric/adapters/mcp/catalog"
)

type credentialsFixture struct {
	digest  [32]byte
	changed atomic.Bool
	calls   atomic.Int32
}

func (c *credentialsFixture) Resolve(context.Context, string) (Credentials, error) {
	c.calls.Add(1)
	d := c.digest
	if c.changed.Load() {
		d[0] ^= 1
	}
	return Credentials{d, mcp.Credentials{Headers: map[string]string{"Authorization": "Bearer private-token-never-stored"}}}, nil
}
func TestActualInstalledMCPSharedCatalogExactInvokeAndAccountChange(t *testing.T) {
	p, scope, caller, _ := serviceFixture(t)
	var effects atomic.Int32
	sdkServer := sdk.NewServer(&sdk.Implementation{Name: "actual-official-provider", Version: "1"}, &sdk.ServerOptions{SupportedProtocolVersions: []string{"2026-07-28"}})
	sdkServer.AddTool(&sdk.Tool{Name: "compute", Description: "Public operation description", InputSchema: json.RawMessage(`{"type":"object","properties":{"n":{"type":"number"}}}`)}, func(_ context.Context, r *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		effects.Add(1)
		if !bytes.Equal(r.Params.Arguments, []byte(`{"n":9007199254740993123456789}`)) {
			t.Error("input precision changed")
		}
		return &sdk.CallToolResult{StructuredContent: json.RawMessage(`{"n":9007199254740993123456789}`), Content: []sdk.Content{}}, nil
	})
	handler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return sdkServer }, &sdk.StreamableHTTPOptions{Stateless: true})
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer private-token-never-stored" {
			t.Error("private credential not applied")
		}
		handler.ServeHTTP(w, r)
	}))
	defer httpServer.Close()
	v := serviceProfile()
	v.MCP.URL = httpServer.URL
	v.MCP.AllowHTTP = true
	if _, e := p.Install(t.Context(), scope, v); e != nil {
		t.Fatal(e)
	}
	credentials := &credentialsFixture{digest: v.BindingDigest}
	connections, e := NewConnections(p, credentials, invocationFixture(t, p), 2)
	if e != nil {
		t.Fatal(e)
	}
	defer connections.Close()
	if _, _, e = connections.ResolveMCP(t.Context(), scope); e == nil || credentials.calls.Load() != 0 {
		t.Fatal("Resolve implicitly connected provider", e)
	}
	if e = connections.ConnectMCP(t.Context(), scope, true); e != nil {
		t.Fatal(e)
	}
	if effects.Load() != 0 {
		t.Fatal("catalog sync invoked tool")
	}
	key := p.protector.Reference()
	cat, e := catalog.Open(t.Context(), catalog.Config{BindingDigest: v.BindingDigest, Store: p.store, Owner: caller, Scope: scope, MaxTools: v.MCP.Limits.MaxTools, Protector: p.protector, KeyID: key.ID, KeyVersion: key.Version})
	if e != nil {
		t.Fatal(e)
	}
	// The actual retained catalog has a schema-free summary and canonical offer.
	summary, e := cat.Current(t.Context(), scope.BindingID)
	if e != nil || len(summary) != 1 {
		t.Fatal(summary, e)
	}
	entry := connections.entries[connectionKey(scope)]
	page, e := p.store.ReadBindingProjection(t.Context(), caller, scope, "", 2)
	if e != nil || len(page.Rows) != 1 {
		t.Fatal(e)
	}
	offer, e := cat.Resolve(t.Context(), scope.BindingID, page.Rows[0].Ref, "")
	if e != nil {
		t.Fatal(e)
	}
	adapter, fingerprint, e := connections.ResolveMCP(t.Context(), scope)
	if e != nil || fingerprint != entry.fingerprint {
		t.Fatal(e)
	}
	d, e := p.store.GetEndpoint(t.Context(), scope.Endpoint, scope.ExpectedEndpointRevision)
	if e != nil {
		t.Fatal(e)
	}
	request := fabric.InvokeRequest{InvocationID: "original-invocation", Target: offer.Offer.Ref, ExpectedRevision: offer.Offer.Revision, Input: json.RawMessage(`{"n":9007199254740993123456789}`)}
	invoke := func(ctx context.Context, caller fabric.ExecutionContext, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
		return adapter.Invoke(ctx, caller, d, r)
	}
	stream, e := executeServiceFixture(t.Context(), p, request, invoke)
	if e != nil {
		t.Fatal(e)
	}
	var raw bytes.Buffer
	terminal := fabric.FrameKind("")
	for i := 0; i < 10; i++ {
		f, e := stream.Next(t.Context())
		if e != nil {
			t.Fatal(e)
		}
		raw.Write(f.Data)
		if f.Kind == fabric.FrameComplete || f.Kind == fabric.FrameError {
			terminal = f.Kind
			break
		}
	}
	stream.Close()
	if terminal != fabric.FrameComplete || !bytes.Contains(raw.Bytes(), []byte("9007199254740993123456789")) || effects.Load() != 1 {
		t.Fatal("exact actual result unavailable", terminal, effects.Load())
	}
	replay, e := executeServiceFixture(t.Context(), p, request, invoke)
	if e != nil {
		t.Fatal("exact original replay denied", e)
	}
	var replayRaw bytes.Buffer
	for {
		f, e := replay.Next(t.Context())
		if e != nil {
			t.Fatal(e)
		}
		replayRaw.Write(f.Data)
		if f.Kind == fabric.FrameComplete || f.Kind == fabric.FrameError {
			break
		}
	}
	replay.Close()
	if !bytes.Equal(raw.Bytes(), replayRaw.Bytes()) || effects.Load() != 1 {
		t.Fatal("retained original replay executed provider again")
	}
	credentials.changed.Store(true)
	request.InvocationID = "new-invocation"
	if s, e := executeServiceFixture(t.Context(), p, request, invoke); e == nil {
		if s != nil {
			s.Close()
		}
		t.Fatal("changed account reused prior SDK session")
	}
	if effects.Load() != 1 {
		t.Fatal("account-denied call had side effect")
	}
	if e = connections.Close(); e != nil {
		t.Fatal(e)
	}
	if _, _, e = connections.ResolveMCP(t.Context(), scope); e == nil {
		t.Fatal("closed binding usable")
	}
}
func TestConnectionsCloseCancelsOwnPendingSDKSetup(t *testing.T) {
	p, scope, _, _ := serviceFixture(t)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer func() { close(release); server.Close() }()
	v := serviceProfile()
	v.MCP.URL = server.URL
	v.MCP.AllowHTTP = true
	p.Install(t.Context(), scope, v)
	c, _ := NewConnections(p, &credentialsFixture{digest: v.BindingDigest}, invocationFixture(t, p), 1)
	done := make(chan error, 1)
	go func() { done <- c.ConnectMCP(t.Context(), scope, true) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("own SDK setup not started")
	}
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	select {
	case e := <-closed:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close failed to cancel and join own setup")
	}
	if e := <-done; e == nil {
		t.Fatal("canceled setup published connection")
	}
	if _, _, e := c.ResolveMCP(t.Context(), scope); e == nil {
		t.Fatal("closed connection resurrected")
	}
}
