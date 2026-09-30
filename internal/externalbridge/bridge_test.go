package externalbridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/pagnet-code/pagnet/sdk"
)

const testNetwork = "01900000-0000-7000-8000-000000000001"
const testTarget = "01900000-0000-7000-8000-000000000002"
const testInvocation = "01900000-0000-7000-8000-000000000003"

type fakeClient struct {
	calls   []sdk.Invocation
	queried string
	read    *sdk.Invocation
}

func (f *fakeClient) WhoAmI(context.Context) (*sdk.Identity, error) {
	return &sdk.Identity{PrincipalID: testTarget}, nil
}
func (f *fakeClient) Search(_ context.Context, n string, q sdk.Query) ([]sdk.SearchResult, string, error) {
	f.queried = n
	return nil, "", nil
}
func (f *fakeClient) Invoke(_ context.Context, in sdk.Invocation) (*sdk.Invocation, error) {
	f.calls = append(f.calls, in)
	return &sdk.Invocation{ID: in.ID, State: "pending"}, sdk.ErrInvocationTimeout
}
func (f *fakeClient) GetInvocation(context.Context, string, string) (*sdk.Invocation, error) {
	return f.read, nil
}
func request(args map[string]any) mcp.CallToolRequest {
	var r mcp.CallToolRequest
	r.Params.Arguments = args
	return r
}
func TestDiscoveryOnlyAndFixedScope(t *testing.T) {
	f := &fakeClient{}
	b, err := New(f, Config{Network: testNetwork})
	if err != nil {
		t.Fatal(err)
	}
	tools := b.Server().ListTools()
	if len(tools) != 2 || tools["pagnet_invoke"] != nil || tools["pagnet_invocation_get"] != nil {
		t.Fatalf("discovery tools: %v", tools)
	}
	_, err = tools["pagnet_search"].Handler(context.Background(), request(map[string]any{"networkId": "foreign"}))
	if err != nil || f.queried != testNetwork {
		t.Fatalf("scope=%q err=%v", f.queried, err)
	}
}
func TestInvokeExactGrantsAndDurableRetry(t *testing.T) {
	f := &fakeClient{}
	b, err := New(f, Config{Network: testNetwork, Grants: []string{testTarget + "/hello.say"}})
	if err != nil {
		t.Fatal(err)
	}
	tools := b.Server().ListTools()
	args := map[string]any{"targetPrincipalId": testTarget, "capabilityId": "hello.say", "invocationId": testInvocation, "input": map[string]any{"text": "world"}}
	denied := map[string]any{"targetPrincipalId": testTarget, "capabilityId": "danger", "invocationId": testInvocation, "input": map[string]any{}}
	r, _ := tools["pagnet_invoke"].Handler(context.Background(), request(denied))
	if !r.IsError || len(f.calls) != 0 {
		t.Fatal("unauthorized invocation reached client")
	}
	for i := 0; i < 2; i++ {
		r, err := tools["pagnet_invoke"].Handler(context.Background(), request(args))
		if err != nil || r.IsError {
			t.Fatalf("timeout should include durable handle: %v %#v", err, r)
		}
		var data map[string]any
		if err := json.Unmarshal([]byte(r.Content[0].(mcp.TextContent).Text), &data); err != nil {
			t.Fatal(err)
		}
		if data["invocationId"] != testInvocation {
			t.Fatal(data)
		}
	}
	if len(f.calls) != 2 || f.calls[0].IdempotencyKey != f.calls[1].IdempotencyKey || f.calls[0].ID != f.calls[1].ID || f.calls[0].NetworkID != testNetwork {
		t.Fatal("retry changed durable identity/scope")
	}
	f.read = &sdk.Invocation{ID: testInvocation, TargetPrincipalID: testTarget, CapabilityID: "danger"}
	r, _ = tools["pagnet_invocation_get"].Handler(context.Background(), request(map[string]any{"invocationId": testInvocation}))
	if !r.IsError {
		t.Fatal("out-of-grant result exposed")
	}
}
func TestInvalidPolicy(t *testing.T) {
	for _, cfg := range []Config{{Network: "../foreign"}, {Network: testNetwork, Grants: []string{"*/hello.say"}}, {Network: testNetwork, Grants: []string{testTarget + "/*"}}} {
		if _, err := New(nil, cfg); err == nil {
			t.Fatal("accepted invalid policy", cfg)
		}
	}
}
func TestHTTPAuthenticationAndRebinding(t *testing.T) {
	token := strings.Repeat("a", 32)
	b, _ := New(&fakeClient{}, Config{Network: testNetwork})
	handler := HTTPHandler(b.Server(), token)
	for _, tc := range []struct {
		host, origin, auth string
		want               int
	}{{"127.0.0.1:8999", "", "", 401}, {"evil.example", "", "Bearer " + token, 403}, {"127.0.0.1:8999", "https://evil.example", "Bearer " + token, 403}, {"127.0.0.1:8999", "", "Bearer wrong", 401}} {
		r := httptest.NewRequest(http.MethodPost, "http://"+tc.host+"/mcp", strings.NewReader(`{}`))
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("Authorization", tc.auth)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("status=%d want=%d", w.Code, tc.want)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8999/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("authenticated MCP handshake: %d %s", w.Code, w.Body.String())
	}
}
func TestLoopbackOnly(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8999", "localhost:8999", "192.168.1.2:8999", ":8999"} {
		if ValidateListen(addr, strings.Repeat("x", 32)) == nil {
			t.Fatal("accepted", addr)
		}
	}
	if ValidateListen("[::1]:8999", strings.Repeat("x", 32)) != nil {
		t.Fatal("IPv6 loopback rejected")
	}
	if ValidateListen("127.0.0.1:8999", "short") == nil {
		t.Fatal("short token accepted")
	}
}
