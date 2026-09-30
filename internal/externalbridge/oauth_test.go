package externalbridge

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOAuthProtectedMCPDiscoveryScopesRevocationAndIsolation(t *testing.T) {
	var active atomic.Bool
	active.Store(true)
	var upstreamCalls atomic.Int32
	resource := "https://connector.example/mcp"
	var issuer string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		id, secret, ok := r.BasicAuth()
		if !ok || id != "introspection-client" || secret != "introspection-secret" {
			t.Error("missing introspection client authentication")
			w.WriteHeader(401)
			return
		}
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Error("nonstandard introspection request")
		}
		_ = r.ParseForm()
		token := r.Form.Get("token")
		claims := map[string]any{"active": active.Load(), "iss": issuer, "sub": "owner-subject", "aud": []string{resource}, "exp": time.Now().Add(time.Minute).Unix(), "scope": DiscoveryScope + " " + InvocationScope, "token_type": "Bearer"}
		switch token {
		case "discovery":
			claims["scope"] = DiscoveryScope
		case "other-subject":
			claims["sub"] = "other-user"
		case "other-audience":
			claims["aud"] = "https://different.example/mcp"
		case "other-issuer":
			claims["iss"] = "https://evil.example"
		case "expired":
			claims["exp"] = time.Now().Add(-time.Minute).Unix()
		case "refresh-token":
			claims["token_type"] = "Refresh"
		case "missing-expiry":
			delete(claims, "exp")
		case "missing-token-type":
			delete(claims, "token_type")
		case "not-yet-valid":
			claims["nbf"] = time.Now().Add(time.Minute).Unix()
		case "no-scope":
			claims["scope"] = "pagnet:discover-all"
		case "good":
		default:
			claims["active"] = false
		}
		_ = json.NewEncoder(w).Encode(claims)
	}))
	defer upstream.Close()
	issuer = upstream.URL
	cfg := OAuthConfig{ResourceURL: resource, Issuer: issuer, IntrospectionURL: issuer + "/introspect", ClientID: "introspection-client", ClientSecret: "introspection-secret", Subject: "owner-subject", AllowInvoke: true}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	bridge, _ := New(&fakeClient{}, Config{Network: testNetwork, Grants: []string{testTarget + "/hello.say"}})
	backend := httptest.NewServer(oauthHTTPHandler(bridge.Server(), cfg, upstream.Client()))
	defer backend.Close()
	call := func(path, token, body string) (int, string, http.Header) {
		t.Helper()
		method := "POST"
		if body == "" {
			method = "GET"
		}
		request, _ := http.NewRequest(method, backend.URL+path, strings.NewReader(body))
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json, text/event-stream")
		request.Header.Set("Mcp-Session-Id", "same-session-does-not-grant-authority")
		response, err := backend.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(data), response.Header
	}
	status, data, _ := call("/.well-known/oauth-protected-resource/mcp", "", "")
	if status != 200 || !strings.Contains(data, resource) || !strings.Contains(data, issuer) || upstreamCalls.Load() != 0 {
		t.Fatalf("metadata discovery: %d %s", status, data)
	}
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"browser-connector","version":"1"}}}`
	status, _, headers := call("/mcp", "", init)
	if status != 401 || !strings.Contains(headers.Get("WWW-Authenticate"), `resource_metadata="https://connector.example/.well-known/oauth-protected-resource/mcp"`) {
		t.Fatal("missing vendor OAuth discovery challenge", status, headers)
	}
	status, data, _ = call("/mcp", "good", init)
	if status != 200 || !strings.Contains(data, "pagnet-external") {
		t.Fatalf("OAuth MCP initialize: %d %s", status, data)
	}
	status, data, _ = call("/mcp", "discovery", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if status != 200 || !strings.Contains(data, "pagnet_search") {
		t.Fatalf("tools discovery: %d %s", status, data)
	}
	invoke := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"pagnet_invoke","arguments":{"targetPrincipalId":"` + testTarget + `","capabilityId":"hello.say","invocationId":"` + testInvocation + `","input":{}}}}`
	status, _, headers = call("/mcp", "discovery", invoke)
	if status != 403 || !strings.Contains(headers.Get("WWW-Authenticate"), InvocationScope) {
		t.Fatal("invocation scope bypass", status)
	}
	status, _, _ = call("/mcp", "discovery", `{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"future_mutating_tool","arguments":{}}}`)
	if status != 403 {
		t.Fatal("future tool bypassed scope default deny", status)
	}
	status, _, _ = call("/mcp", "good", `[{"jsonrpc":"2.0","id":31,"method":"tools/call","params":{"name":"pagnet_identity","arguments":{}}}]`)
	if status != 400 {
		t.Fatal("batch bypassed per-request scope guard", status)
	}
	status, data, _ = call("/mcp", "good", invoke)
	if status != 200 || !strings.Contains(data, testInvocation) {
		t.Fatalf("authorized invocation: %d %s", status, data)
	}
	identity := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"pagnet_identity","arguments":{}}}`
	for _, token := range []string{"other-subject", "other-audience", "other-issuer", "expired", "not-yet-valid", "refresh-token", "missing-expiry", "missing-token-type", "no-scope"} {
		status, _, _ = call("/mcp", token, identity)
		expected := 401
		if token == "no-scope" {
			expected = 403
		}
		if status != expected {
			t.Errorf("%s: status %d want %d", token, status, expected)
		}
	}
	active.Store(false)
	status, _, _ = call("/mcp", "good", identity)
	if status != 401 {
		t.Fatal("revoked token reused MCP session", status)
	}
}

func TestOAuthIntrospectionRedirectAndProviderFailureDoNotLeakSecrets(t *testing.T) {
	var redirectCalls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/destination" {
			redirectCalls.Add(1)
			w.WriteHeader(200)
			return
		}
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/destination", 302)
			return
		}
		w.WriteHeader(503)
		_, _ = w.Write([]byte("sensitive-provider-diagnostic"))
	}))
	defer upstream.Close()
	cfg := OAuthConfig{ResourceURL: "https://connector.example/mcp", Issuer: upstream.URL, IntrospectionURL: upstream.URL + "/redirect", ClientID: "client", ClientSecret: "very-secret", Subject: "owner"}
	bridge, _ := New(&fakeClient{}, Config{Network: testNetwork})
	for _, path := range []string{"/redirect", "/failure"} {
		cfg.IntrospectionURL = upstream.URL + path
		client := upstream.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		handler := oauthHTTPHandler(bridge.Server(), cfg, client)
		request := httptest.NewRequest("POST", "http://127.0.0.1/mcp", strings.NewReader(`{}`))
		request.Header.Set("Authorization", "Bearer secret-access-token")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, request)
		if w.Code != 503 || strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), "diagnostic") {
			t.Fatalf("provider error disclosure: %d %s", w.Code, w.Body.String())
		}
	}
	if redirectCalls.Load() != 0 {
		t.Fatal("introspection redirect followed")
	}
}

func TestOAuthConfigurationFailClosed(t *testing.T) {
	valid := OAuthConfig{ResourceURL: "https://connector.example/mcp", Issuer: "https://identity.example/realm", IntrospectionURL: "https://identity.example/realm/introspect", ClientID: "client", ClientSecret: "secret", Subject: "owner"}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*OAuthConfig){
		func(c *OAuthConfig) { c.ResourceURL = "http://connector.example/mcp" }, func(c *OAuthConfig) { c.ResourceURL = "https://connector.example/mcp?token=secret" }, func(c *OAuthConfig) { c.IntrospectionURL = "https://evil.example/introspect" }, func(c *OAuthConfig) { c.Subject = "" }, func(c *OAuthConfig) { c.ClientSecret = "" },
	} {
		c := valid
		mutate(&c)
		if c.Validate() == nil {
			t.Fatal("invalid OAuth config accepted")
		}
	}
}
