package mcp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
)

func TestOfficialRemoteSDKExactResultAndLostResponseAfterEffectNeverReplays(t *testing.T) {
	for _, drop := range []bool{false, true} {
		t.Run(map[bool]string{false: "original", true: "lost-response-after-effect"}[drop], func(t *testing.T) {
			var effects atomic.Int32
			server := sdk.NewServer(&sdk.Implementation{Name: "official-http-fixture", Version: "1"}, nil)
			server.AddTool(&sdk.Tool{Name: "compute", InputSchema: json.RawMessage(`{"type":"object","properties":{"n":{"const":9007199254740993123456789}}}`)}, func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
				effects.Add(1)
				return &sdk.CallToolResult{StructuredContent: json.RawMessage(`{"n":9007199254740993123456789}`), Content: []sdk.Content{}}, nil
			})
			handler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, &sdk.StreamableHTTPOptions{Stateless: true})
			httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
					if err != nil {
						t.Error("fixture request read failed")
						return
					}
					r.Body = io.NopCloser(bytes.NewReader(raw))
					var request struct {
						Method string `json:"method"`
					}
					_ = json.Unmarshal(raw, &request)
					if drop && request.Method == "tools/call" {
						recorder := httptest.NewRecorder()
						handler.ServeHTTP(recorder, r)
						connection, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error("fixture could not drop completed response")
							return
						}
						_ = connection.Close()
						return
					}
				}
				handler.ServeHTTP(w, r)
			}))
			defer httpServer.Close()
			key, _, _ := ed25519.GenerateKey(rand.Reader)
			endpoint, _ := fabric.NewEndpointRef(key)
			catalog := &fixtureCatalog{records: map[string]ToolBinding{}, endpoint: endpoint}
			a, err := New(t.Context(), Config{Audience: "fixture-node", BindingID: "registered-remote", Endpoint: endpoint, Credentials: &fixtureCredentials{}, Transport: RemoteFactory{Endpoint: httpServer.URL, AllowHTTP: true}, Catalog: catalog})
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			if err = a.Connect(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err = a.Sync(t.Context()); err != nil {
				t.Fatal(err)
			}
			raw, terminal := drainFixture(t, invokeFixture(t, a, catalog))
			if effects.Load() != 1 {
				t.Fatal("destructive HTTP call repeated", effects.Load())
			}
			if drop {
				if terminal.Kind != fabric.FrameError || terminal.Error.Effect != fabric.EffectUnknown || len(raw) != 0 {
					t.Fatal("lost response claimed completion/not-started")
				}
			} else if terminal.Kind != fabric.FrameComplete || !bytes.Contains(raw, []byte("9007199254740993123456789")) {
				t.Fatal("official HTTP result precision lost")
			}
		})
	}
}
func TestRemoteCredentialHeadersCannotCreateReplayOrProtocolDowngrade(t *testing.T) {
	factory := RemoteFactory{Endpoint: "https://configured.example/mcp"}
	for _, header := range []string{"Mcp-Protocol-Version", "Mcp-Session-Id", "Idempotency-Key", "X-Idempotency-Key", "Host"} {
		if _, err := factory.Transport(t.Context(), Credentials{Headers: map[string]string{header: "value"}}, newResultTap(DefaultLimits)); err == nil {
			t.Fatal("credential overrides transport authority", header)
		}
	}
}

func TestDefaultRemoteTransportDoesNotSelectEnvironmentProxy(t *testing.T) {
	var proxyCalls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { proxyCalls.Add(1) }))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	var receivedCredential atomic.Bool
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedCredential.Store(r.Header.Get("Authorization") == "Bearer private-fixture")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer provider.Close()
	factory := RemoteFactory{Endpoint: "http://selected-provider.invalid/mcp", AllowHTTP: true}
	transport, err := factory.Transport(t.Context(), Credentials{Headers: map[string]string{"Authorization": "Bearer private-fixture"}}, newResultTap(DefaultLimits))
	if err != nil {
		t.Fatal(err)
	}
	client := transport.(*sdk.StreamableClientTransport).HTTPClient
	base := client.Transport.(*httpResultTap).base.(*credentialTransport).base.(*http.Transport)
	if base.Proxy != nil || base.MaxConnsPerHost != DefaultLimits.MaxPending || base.MaxIdleConnsPerHost != DefaultLimits.MaxPending || base.MaxResponseHeaderBytes != 64<<10 || base.ResponseHeaderTimeout <= 0 {
		t.Fatal("default remote transport exposes proxy or unbounded pooling/headers")
	}
	// Route the explicitly selected host to this isolated provider; an environment
	// proxy would change addr and is rejected rather than receiving credentials.
	providerURL, _ := url.Parse(provider.URL)
	base.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != "selected-provider.invalid:80" {
			return nil, errors.New("unselected transport destination")
		}
		return (&net.Dialer{}).DialContext(ctx, network, providerURL.Host)
	}
	response, err := client.Get(factory.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	base.CloseIdleConnections()
	if proxyCalls.Load() != 0 || !receivedCredential.Load() {
		t.Fatal("credential reached proxy or missed selected provider")
	}
	explicit := &http.Transport{Proxy: http.ProxyURL(providerURL)}
	supplied, err := (RemoteFactory{Endpoint: "https://configured.example/mcp", Client: &http.Client{Transport: explicit}}).Transport(t.Context(), Credentials{}, newResultTap(DefaultLimits))
	if err != nil || supplied.(*sdk.StreamableClientTransport).HTTPClient.Transport.(*httpResultTap).base.(*credentialTransport).base != explicit {
		t.Fatal("explicit operator transport replaced")
	}
}
