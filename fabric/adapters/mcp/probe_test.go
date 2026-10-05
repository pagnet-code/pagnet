package mcp

import (
	"context"
	"encoding/json"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestOfficialMetadataProbeNegotiatesSelectedVersionWithoutToolEffects(t *testing.T) {
	for _, v := range []struct {
		version   string
		stateless bool
	}{{"2025-11-25", false}, {"2026-07-28", true}} {
		t.Run(v.version, func(t *testing.T) {
			var calls, deletes atomic.Int32
			server := sdk.NewServer(&sdk.Implementation{Name: "actual-probe", Version: "1"}, &sdk.ServerOptions{SupportedProtocolVersions: []string{v.version}})
			server.AddTool(&sdk.Tool{Name: "never-call", InputSchema: json.RawMessage(`{"type":"object"}`)}, func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
				calls.Add(1)
				return &sdk.CallToolResult{}, nil
			})
			handler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, &sdk.StreamableHTTPOptions{Stateless: v.stateless})
			remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer explicit-private-probe" {
					t.Error("selected credentials absent")
				}
				if r.Method == http.MethodDelete {
					deletes.Add(1)
				}
				handler.ServeHTTP(w, r)
			}))
			defer remote.Close()
			selected, e := NegotiateRemote(t.Context(), RemoteFactory{Endpoint: remote.URL, AllowHTTP: true}, Credentials{Headers: map[string]string{"Authorization": "Bearer explicit-private-probe"}}, DefaultLimits)
			if e != nil || selected != v.version || calls.Load() != 0 {
				t.Fatal("not genuine metadata-only negotiation", selected, e, calls.Load())
			}
			if !v.stateless && deletes.Load() != 1 {
				t.Fatal("owned probe session not terminated")
			}
		})
	}
}
