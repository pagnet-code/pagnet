package sdk

import (
	"context"
	"encoding/json"
	"github.com/gorilla/websocket"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestBrowserBridgePinsPolicyKeepsEndpointSecretAndServicesHeartbeatDuringTool(t *testing.T) {
	policy := BrowserBridgePolicy{ConnectorID: "01900000-0000-7000-8000-000000000001", NetworkID: "01900000-0000-7000-8000-000000000002", Grants: []string{}, PolicyRevision: 1}
	var observed atomic.Bool
	heartbeat := make(chan struct{})
	response := make(chan struct{})
	serverDone := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(serverDone)
		if r.Header.Get("Authorization") != "Bearer pgn_epd_v1_private-endpoint" {
			t.Error("bridge didn't use endpointcredential internally")
		}
		if r.URL.Path != "/wss/browser-connectors/"+policy.ConnectorID {
			t.Error("wrong connector route")
		}
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_ = conn.WriteJSON(map[string]any{"type": "ready", "connectorId": policy.ConnectorID, "networkId": policy.NetworkID, "grants": policy.Grants, "policyRevision": int64(1)})
		_ = conn.WriteJSON(map[string]any{"type": "request", "id": "request-1", "body": json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)})
		_ = conn.WriteJSON(map[string]any{"type": "ping"})
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		for i := 0; i < 2; i++ {
			var frame struct {
				Type string          `json:"type"`
				ID   string          `json:"id"`
				Body json.RawMessage `json:"body"`
			}
			if err = conn.ReadJSON(&frame); err != nil {
				t.Error(err)
				return
			}
			if frame.Type == "pong" {
				close(heartbeat)
			} else if frame.Type == "response" && frame.ID == "request-1" {
				observed.Store(true)
				close(response)
			} else {
				t.Errorf("unexpected frame %s", frame.Type)
			}
		}
	}))
	defer ts.Close()
	c := &Client{cfg: Config{Server: ts.URL}}
	c.credential.Store("pgn_epd_v1_private-endpoint")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	err := c.ServeBrowserBridge(ctx, policy, func(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
		select {
		case <-heartbeat:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return json.RawMessage(`{"jsonrpc":"2.0","id":1,"result":{}}`), nil
	})
	<-serverDone
	if !observed.Load() {
		t.Fatalf("heartbeat couldn't progress during work: %v", err)
	}
}
func TestBrowserBridgeRejectsServerPolicyReplacementBeforeCallingHandler(t *testing.T) {
	policy := BrowserBridgePolicy{ConnectorID: "01900000-0000-7000-8000-000000000001", NetworkID: "01900000-0000-7000-8000-000000000002", PolicyRevision: 1}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteJSON(map[string]any{"type": "ready", "connectorId": policy.ConnectorID, "networkId": policy.NetworkID, "grants": []string{"unexpected/cap"}, "policyRevision": 1})
	}))
	defer ts.Close()
	c := &Client{cfg: Config{Server: ts.URL}}
	c.credential.Store("pgn_epd_v1_private-endpoint")
	if err := c.ServeBrowserBridge(context.Background(), policy, func(context.Context, json.RawMessage) (json.RawMessage, error) {
		t.Error("handler reached despitechanged policy")
		return nil, nil
	}); err == nil {
		t.Fatal("changed policy accepted")
	}
}
