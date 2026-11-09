package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/websocket"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBrowserBridgePinsPolicyKeepsEndpointSecretAndServicesHeartbeatDuringTool(t *testing.T) {
	policy := BrowserBridgePolicy{ConnectorID: "01900000-0000-7000-8000-000000000001", NetworkID: "01900000-0000-7000-8000-000000000002", Grants: []string{}, Events: []string{"task.*"}, PolicyRevision: 1}
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
		_ = conn.WriteJSON(map[string]any{"type": "ready", "connectorId": policy.ConnectorID, "networkId": policy.NetworkID, "grants": policy.Grants, "events": policy.Events, "policyRevision": int64(1)})
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
	var failure *BrowserBridgeError
	if !errors.As(err, &failure) || !failure.Healthy {
		t.Fatalf("heartbeat session did not report healthy disconnect: %v", err)
	}
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
func TestBrowserBridgeRejectsEventPolicyMismatchBeforeCallingHandler(t *testing.T) {
	policy := BrowserBridgePolicy{ConnectorID: "01900000-0000-7000-8000-000000000001", NetworkID: "01900000-0000-7000-8000-000000000002", Events: []string{"task.*"}, PolicyRevision: 1}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteJSON(map[string]any{"type": "ready", "connectorId": policy.ConnectorID, "networkId": policy.NetworkID, "events": []string{"task.created"}, "policyRevision": 1})
	}))
	defer ts.Close()
	c := &Client{cfg: Config{Server: ts.URL}}
	c.credential.Store("pgn_epd_v1_private-endpoint")
	if err := c.ServeBrowserBridge(context.Background(), policy, func(context.Context, json.RawMessage) (json.RawMessage, error) {
		t.Error("handler reached despite changed event policy")
		return nil, nil
	}); err == nil {
		t.Fatal("changed event policy accepted")
	}
}

func TestBrowserBridgeConnectionFailuresAreSafeAndClassified(t *testing.T) {
	policy := BrowserBridgePolicy{ConnectorID: "01900000-0000-7000-8000-000000000001"}
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusServiceUnavailable} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "private-server-body", status)
			}))
			defer ts.Close()
			c := &Client{cfg: Config{Server: ts.URL}}
			c.credential.Store("private-credential")
			err := c.ServeBrowserBridge(context.Background(), policy, nil)
			var failure *BrowserBridgeError
			if !errors.As(err, &failure) || failure.HTTPStatus != status || failure.Healthy {
				t.Fatalf("unexpected diagnostics: %v", err)
			}
			if errors.Is(err, ErrCredentialDead) != (status == 401 || status == 403) {
				t.Fatalf("incorrect credential failure classification: %v", err)
			}
			if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), ts.URL) {
				t.Fatalf("unsafe error: %v", err)
			}
		})
	}
	t.Run("transport", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		ts.Close()
		c := &Client{cfg: Config{Server: ts.URL}}
		c.credential.Store("private-credential")
		err := c.ServeBrowserBridge(context.Background(), policy, nil)
		var failure *BrowserBridgeError
		if !errors.As(err, &failure) || failure.HTTPStatus != 0 || errors.Is(err, ErrCredentialDead) {
			t.Fatalf("transport failure must be retryable: %v", err)
		}
		if strings.Contains(err.Error(), ts.URL) {
			t.Fatalf("unsafe transport error: %v", err)
		}
	})
}

func TestBrowserBridgeWaitsForEndpointBeforeDial(t *testing.T) {
	var dials atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dials.Add(1)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer ts.Close()
	c := &Client{cfg: Config{Server: ts.URL}, closeCh: make(chan struct{}), terminalCh: make(chan struct{})}
	c.credential.Store("private-credential")
	policy := BrowserBridgePolicy{ConnectorID: "01900000-0000-7000-8000-000000000001"}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := c.ServeBrowserBridge(ctx, policy, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("readiness wait ignored cancellation: %v", err)
	}
	if dials.Load() != 0 {
		t.Fatal("dialed while endpoint offline")
	}
	result := make(chan error, 1)
	go func() { result <- c.ServeBrowserBridge(context.Background(), policy, nil) }()
	c.connected.Store(true)
	select {
	case err := <-result:
		var failure *BrowserBridgeError
		if !errors.As(err, &failure) || failure.HTTPStatus != 503 || dials.Load() != 1 {
			t.Fatalf("did not dial after endpoint ready: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("bridge did not resume after endpoint ready")
	}
}

func TestBrowserBridgeShortSessionRetainsBackoff(t *testing.T) {
	policy := BrowserBridgePolicy{ConnectorID: "01900000-0000-7000-8000-000000000001"}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteJSON(map[string]any{"type": "ready", "connectorId": policy.ConnectorID})
	}))
	defer ts.Close()
	c := &Client{cfg: Config{Server: ts.URL}}
	c.credential.Store("private-credential")
	err := c.ServeBrowserBridge(context.Background(), policy, nil)
	var failure *BrowserBridgeError
	if !errors.As(err, &failure) || failure.Healthy {
		t.Fatalf("short session must retain backoff: %v", err)
	}
}
