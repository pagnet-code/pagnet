package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// BrowserBridgePolicy is the immutable connection policy approved in Pagnet.
// OAuth tokens and account credentials never cross this device bridge.
type BrowserBridgePolicy struct {
	ConnectorID    string   `json:"connectorId"`
	NetworkID      string   `json:"networkId"`
	Grants         []string `json:"grants"`
	PolicyRevision int64    `json:"policyRevision"`
}

// ServeBrowserBridge opens an outbound connection to the configured Pagnet
// server using this SDK endpoint credential internally; callers never receive
// that durable secret. The handler receives only MCP JSON, with bounded work.
func (c *Client) ServeBrowserBridge(ctx context.Context, policy BrowserBridgePolicy, handle func(context.Context, json.RawMessage) (json.RawMessage, error)) error {
	if _, err := uuid.Parse(policy.ConnectorID); err != nil {
		return errors.New("browser bridge connector must be UUID")
	}
	u, err := url.Parse(c.cfg.serverBase())
	if err != nil {
		return err
	}
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	u.Path = "/wss/browser-connectors/" + policy.ConnectorID
	u.RawQuery = url.Values{"endpointId": {c.EndpointID()}}.Encode()
	u.Fragment = ""
	headers := http.Header{"Authorization": []string{"Bearer " + c.credential.Load().(string)}}
	conn, resp, err := websocket.DefaultDialer.DialContext(ctx, u.String(), headers)
	if err != nil {
		if resp != nil && (resp.StatusCode == 401 || resp.StatusCode == 403) {
			return fmt.Errorf("%w: browser connector unavailable", ErrCredentialDead)
		}
		return errors.New("browser bridge connection failed")
	}
	defer conn.Close()
	bridgeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var writeMu sync.Mutex
	write := func(v any) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		return conn.WriteJSON(v)
	}
	go func() { <-bridgeCtx.Done(); _ = conn.Close() }()
	conn.SetReadLimit((2 << 20) + (64 << 10))
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	var ready struct {
		Type string `json:"type"`
		BrowserBridgePolicy
	}
	if conn.ReadJSON(&ready) != nil {
		return errors.New("browser bridge handshake failed")
	}
	if ready.Type != "ready" || ready.ConnectorID != policy.ConnectorID || ready.NetworkID != policy.NetworkID || ready.PolicyRevision != policy.PolicyRevision || !sameBrowserGrants(ready.Grants, policy.Grants) {
		return errors.New("browser bridge policy mismatch; reconnect requires explicit setup approval")
	}
	jobs := make(chan struct {
		ID   string
		Body json.RawMessage
	}, 8)
	go func() {
		for {
			select {
			case <-bridgeCtx.Done():
				return
			case job := <-jobs:
				workCtx, stop := context.WithTimeout(bridgeCtx, 24*time.Second)
				body, err := handle(workCtx, job.Body)
				stop()
				if err != nil {
					cancel()
					return
				}
				if len(body) == 0 {
					body = json.RawMessage("null")
				}
				if len(body) > 2<<20 || !json.Valid(body) {
					cancel()
					return
				}
				if write(map[string]any{"type": "response", "id": job.ID, "body": body}) != nil {
					cancel()
					return
				}
			}
		}
	}()
	for {
		var frame struct {
			Type string          `json:"type"`
			ID   string          `json:"id"`
			Body json.RawMessage `json:"body"`
		}
		if conn.ReadJSON(&frame) != nil {
			return errors.New("browser bridge disconnected")
		}
		_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
		switch frame.Type {
		case "ping":
			if write(map[string]any{"type": "pong"}) != nil {
				return errors.New("browser bridge heartbeat failed")
			}
		case "request":
			if len(frame.Body) == 0 || len(frame.Body) > 2<<20 || !json.Valid(frame.Body) {
				return errors.New("invalid browser request")
			}
			select {
			case jobs <- struct {
				ID   string
				Body json.RawMessage
			}{frame.ID, frame.Body}:
			default:
				return errors.New("browser bridge request limit exceeded")
			}
		default:
			return errors.New("unsupported browser bridge frame")
		}
	}
}
func sameBrowserGrants(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[string]bool{}
	for _, v := range a {
		if set[v] {
			return false
		}
		set[v] = true
	}
	for _, v := range b {
		if !set[v] {
			return false
		}
		delete(set, v)
	}
	return true
}
