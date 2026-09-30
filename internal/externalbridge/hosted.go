package externalbridge

import (
	"context"
	"encoding/json"
	"errors"
)

// HandleHosted validates the remote gateway's request again on the device.
// Only this bridge's fixed public MCP surface is reachable; permissions remain
// enforced by the same local grant map as stdio and the advanced HTTP bridge.
func (b *Bridge) HandleHosted(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	var rpc struct {
		JSONRPC string `json:"jsonrpc"`
		Method  string `json:"method"`
		Params  struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if len(body) > 2<<20 || json.Unmarshal(body, &rpc) != nil || rpc.JSONRPC != "2.0" {
		return nil, errors.New("invalid hosted MCP request")
	}
	allowed := false
	switch rpc.Method {
	case "initialize", "ping", "tools/list", "notifications/initialized":
		allowed = true
	case "tools/call":
		switch rpc.Params.Name {
		case "pagnet_identity", "pagnet_search":
			allowed = true
		case "pagnet_invoke", "pagnet_invocation_get":
			allowed = len(b.grants) > 0
		}
	}
	if !allowed {
		return nil, errors.New("hosted MCP method/tool is outside approved bridge policy")
	}
	return json.Marshal(b.Server().HandleMessage(ctx, body))
}
