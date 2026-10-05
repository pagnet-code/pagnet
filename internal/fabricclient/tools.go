package fabricclient

import (
	"context"
	"encoding/json"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
)

// CanonicalTools obtains the schemas from the actual authenticated node. A
// bridge never invents an independently maintained version of these schemas or
// pulls an arbitrary integration's catalog into the runtime's tools/list.
func (c *Client) CanonicalTools(ctx context.Context) ([]*sdk.Tool, error) {
	if c == nil || c.session == nil || ctx == nil {
		return nil, fabric.NewError(fabric.CodeUnauthenticated, "Authenticated node session is unavailable")
	}
	page, err := c.session.ListTools(ctx, &sdk.ListToolsParams{})
	if err != nil {
		return nil, err
	}
	if page == nil || page.NextCursor != "" || len(page.Tools) != 3 {
		return nil, fabric.NewError(fabric.CodeProtocolError, "Node must publish exactly the three canonical operations")
	}
	seen := map[string]bool{}
	for _, tool := range page.Tools {
		if tool == nil || (tool.Name != "discover" && tool.Name != "describe" && tool.Name != "invoke") || seen[tool.Name] {
			return nil, fabric.NewError(fabric.CodeProtocolError, "Invalid canonical node operation surface")
		}
		seen[tool.Name] = true
		raw, err := json.Marshal(tool)
		if err != nil || len(raw) > 32<<10 {
			return nil, fabric.NewError(fabric.CodeProtocolError, "Canonical tool schema exceeds its bound")
		}
	}
	return page.Tools, nil
}
