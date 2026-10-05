package agentbridge

import (
	"context"
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/fabricclient"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
)

// HostedFabricSideport is received only on the original worker's authenticated
// private bridge. It has no nonce, principal or signing key. The existing bridge
// activation supplies its own nonce when opening a SECOND socket from this
// original MCP subprocess; the node then verifies its actual kernel ancestry.
// It never modifies an original runtime's immutable launch profile or history.
type HostedFabricSideport struct {
	Socket     string             `json:"socket"`
	Endpoint   fabric.EndpointRef `json:"endpoint"`
	Generation string             `json:"generation"`
}

func (p HostedFabricSideport) Validate() error {
	if fabrichost.ValidateSocketPath(p.Socket) != nil || p.Endpoint.IsOffer() || p.Endpoint.String() == "" || len(p.Generation) == 0 || len(p.Generation) > 256 {
		return fabric.NewError(fabric.CodeUnauthenticated, "Original hosted Fabric sideport is invalid")
	}
	return nil
}

// DialHostedFabric is executed inside the original runtime's MCP subprocess,
// preserving actual peer/process identity. Authentication is attempted once;
// failure never reconnects as owner or uses cloud credentials.
func DialHostedFabric(ctx context.Context, p HostedFabricSideport, instanceID, nonce string) (*fabricclient.Client, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	auth := fabrichost.Authentication{Type: "fabric.auth", Mode: "hosted", Endpoint: p.Endpoint, WorkerID: instanceID, Generation: p.Generation, Nonce: nonce}
	if err := auth.Validate(); err != nil {
		return nil, err
	}
	return fabricclient.Dial(ctx, p.Socket, auth)
}

// RegisterHostedFabricTools retains the original bridge's tools while exposing
// only the node's three canonical tools through its official SDK connection.
// Schema discovery is read-only. No registration invokes an endpoint or makes
// an unsupported active runtime refresh claim. The caller owns client lifetime.
func RegisterHostedFabricTools(ctx context.Context, s *server.MCPServer, client *fabricclient.Client) error {
	if s == nil || client == nil {
		return fabric.NewError(fabric.CodeInvalidInput, "Original bridge and authenticated node are required")
	}
	tools, err := client.CanonicalTools(ctx)
	if err != nil {
		return err
	}
	for _, actual := range tools {
		raw, err := json.Marshal(actual)
		if err != nil {
			return err
		}
		var tool mcp.Tool
		if err = json.Unmarshal(raw, &tool); err != nil {
			return err
		}
		// The legacy bridge's typed schema represents only a JSON Schema subset
		// and drops oneOf and other composition keywords. Retain the actual raw
		// canonical schemas so runtime validation matches the node exactly.
		inputSchema, err := json.Marshal(actual.InputSchema)
		if err != nil {
			return err
		}
		tool.InputSchema = mcp.ToolInputSchema{}
		tool.RawInputSchema = inputSchema
		if actual.OutputSchema != nil {
			outputSchema, err := json.Marshal(actual.OutputSchema)
			if err != nil {
				return err
			}
			tool.OutputSchema = mcp.ToolOutputSchema{}
			tool.RawOutputSchema = outputSchema
		}
		op := fabric.Operation(actual.Name)
		s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			arguments, err := json.Marshal(request.GetRawArguments())
			if err != nil {
				return nil, err
			}
			result, err := client.Call(ctx, op, json.RawMessage(arguments))
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			raw, err := json.Marshal(result)
			if err != nil || len(raw) > fabric.DefaultWireLimits.MaxBytes {
				return nil, fabric.NewError(fabric.CodeProtocolError, "Canonical node result exceeds its bound")
			}
			var translated mcp.CallToolResult
			if err = json.Unmarshal(raw, &translated); err != nil {
				return nil, err
			}
			return &translated, nil
		})
	}
	return nil
}
