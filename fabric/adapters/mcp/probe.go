package mcp

import (
	"context"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
)

// NegotiateRemote performs only the official SDK connection lifecycle against
// an operator-selected address/account. It creates no registry/catalog/actor
// authority and cannot invoke a tool. Limits and transport safety are identical
// to the registered remote adapter. The returned version is actual SDK evidence.
func NegotiateRemote(ctx context.Context, factory RemoteFactory, credentials Credentials, limits Limits) (string, error) {
	if ctx == nil || limits.MaxTools < 1 || limits.MaxTools > 65536 || limits.MaxPages < 1 || limits.MaxPages > 1024 || limits.MaxPending < 1 || limits.MaxPending > 128 || limits.MaxResultBytes < 1 || limits.MaxResultBytes > 16<<20 || limits.MaxCatalogBytes < 1 || limits.MaxCatalogBytes > 128<<20 {
		return "", fabric.NewError(fabric.CodeInvalidInput, "Explicit bounded MCP setup required")
	}
	tap := newResultTap(limits)
	defer tap.close()
	transport, e := factory.Transport(ctx, credentials, tap)
	if e != nil {
		return "", fabric.NewError(fabric.CodeInvalidInput, "Invalid selected MCP setup transport")
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "pagnet-service-setup", Version: "1"}, &sdk.ClientOptions{MultiRoundTrip: &sdk.MultiRoundTripOptions{Disabled: true}})
	session, e := client.Connect(ctx, transport, nil)
	if e != nil {
		return "", fabric.NewError(fabric.CodeTargetUnavailable, "Selected MCP endpoint could not negotiate its protocol")
	}
	version := session.InitializeResult().ProtocolVersion
	if e = session.Close(); e != nil {
		return "", fabric.NewError(fabric.CodeTargetUnavailable, "Selected MCP setup session cleanup failed")
	}
	if version == "" {
		return "", fabric.NewError(fabric.CodeProtocolError, "MCP protocol version absent")
	}
	return version, nil
}
