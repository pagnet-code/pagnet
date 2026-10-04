package daemon

import (
	"context"
	"io"
	"net"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/mcpbridge"
	"github.com/pagnet-code/pagnet/internal/fabricmcp"
)

// ManagedFabricPeer contains only facts established by the existing nonce,
// live process and kernel ancestry checks, not a caller-supplied principal.
// The trusted binder must additionally resolve the retained local root binding.
type ManagedFabricPeer struct {
	InstanceID, AgentPrincipalID, NetworkID, Kind string
	RootPID                                       int
	ProcessBound                                  bool
}
type ManagedFabricMCP struct {
	Server       *fabricmcp.Server
	BindVerified func(context.Context, net.Conn, ManagedFabricPeer) (fabricmcp.SessionFactory, error)
}
type managedFabricFactory struct {
	daemon     *Daemon
	connection net.Conn
	peer       ManagedFabricPeer
	nonce      string
	factory    fabricmcp.SessionFactory
}

func (f *managedFabricFactory) Build(ctx context.Context, call mcpbridge.Call) ([]byte, any, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, fabric.NewError(fabric.CodeUnauthenticated, "Local MCP peer unavailable")
	}
	row, ok, err := f.daemon.state.GetInstance(f.peer.InstanceID)
	if err != nil || !ok || row.Status == "stopped" || row.Status == "hibernated" || row.AgentPrincipalID != f.peer.AgentPrincipalID || row.NetworkID != f.peer.NetworkID || !f.daemon.bridgeNonceValid(f.peer.InstanceID, f.nonce) {
		return nil, nil, fabric.NewError(fabric.CodeUnauthenticated, "Local MCP peer revoked")
	}
	kind := row.Kind
	if kind == "" {
		kind = "worker"
	}
	pid := f.daemon.instanceRootPID(f.peer.InstanceID)
	if kind != f.peer.Kind || pid == nil || *pid != f.peer.RootPID || f.daemon.verifyBridgePeer(f.connection, *pid) != nil {
		return nil, nil, fabric.NewError(fabric.CodeUnauthenticated, "Local MCP process binding changed")
	}
	return f.factory.Build(ctx, call)
}
func (d *Daemon) prepareManagedFabricPeer(ctx context.Context, c net.Conn, row *InstanceRow, kind, nonce string, pid int) (fabricmcp.SessionFactory, error) {
	if d.FabricMCP == nil || d.FabricMCP.Server == nil || d.FabricMCP.BindVerified == nil {
		return nil, fabric.NewError(fabric.CodeUnsupported, "Local Fabric MCP not configured")
	}
	peer := ManagedFabricPeer{row.InstanceID, row.AgentPrincipalID, row.NetworkID, kind, pid, bridgeIsolationMode() == bridgeIsolationProcessBound}
	factory, err := d.FabricMCP.BindVerified(ctx, c, peer)
	if err != nil || factory == nil {
		if factory != nil {
			_ = factory.Close()
		}
		return nil, fabric.NewError(fabric.CodeUnauthenticated, "Local Fabric peer binding unavailable")
	}
	return &managedFabricFactory{d, c, peer, nonce, factory}, nil
}
func (d *Daemon) serveManagedFabric(c net.Conn, reader io.Reader, factory fabricmcp.SessionFactory) {
	// Serve owns the authenticated socket. No old cloud tool relay is attempted.
	_ = d.FabricMCP.Server.ServeVerified(d.turnCtx, c, reader, factory)
}

func (f *managedFabricFactory) Close() error { return f.factory.Close() }
