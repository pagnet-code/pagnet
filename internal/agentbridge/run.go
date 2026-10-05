// The shared MCP bridge body (packaging migration step 5). The daemon
// spawns its bridges as <self> mcp worker|control, so the unified binary
// (the only daemon entrypoint) must be able to run the bridge too. The
// entrypoints live in the cmd/ packages; this is the one shared
// run/dial implementation they route to.

package agentbridge

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/pagnet-code/pagnet/internal/fabricclient"
)

// log is the bridge's own stderr logger (JSON): the bridge is spawned
// by an agent runtime whose stdout is the MCP protocol channel —
// diagnostics go to stderr, never stdout.
var log = slog.New(slog.NewJSONHandler(os.Stderr, nil))

// sideportDialTimeout bounds the sideport's second-socket handshake (the
// local node dial, its authentication and the MCP initialization). The node
// is on this host; the bound keeps a wedged or absent node from delaying the
// bridge's own startup past any useful window.
const sideportDialTimeout = 30 * time.Second

// hostedFabricSideportInstructions is the actionable explicit refresh
// requirement shown in the MCP initialize response when this bridge carries
// a hosted Fabric sideport. The bridge NEVER claims tools/list_changed (it
// cannot: the server emits no tool-change notification), so a client that
// already initialized — an already-running old bridge or session — cannot
// learn new tools; the only refresh is a new bridge session.
const hostedFabricSideportInstructions = "This pagnet bridge may carry the hosted Fabric operations (discover, describe, invoke) alongside the network tools; they are attached at bridge start only when the original worker's node accepts this process. This server does not declare tools/list_changed: the tool list is fixed for the lifetime of this bridge, so an MCP client that already initialized (including against an older bridge) must reconnect and re-initialize — start a fresh bridge session — to see the current tools. If the Fabric operations are missing here, the node refused this bridge at start-up; restarting the agent's bridge is the explicit refresh."

// sideportServerOptions shapes the MCP server for a sideport-carrying
// bridge: the actionable explicit refresh requirement in the initialize
// response. It NEVER adds tools/list_changed to the declared capabilities
// (the server emits no tool-change notification, so claiming it would be a
// lie); ordinary bridges get no options at all and stay byte-identical in
// their initialize response.
func sideportServerOptions(br *Bridge) []server.ServerOption {
	if _, ok := br.Sideport(); !ok {
		return nil
	}
	return []server.ServerOption{server.WithInstructions(hostedFabricSideportInstructions)}
}

// RunBridge serves one MCP bridge over stdio: check the injected
// environment, connect to the daemon's Unix socket with the instance
// identity + the per-activation nonce, register the surface's tools, and
// serve until the runtime closes stdin. When the authenticated handshake
// advertised a hosted Fabric sideport, the bridge first opens the node's
// second socket with its OWN nonce/instance (DialHostedFabric) and merges
// the node's three canonical tools (RegisterHostedFabricTools) over the
// original surface; the node client is closed with the bridge lifetime.
// serverName must stay the EXACT name the daemon's MCP config carries
// ("pagnet" / "pagnet-control"); kind is the instance kind this surface
// serves ("worker" / "representative") — the daemon binds the auth to it
// (S1).
func RunBridge(socket, serverName, kind string, register func(s *server.MCPServer, br *Bridge)) error {
	instanceID := os.Getenv("PAGNET_INSTANCE_ID")
	networkID := os.Getenv("PAGNET_NETWORK_ID") // empty for representatives
	// S1: the per-activation nonce the daemon minted for this launch and
	// shipped in the MCP config env. A bridge without it cannot
	// authenticate — fail closed instead of degrading to identifier-only
	// auth (that hole is exactly what the nonce closes).
	nonce := os.Getenv("PAGNET_BRIDGE_NONCE")
	if socket == "" {
		return errors.New("--socket is required (the daemon injects it)")
	}
	if instanceID == "" {
		return errors.New("PAGNET_INSTANCE_ID is not set (this process must be launched by the pagnet daemon)")
	}
	if nonce == "" {
		return errors.New("PAGNET_BRIDGE_NONCE is not set (the daemon must mint it in the MCP config; refusing to bridge without per-activation credentials)")
	}

	br, err := dialWithRetry(socket, instanceID, networkID, nonce, kind)
	if err != nil {
		return err
	}
	defer br.Close()
	log.Info("mcp bridge connected", "server", serverName, "instance", instanceID, "kind", kind, "network", networkID)

	// The bridge's tool surface is registered once at start and never
	// changes mid-bridge: the server must NOT claim tools/list_changed
	// (it emits no tool-change notification — claiming it would be a
	// lie). A client that needs the current tool list starts a fresh
	// bridge session — the explicit refresh (see the sideport
	// instructions below). Same convention as the external bridge.
	opts := []server.ServerOption{server.WithToolCapabilities(false)}
	opts = append(opts, sideportServerOptions(br)...)
	s := server.NewMCPServer(serverName, "1.0.0", opts...)
	register(s, br)

	// Hosted Fabric sideport (Phase A step 3): when the daemon's REAL
	// authenticated handshake advertised a sideport for this instance, open
	// the node's SECOND socket from THIS original MCP subprocess with the
	// bridge's OWN per-activation nonce and instance identity (never
	// daemon/operator credentials); the node then verifies this process's
	// actual kernel ancestry against the original worker. The node client
	// dies with this bridge — no client may outlive its bridge.
	var sideClient *fabricclient.Client
	if sp, ok := br.Sideport(); ok {
		dialCtx, cancel := context.WithTimeout(context.Background(), sideportDialTimeout)
		client, dialErr := DialHostedFabric(dialCtx, sp, instanceID, nonce)
		cancel()
		if dialErr != nil {
			// Explicit, not silent: the original tools still serve, and the
			// refusal is on the bridge's stderr for the operator.
			log.Error("hosted fabric sideport unavailable; the bridge serves its original tools only",
				"error", dialErr.Error(), "instance", instanceID)
		} else {
			registerCtx, registerCancel := context.WithTimeout(context.Background(), sideportDialTimeout)
			regErr := RegisterHostedFabricTools(registerCtx, s, client)
			registerCancel()
			if regErr != nil {
				_ = client.Close()
				log.Error("hosted fabric tools unavailable; the bridge serves its original tools only",
					"error", regErr.Error(), "instance", instanceID)
			} else {
				sideClient = client
				log.Info("hosted fabric sideport attached", "instance", instanceID, "tools", 3)
			}
		}
	}

	serveErr := server.ServeStdio(s)
	// The bridge lifetime is over (the runtime closed stdin): the node
	// session and its underlying authenticated socket go with it.
	if sideClient != nil {
		if closeErr := sideClient.Close(); closeErr != nil {
			log.Warn("closing the hosted fabric node session with the bridge", "error", closeErr.Error())
		}
	}
	return serveErr
}

// dialWithRetry dials the daemon's Unix socket with a short retry
// window: the socket is local and comes up with the daemon, but the
// runtime process may start a fraction earlier.
func dialWithRetry(socket, instanceID, networkID, nonce, kind string) (*Bridge, error) {
	var br *Bridge
	var err error
	deadline := time.Now().Add(10 * time.Second)
	for {
		br, err = Dial(socket, instanceID, networkID, nonce, kind)
		if err == nil {
			return br, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("agent bridge unavailable at %s: %w", socket, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
