//go:build linux || darwin

package fabricmcp_test

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/mcpbridge"
	"github.com/pagnet-code/pagnet/fabric/node/dispatch"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabricmcp"
	"github.com/pagnet-code/pagnet/internal/fabricnode"
)

// This node deliberately installs no endpoint executors. Discovery/description
// are genuine; an attempted invocation is explicitly unavailable, never faked.
type noInstalledBinding struct{}

func (noInstalledBinding) Select(context.Context, fabric.ExecutionContext, fabric.EndpointDescriptor, *fabric.OfferDescriptor) (dispatch.Selection, error) {
	return dispatch.Selection{}, fabric.NewError(fabric.CodeTargetUnavailable, "No executor installed in read-only node fixture")
}

type noInstalledAdmission struct{}

func (noInstalledAdmission) WithDispatch(context.Context, fabric.ExecutionContext, []byte, []byte, fabric.EndpointDescriptor, *fabric.OfferDescriptor, dispatch.Selection, func(context.Context) (fabric.InvocationStream, error)) (fabric.InvocationStream, error) {
	return nil, fabric.NewError(fabric.CodeUnauthenticated, "No invocation admission installed in read-only node fixture")
}

func TestRealUnixOwnerRetainedNodeOfficialMCPAndRestart(t *testing.T) {
	ctx := t.Context()
	directory := filepath.Join(t.TempDir(), "retained-domain")
	owner := fabric.Principal{Ref: "local:registered-owner", Kind: "local.owner", Issuer: "operator.setup"}
	bootstrap, err := registry.Bootstrap(ctx, directory, owner)
	if err != nil {
		t.Fatal(err)
	}
	originalRoot := bootstrap.AuthorityIdentity()
	if err = bootstrap.Close(); err != nil {
		t.Fatal(err)
	}
	private, err := os.MkdirTemp("", "pgn-mcp-owner-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(private)
	socket := filepath.Join(private, "owner.sock")
	var authority *fabricauth.Authority
	config := fabricnode.Config{Directory: directory, Compose: func(ctx context.Context, store *registry.Store, _ *search.Backend) (fabricnode.Ports, error) {
		root := store.AuthorityIdentity()
		var err error
		authority, err = fabricauth.New(fabricauth.Config{Root: root, RootOwner: owner, Audience: root.Namespace, SocketPath: socket, CurrentRoot: func(ctx context.Context) (registry.AuthorityIdentity, error) {
			return store.CurrentAuthorityIdentity(ctx)
		}})
		return fabricnode.Ports{Authenticator: authority, Bindings: noInstalledBinding{}, Admission: noInstalledAdmission{}}, err
	}}
	endpoint, _ := fabric.NewEndpointRef(originalRoot.PublicKey)
	var remembered fabric.Revision
	for phase := 0; phase < 2; phase++ {
		n, err := fabricnode.Open(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		if n.Store.AuthorityIdentity().Namespace != originalRoot.Namespace || n.Store.AuthorityIdentity().StoreID != originalRoot.StoreID {
			t.Fatal("restart replaced retained root")
		}
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		listener.SetUnlinkOnClose(false)
		if err = os.Chmod(socket, 0600); err != nil {
			t.Fatal(err)
		}
		clientConn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		accepted, err := listener.AcceptUnix()
		if err != nil {
			t.Fatal(err)
		}
		factory, err := authority.BindOwner(ctx, accepted)
		if err != nil {
			t.Fatal("actual kernel owner refused", err)
		}
		if phase == 0 {
			raw, evidence, err := factory.Build(ctx, mcpbridge.Call{Operation: fabric.OperationDiscover, Discover: &fabric.DiscoverRequest{Query: "invoice", Limit: 1}})
			if err != nil {
				t.Fatal(err)
			}
			trusted, err := authority.Authenticate(ctx, fabric.AuthenticationRequest{ExactEnvelope: raw, Audience: originalRoot.Namespace, PeerEvidence: evidence})
			if err != nil {
				t.Fatal(err)
			}
			remembered, err = n.Store.Register(ctx, trusted, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: endpoint, Kind: "actor.agent", Name: "Invoice", Description: "Invoice retrieval"}})
			if err != nil {
				t.Fatal(err)
			}
			if more, err := n.Synchronize(ctx, 1); err != nil || more {
				t.Fatal("genuine signed descriptor did not index", err)
			}
		}
		server, err := fabricmcp.New(fabricmcp.Config{Executor: n.Service})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- server.ServeVerified(ctx, accepted, accepted, factory) }()
		client := sdk.NewClient(&sdk.Implementation{Name: "real-local-owner", Version: "1"}, nil)
		session, err := client.Connect(ctx, &sdk.IOTransport{Reader: clientConn, Writer: clientConn}, nil)
		if err != nil {
			t.Fatal(err)
		}
		result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "discover", Arguments: map[string]any{"query": "invoice", "limit": 1}})
		if err != nil || result.IsError {
			t.Fatal("real node discover failed", err, result)
		}
		text, ok := result.Content[0].(*sdk.TextContent)
		if !ok {
			t.Fatal("missing genuine discovery payload")
		}
		var discovery fabric.DiscoverResult
		if fabric.DecodeJSON([]byte(text.Text), &discovery) != nil || len(discovery.Candidates) != 1 || discovery.Candidates[0].Document.Ref != endpoint {
			t.Fatal("retained exact descriptor missing")
		}
		result, err = session.CallTool(ctx, &sdk.CallToolParams{Name: "describe", Arguments: map[string]any{"selections": []any{map[string]any{"ref": endpoint.String(), "expectedRevision": string(remembered)}}}})
		if err != nil || result.IsError {
			t.Fatal("remembered real descriptor unavailable", err, result)
		}
		rawResult, _ := json.Marshal(result)
		if len(rawResult) == 0 {
			t.Fatal("empty description")
		}
		session.Close()
		bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
		err = server.CloseContext(bounded)
		cancel()
		if err != nil {
			t.Fatal("real owner session did not join", err)
		}
		<-done
		if _, _, err = factory.Build(ctx, mcpbridge.Call{Operation: fabric.OperationDiscover, Discover: &fabric.DiscoverRequest{Query: "invoice", Limit: 1}}); err == nil {
			t.Fatal("closed real owner session still minted proof")
		}
		if err = n.Close(); err != nil {
			t.Fatal(err)
		}
		listener.Close()
		os.Remove(socket)
	}
}
