//go:build linux || darwin

package agentbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabricclient"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
	"github.com/pagnet-code/pagnet/internal/fabricmcp"
)

type sideportRecordingExecutor struct {
	node *node.Service
	mu   sync.Mutex
	last []byte
}

func (r *sideportRecordingExecutor) Execute(ctx context.Context, body []byte, proof any) (node.Result, error) {
	r.mu.Lock()
	r.last = bytes.Clone(body)
	r.mu.Unlock()
	return r.node.Execute(ctx, body, proof)
}

func TestHostedSideportCanonicalSDKMergeRetainsOriginalToolsAndRawJSON(t *testing.T) {
	ctx := t.Context()
	private, err := os.MkdirTemp("", "pgn-side-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(private)
	socket := filepath.Join(private, "fabric.sock")
	owner := fabric.Principal{Ref: "local:owner", Kind: "local.owner", Issuer: "owner.test"}
	store, err := registry.Bootstrap(ctx, filepath.Join(private, "registry"), owner)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	root := store.AuthorityIdentity()
	auth, err := fabricauth.New(fabricauth.Config{Root: root, RootOwner: owner, Audience: root.Namespace, SocketPath: socket, CurrentRoot: store.CurrentAuthorityIdentity})
	if err != nil {
		t.Fatal(err)
	}
	index, err := store.LoadIndex(ctx, search.Config{})
	if err != nil {
		t.Fatal(err)
	}
	n, err := node.New(node.Config{Audience: root.Namespace, Authenticator: auth, Search: index, Descriptors: store})
	if err != nil {
		t.Fatal(err)
	}
	executor := &sideportRecordingExecutor{node: n}
	canonical, err := fabricmcp.New(fabricmcp.Config{Executor: executor})
	if err != nil {
		t.Fatal(err)
	}
	host, err := fabrichost.Start(ctx, fabrichost.Config{SocketPath: socket, Authority: auth, Server: canonical})
	if err != nil {
		t.Fatal(err)
	}
	defer host.CloseContext(ctx)
	// This interop fixture uses a genuine kernel OWNER session only to test
	// schema/result translation. It does not claim original runtime ownership.
	client, err := fabricclient.Dial(ctx, socket, fabrichost.Authentication{Type: "fabric.auth", Mode: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	s := server.NewMCPServer("pagnet", "1")
	legacySocket, _ := fakeBridgeServer(t)
	br, err := Dial(legacySocket, "inst-1", "net-1", "nonce-1", "worker")
	if err != nil {
		t.Fatal(err)
	}
	defer br.Close()
	RegisterWorkerTools(s, br)
	old := len(s.ListTools())
	if err = RegisterHostedFabricTools(ctx, s, client); err != nil {
		t.Fatal(err)
	}
	tools := s.ListTools()
	if len(tools) != old+3 {
		t.Fatal("lost original tools or published an unbounded catalog")
	}
	for _, name := range []string{"discover", "describe", "invoke"} {
		if _, ok := tools[name]; !ok {
			t.Fatal("missing canonical operation", name)
		}
	}
	actualTools, err := client.CanonicalTools(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, actual := range actualTools {
		expected, _ := json.Marshal(actual.InputSchema)
		retained := tools[actual.Name].Tool.RawInputSchema
		if !bytes.Equal(retained, expected) {
			t.Fatal("canonical JSON Schema composition was lost", actual.Name)
		}
	}
	if !bytes.Contains(tools["invoke"].Tool.RawInputSchema, []byte(`"oneOf"`)) {
		t.Fatal("canonical invoke alternatives disappeared")
	}
	discover := tools["discover"]
	result, err := discover.Handler(ctx, mcp.CallToolRequest{Params: mcp.CallToolParams{Name: "discover", RawArguments: json.RawMessage(`{"query":"sales","limit":1}`)}})
	if err != nil || result == nil || result.IsError {
		t.Fatal("actual authenticated discovery", err, result)
	}
	invoke := tools["invoke"]
	ref, _ := fabric.NewEndpointRef(root.PublicKey)
	arguments, _ := json.Marshal(map[string]any{"target": ref.String(), "revision": "exact-revision", "input": json.RawMessage(`{"n":9007199254740993}`)})
	_, err = invoke.Handler(ctx, mcp.CallToolRequest{Params: mcp.CallToolParams{Name: "invoke", RawArguments: arguments}})
	if err != nil {
		t.Fatal(err)
	}
	executor.mu.Lock()
	raw := bytes.Clone(executor.last)
	executor.mu.Unlock()
	if !bytes.Contains(raw, []byte("9007199254740993")) {
		t.Fatal("raw application number lost precision", string(raw))
	}
	// A hosted attempt cannot degrade into this working owner connection.
	if _, err = DialHostedFabric(ctx, HostedFabricSideport{Socket: socket, Endpoint: ref, Generation: "original"}, "original-instance", "original-nonce"); err == nil {
		t.Fatal("hosted mode became owner without actual original worker proof")
	}
}
