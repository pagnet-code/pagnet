//go:build linux || darwin

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
	"github.com/pagnet-code/pagnet/internal/fabricmcp"
)

func TestMCPFabricCLIHelper(t *testing.T) {
	if os.Getenv("PAGNET_TEST_FABRIC_CLI") != "1" {
		return
	}
	command := mcpFabricCmd()
	command.SetArgs([]string{"--socket", os.Getenv("PAGNET_TEST_FABRIC_SOCKET")})
	if err := command.Execute(); err != nil {
		os.Exit(2)
	}
	os.Exit(0) // stdout belongs exclusively to MCP, including fixture shutdown.
}
func TestActualFabricCLIChildOfficialSDKAndPrivateOwner(t *testing.T) {
	private, err := os.MkdirTemp("", "pgn-mcp-cli-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(private)
	socket := filepath.Join(private, "fabric.sock")
	owner := fabric.Principal{Ref: "local:registered-owner", Issuer: "actual-cli-fixture", Kind: "local.owner"}
	store, err := registry.Bootstrap(t.Context(), filepath.Join(t.TempDir(), "retained"), owner)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	root := store.AuthorityIdentity()
	authority, err := fabricauth.New(fabricauth.Config{Root: root, RootOwner: owner, Audience: root.Namespace, SocketPath: socket, CurrentRoot: store.CurrentAuthorityIdentity})
	if err != nil {
		t.Fatal(err)
	}
	index, err := store.LoadIndex(t.Context(), search.Config{})
	if err != nil {
		t.Fatal(err)
	}
	service, err := node.New(node.Config{Audience: root.Namespace, Authenticator: authority, Search: index, Descriptors: store})
	if err != nil {
		t.Fatal(err)
	}
	server, err := fabricmcp.New(fabricmcp.Config{Executor: service})
	if err != nil {
		t.Fatal(err)
	}
	host, err := fabrichost.Start(t.Context(), fabrichost.Config{SocketPath: socket, Authority: authority, Server: server})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		host.CloseContext(ctx)
	}()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestMCPFabricCLIHelper$")
	names := []string{fabrichost.EndpointEnvironment, fabrichost.WorkerEnvironment, fabrichost.GenerationEnvironment, fabrichost.NonceEnvironment}
	for _, value := range os.Environ() {
		exclude := false
		for _, name := range names {
			if strings.HasPrefix(value, name+"=") {
				exclude = true
			}
		}
		if !exclude {
			child.Env = append(child.Env, value)
		}
	}
	child.Env = append(child.Env, "PAGNET_TEST_FABRIC_CLI=1", "PAGNET_TEST_FABRIC_SOCKET="+socket)
	client := sdk.NewClient(&sdk.Implementation{Name: "actual-stdio-local-client", Version: "1"}, nil)
	session, err := client.Connect(t.Context(), &sdk.CommandTransport{Command: child}, nil)
	if err != nil {
		t.Fatal("actual CLI protocol initialization failed", err)
	}
	tools, err := session.ListTools(t.Context(), nil)
	if err != nil || len(tools.Tools) != 3 {
		t.Fatal("actual CLI did not expose three genuine tools", err)
	}
	result, err := session.CallTool(t.Context(), &sdk.CallToolParams{Name: "discover", Arguments: map[string]any{"query": "local work", "limit": 1}})
	if err != nil || result.IsError {
		t.Fatal("actual CLI never reached authenticated node", err, result)
	}
	if err = session.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestFabricCLIRequiresExplicitSocketAndRejectsPartialManagedBeforeDial(t *testing.T) {
	command := mcpFabricCmd()
	command.SetArgs(nil)
	if err := command.Execute(); err == nil {
		t.Fatal("CLI silently selected a socket")
	}
	t.Setenv(fabrichost.EndpointEnvironment, "broken")
	for _, name := range []string{fabrichost.WorkerEnvironment, fabrichost.GenerationEnvironment, fabrichost.NonceEnvironment} {
		t.Setenv(name, "")
	}
	// There is intentionally no socket listener: credential validation must reject
	// before any attempt to contact a host or select an owner identity.
	command = mcpFabricCmd()
	command.SetArgs([]string{"--socket", filepath.Join(t.TempDir(), "absent.sock")})
	if err := command.Execute(); err == nil {
		t.Fatal("partial managed fields granted owner")
	}
}
