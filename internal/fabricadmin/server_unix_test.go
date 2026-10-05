//go:build linux || darwin

package fabricadmin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
	"github.com/pagnet-code/pagnet/internal/fabricmcp"
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func actualHost(t *testing.T, handlers map[string]Handler, options ...func(*fabricauth.Config)) (*fabrichost.Host, *Server, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "pgn-admin-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "fabric.sock")
	owner := fabric.Principal{Ref: "local:owner", Issuer: "registered-owner", Kind: "local.owner"}
	store, err := registry.Bootstrap(t.Context(), filepath.Join(t.TempDir(), "root"), owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	root := store.AuthorityIdentity()
	authConfig := fabricauth.Config{Root: root, RootOwner: owner, Audience: root.Namespace, SocketPath: socket, CurrentRoot: store.CurrentAuthorityIdentity}
	for _, option := range options {
		option(&authConfig)
	}
	auth, err := fabricauth.New(authConfig)
	if err != nil {
		t.Fatal(err)
	}
	index, err := store.LoadIndex(t.Context(), search.Config{})
	if err != nil {
		t.Fatal(err)
	}
	service, err := node.New(node.Config{Audience: root.Namespace, Authenticator: auth, Search: index, Descriptors: store})
	if err != nil {
		t.Fatal(err)
	}
	mcp, err := fabricmcp.New(fabricmcp.Config{Executor: service})
	if err != nil {
		t.Fatal(err)
	}
	admin, err := New(Config{Handlers: handlers, OperationTimeout: time.Second, IdleTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	host, err := fabrichost.Start(t.Context(), fabrichost.Config{SocketPath: socket, Authority: auth, Server: mcp, Protocols: map[string]fabrichost.VerifiedSessionServer{fabrichost.AdminProtocol: admin}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if e := host.CloseContext(ctx); e != nil {
			t.Error(e)
		}
	})
	return host, admin, socket
}
func req() Request {
	return Request{Version: Version, ID: "management-1", Operation: "agent.inspect", Input: json.RawMessage(`{"n":9007199254740993}`)}
}

type sdkInput struct {
	io.Reader
	conn net.Conn
}

func (i *sdkInput) Close() error { return i.conn.Close() }

func TestPrivateOwnerAdministrationAndMCPRemainSeparate(t *testing.T) {
	var escaped *fabricauth.OwnerAdministration
	_, _, socket := actualHost(t, map[string]Handler{"agent.inspect": func(ctx context.Context, owner *fabricauth.OwnerAdministration, r Request) (json.RawMessage, error) {
		escaped = owner
		if err := owner.VerifyCurrent(ctx); err != nil {
			return nil, err
		}
		if string(r.Input) != `{"n":9007199254740993}` {
			t.Error("input precision changed")
		}
		return json.RawMessage(`{"n":9007199254740993}`), nil
	}})
	client, err := Dial(t.Context(), socket)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	response, err := client.Call(t.Context(), req())
	if err != nil || response.Error != nil || string(response.Result) != `{"n":9007199254740993}` {
		t.Fatal(response, err)
	}
	if escaped == nil || escaped.VerifyCurrent(t.Context()) == nil {
		t.Fatal("management capability escaped")
	}
	conn, reader, err := fabrichost.Dial(t.Context(), socket, fabrichost.Authentication{Type: "fabric.auth", Mode: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	official := sdk.NewClient(&sdk.Implementation{Name: "owner-test", Version: "1"}, nil)
	session, err := official.Connect(t.Context(), &sdk.IOTransport{Reader: &sdkInput{reader, conn}, Writer: conn}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	tools, err := session.ListTools(t.Context(), nil)
	if err != nil || len(tools.Tools) != 3 {
		t.Fatal("private admin altered runtime MCP surface", err)
	}
	for _, tool := range tools.Tools {
		if tool.Name != "discover" && tool.Name != "describe" && tool.Name != "invoke" {
			t.Fatal("management tool exposed", tool.Name)
		}
	}
	// Unknown protocol is explicit, never retried as MCP or owner administration.
	if _, _, err = fabrichost.DialProtocol(t.Context(), socket, fabrichost.Authentication{Type: "fabric.auth", Mode: "owner"}, "fabric.unknown"); err == nil {
		t.Fatal("unknown protocol accepted")
	}
}

func TestAdministrationMalformedFramesNeverReachHandler(t *testing.T) {
	var calls atomic.Int32
	_, _, socket := actualHost(t, map[string]Handler{"agent.inspect": func(context.Context, *fabricauth.OwnerAdministration, Request) (json.RawMessage, error) {
		calls.Add(1)
		return json.RawMessage(`{}`), nil
	}})
	cases := [][]byte{
		[]byte(`{"version":1,"id":"x","operation":"agent.inspect","input":{},"input":{}}` + "\n"),
		[]byte(`{"version":1,"ID":"x","operation":"agent.inspect","input":{}}` + "\n"),
		[]byte(`{"version":1,"id":"x","operation":"agent.inspect","input":{},"owner":"forged"}` + "\n"),
		append(bytes.Repeat([]byte("x"), MaxRequestBytes+1), '\n'),
		[]byte(`{"version":1,"id":"x","operation":"agent.inspect","input":{}} {}` + "\n"),
	}
	for i, frame := range cases {
		conn, reader, err := fabrichost.DialProtocol(t.Context(), socket, fabrichost.Authentication{Type: "fabric.auth", Mode: "owner"}, fabrichost.AdminProtocol)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(time.Second))
		conn.Write(frame)
		if _, err = reader.ReadByte(); err == nil {
			t.Fatalf("malformed frame %d received response", i)
		}
		conn.Close()
	}
	if calls.Load() != 0 {
		t.Fatal("malformed request reached handler")
	}
}

func TestAdministrationDisconnectCancelsAndShutdownJoinsActualCallback(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	host, admin, socket := actualHost(t, map[string]Handler{"agent.inspect": func(ctx context.Context, owner *fabricauth.OwnerAdministration, _ Request) (json.RawMessage, error) {
		close(started)
		<-ctx.Done()
		close(canceled)
		<-release
		if owner.VerifyCurrent(context.Background()) == nil {
			t.Error("disconnected owner capability accepted")
		}
		return nil, ctx.Err()
	}})
	client, err := Dial(t.Context(), socket)
	if err != nil {
		t.Fatal(err)
	}
	callDone := make(chan error, 1)
	go func() { _, e := client.Call(context.Background(), req()); callDone <- e }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
	client.Close()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("disconnect did not cancel handler")
	}
	deadline, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	if err = admin.CloseContext(deadline); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("close falsely joined accepted callback", err)
	}
	cancel()
	close(release)
	bounded, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err = host.CloseContext(bounded); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-callDone:
		if e == nil {
			t.Fatal("disconnected call reported success")
		}
	case <-bounded.Done():
		t.Fatal("client did not finish")
	}
	if _, err = os.Lstat(socket); !os.IsNotExist(err) {
		t.Fatal("listener released before cleanup")
	}
}

func TestAdministrationErrorCannotSerializeProviderSecrets(t *testing.T) {
	_, _, socket := actualHost(t, map[string]Handler{"agent.inspect": func(context.Context, *fabricauth.OwnerAdministration, Request) (json.RawMessage, error) {
		return nil, &fabric.Error{Code: fabric.CodeUnauthenticated, Message: "provider-token-secret", Effect: fabric.EffectUnknown}
	}})
	c, err := Dial(t.Context(), socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r, err := c.Call(t.Context(), req())
	if err != nil || r.Error == nil || r.Error.Code != fabric.CodeUnauthenticated || r.Error.Message == "provider-token-secret" {
		t.Fatal("provider error leaked or mangled", err)
	}
}

func TestAdminManagedChildHelper(t *testing.T) {
	if os.Getenv("PAGNET_ADMIN_CHILD") != "1" {
		return
	}
	socket, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		os.Exit(2)
	}
	socket = socket[:len(socket)-1]
	client, err := Dial(context.Background(), socket)
	if err == nil {
		client.Close()
		os.Exit(3)
	}
	os.Exit(0)
}
func TestActualManagedKernelChildCannotImpersonateAdminOwner(t *testing.T) {
	parent, err := localpeer.ReadProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	var denied atomic.Int32
	_, _, socket := actualHost(t, map[string]Handler{"agent.inspect": func(context.Context, *fabricauth.OwnerAdministration, Request) (json.RawMessage, error) {
		return json.RawMessage(`{}`), nil
	}}, func(c *fabricauth.Config) {
		c.ManagedValidator = func(context.Context, fabricauth.ManagedPeer) (fabric.Principal, error) {
			return fabric.Principal{}, failure()
		}
		c.OwnerValidator = func(_ context.Context, peer localpeer.ProcessSnapshot) error {
			if peer == parent {
				return nil
			}
			if localpeer.VerifyProcessTree(peer.PID, parent.PID, parent.UID, localpeer.ReadProcess) == nil {
				denied.Add(1)
			}
			return failure()
		}
	})
	client, err := Dial(t.Context(), socket)
	if err != nil {
		t.Fatal("actual independent owner denied", err)
	}
	client.Close()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(t.Context(), exe, "-test.run=^TestAdminManagedChildHelper$")
	child.Env = append(os.Environ(), "PAGNET_ADMIN_CHILD=1")
	child.Stdin = bytes.NewBufferString(socket + "\n")
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatal("managed child admin downgrade or fixture failure", err, string(output))
	}
	if denied.Load() != 1 {
		t.Fatal("real kernel child owner guard not applied", denied.Load())
	}
}
