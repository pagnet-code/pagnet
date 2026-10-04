//go:build linux || darwin

package fabrichost

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabricmcp"
	"github.com/pagnet-code/pagnet/internal/localpeer"
)

func fixture(t *testing.T) (Config, *registry.Store) {
	t.Helper()
	private, err := os.MkdirTemp("", "pgn-host-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(private) })
	socket := filepath.Join(private, "fabric.sock")
	owner := fabric.Principal{Ref: "local:owner", Issuer: "registered-owner", Kind: "local.owner"}
	store, err := registry.Bootstrap(t.Context(), filepath.Join(t.TempDir(), "domain"), owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	root := store.AuthorityIdentity()
	auth, err := fabricauth.New(fabricauth.Config{Root: root, RootOwner: owner, Audience: root.Namespace, SocketPath: socket, CurrentRoot: store.CurrentAuthorityIdentity})
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
	server, err := fabricmcp.New(fabricmcp.Config{Executor: service})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		server.CloseContext(ctx)
	})
	return Config{SocketPath: socket, Authority: auth, Server: server}, store
}
func TestOwnerDirectSocketOfficialSDKNoCloudOrRuntime(t *testing.T) {
	config, _ := fixture(t)
	host, err := Start(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer host.CloseContext(t.Context())
	conn, reader, err := Dial(t.Context(), config.SocketPath, Authentication{Type: "fabric.auth", Mode: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "genuine-direct-owner", Version: "1"}, nil)
	session, err := client.Connect(t.Context(), &sdk.IOTransport{Reader: &clientInput{reader, conn}, Writer: conn}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tools, err := session.ListTools(t.Context(), nil)
	if err != nil || len(tools.Tools) != 3 {
		t.Fatal("official protocol negotiation failed", err)
	}
	result, err := session.CallTool(t.Context(), &sdk.CallToolParams{Name: "discover", Arguments: map[string]any{"query": "work", "limit": 1}})
	if err != nil || result.IsError {
		t.Fatal("actual authenticated discovery failed", err, result)
	}
	session.Close()
	bounded, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err = host.CloseContext(bounded); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(config.SocketPath); !os.IsNotExist(err) {
		t.Fatal("owned socket retained after complete join")
	}
}

type clientInput struct {
	io.Reader
	connection net.Conn
}

func (r *clientInput) Close() error { return r.connection.Close() }
func TestAuthenticationCannotFallbackFromManagedToOwner(t *testing.T) {
	config, store := fixture(t)
	root := store.AuthorityIdentity()
	authority, err := fabricauth.New(fabricauth.Config{Root: root, RootOwner: root.Owner, Audience: root.Namespace, SocketPath: config.SocketPath, CurrentRoot: store.CurrentAuthorityIdentity,
		ManagedValidator: func(context.Context, fabricauth.ManagedPeer) (fabric.Principal, error) {
			return fabric.Principal{}, failure()
		},
		OwnerValidator: func(context.Context, localpeer.ProcessSnapshot) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	config.Authority = authority
	var resolved atomic.Int32
	config.ResolveManaged = func(context.Context, ManagedSelector) (fabricauth.Activation, error) {
		resolved.Add(1)
		return fabricauth.Activation{}, failure()
	}
	host, err := Start(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer host.CloseContext(t.Context())
	endpoint, _ := fabric.NewEndpointRef(store.AuthorityIdentity().PublicKey)
	inputs := []string{
		`{"type":"fabric.auth","mode":"owner","workerId":"other"}`,
		`{"type":"fabric.auth","mode":"owner","principal":"forged"}`,
		`{"type":"fabric.auth","mode":"owner","mode":"managed"}`,
		`{"type":"fabric.auth","mode":"managed","endpoint":"` + endpoint.String() + `","workerId":"physical"}`,
		`{"type":"fabric.auth","Mode":"owner"}`,
	}
	for _, input := range inputs {
		c, err := net.Dial("unix", config.SocketPath)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		_, _ = io.WriteString(c, input+"\n")
		var one [1]byte
		n, err := c.Read(one[:])
		c.Close()
		if n != 0 || err == nil {
			t.Fatal("invalid peer received success acknowledgement")
		}
	}
	if resolved.Load() != 0 {
		t.Fatal("malformed identity reached source resolver")
	}
	_, _, err = Dial(t.Context(), config.SocketPath, Authentication{Type: "fabric.auth", Mode: "managed", Endpoint: endpoint, WorkerID: "physical", Generation: "native", Nonce: "presented"})
	if err == nil || resolved.Load() != 1 {
		t.Fatal("failed authoritative resolver became owner", err)
	}
}
func TestBufferedInitializeSurvivesPrivateHandshake(t *testing.T) {
	config, _ := fixture(t)
	host, err := Start(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer host.CloseContext(t.Context())
	c, err := net.Dial("unix", config.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	_, err = io.WriteString(c, "{\"type\":\"fabric.auth\",\"mode\":\"owner\"}\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"prefetched\",\"version\":\"1\"}}}\n")
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(c)
	ack, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(ack, "fabric.ready") {
		t.Fatal("private handshake failed", err)
	}
	initialize, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(initialize, `"id":1`) || !strings.Contains(initialize, `"result"`) {
		t.Fatal("prefetched initialize bytes lost", err, initialize)
	}
}
func TestListenerLockStaleRecoveryAndReplacementSafeCleanup(t *testing.T) {
	config, _ := fixture(t)
	host, err := Start(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	if duplicate, err := Start(t.Context(), config); err == nil {
		duplicate.Close()
		t.Fatal("active listener replaced")
	}
	os.Remove(config.SocketPath)
	replacement, err := net.ListenUnix("unix", &net.UnixAddr{Name: config.SocketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	replacement.SetUnlinkOnClose(false)
	defer replacement.Close()
	os.Chmod(config.SocketPath, 0600)
	before, err := os.Lstat(config.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = host.CloseContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(config.SocketPath)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("shutdown removed replacement socket", err)
	}
	replacement.Close() // Leaves genuine owner-private crash-stale inode.
	listener, release, err := listenPrivate(config.SocketPath)
	if err != nil {
		t.Fatal("genuine stale owner socket could not recover", err)
	}
	listener.Close()
	release()
}

func TestHostFiniteUnauthenticatedConnectionsAndDeadline(t *testing.T) {
	config, _ := fixture(t)
	config.MaxConnections = 1
	config.AuthTimeout = 40 * time.Millisecond
	host, err := Start(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer host.CloseContext(t.Context())
	first, err := net.Dial("unix", config.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	until := time.Now().Add(time.Second)
	for {
		host.mu.Lock()
		count := len(host.connections)
		host.mu.Unlock()
		if count == 1 {
			break
		}
		if time.Now().After(until) {
			t.Fatal("connection never reserved")
		}
		time.Sleep(time.Millisecond)
	}
	second, err := net.Dial("unix", config.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if n, err := second.Read(one[:]); err == nil || n != 0 {
		t.Fatal("unauthenticated capacity not enforced")
	}
	first.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := first.Read(one[:]); err == nil || n != 0 {
		t.Fatal("silent peer retained socket beyond authentication deadline")
	}
}
func TestPrivateListenerRefusesUntrustedPaths(t *testing.T) {
	config, _ := fixture(t)
	if err := os.WriteFile(config.SocketPath, []byte("not a socket"), 0600); err != nil {
		t.Fatal(err)
	}
	if listener, release, err := listenPrivate(config.SocketPath); err == nil {
		listener.Close()
		release()
		t.Fatal("ordinary file removed as stale socket")
	}
	os.Remove(config.SocketPath)
	target := filepath.Join(filepath.Dir(config.SocketPath), "target")
	if err := os.WriteFile(target, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, config.SocketPath); err != nil {
		t.Fatal(err)
	}
	if listener, release, err := listenPrivate(config.SocketPath); err == nil {
		listener.Close()
		release()
		t.Fatal("socket symlink accepted")
	}
	os.Remove(config.SocketPath)
	if err := os.Chmod(filepath.Dir(config.SocketPath), 0755); err != nil {
		t.Fatal(err)
	}
	if listener, release, err := listenPrivate(config.SocketPath); err == nil {
		listener.Close()
		release()
		t.Fatal("nonprivate parent accepted")
	}
}

// The wire selectors are deliberately absent: trusted kernel classification,
// not the claimed mode, must distinguish a managed child from an owner.
func TestManagedChildOwnerDowngradeHelper(t *testing.T) {
	if os.Getenv("PAGNET_TEST_OWNER_DOWNGRADE") != "1" {
		return
	}
	var ready [1]byte
	if _, err := io.ReadFull(os.Stdin, ready[:]); err != nil {
		os.Exit(2)
	}
	auth, err := FromEnvironment(os.Getenv)
	if err != nil || auth.Mode != "owner" {
		os.Exit(3)
	}
	conn, _, err := Dial(context.Background(), os.Getenv("PAGNET_TEST_OWNER_SOCKET"), auth)
	if err == nil {
		conn.Close()
		os.Exit(4)
	}
	os.Exit(0)
}
func TestManagedKernelChildCannotOmitSelectorsToBecomeOwner(t *testing.T) {
	config, store := fixture(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(exe, "-test.run=^TestManagedChildOwnerDowngradeHelper$")
	for _, item := range os.Environ() {
		omit := false
		for _, name := range []string{EndpointEnvironment, WorkerEnvironment, GenerationEnvironment, NonceEnvironment} {
			if strings.HasPrefix(item, name+"=") {
				omit = true
			}
		}
		if !omit {
			child.Env = append(child.Env, item)
		}
	}
	child.Env = append(child.Env, "PAGNET_TEST_OWNER_DOWNGRADE=1", "PAGNET_TEST_OWNER_SOCKET="+config.SocketPath)
	input, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { input.Close(); _ = child.Process.Kill() }()
	native, err := localpeer.ReadProcess(child.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := localpeer.ReadProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	var denied atomic.Int32
	root := store.AuthorityIdentity()
	authority, err := fabricauth.New(fabricauth.Config{
		Root: root, RootOwner: root.Owner, Audience: root.Namespace, SocketPath: config.SocketPath, CurrentRoot: store.CurrentAuthorityIdentity,
		ManagedValidator: func(context.Context, fabricauth.ManagedPeer) (fabric.Principal, error) {
			return fabric.Principal{}, failure()
		},
		OwnerValidator: func(_ context.Context, peer localpeer.ProcessSnapshot) error {
			if peer == owner {
				return nil
			}
			live, e := localpeer.ReadProcess(native.PID)
			if e == nil && live == native && localpeer.VerifyProcessTree(peer.PID, native.PID, native.UID, localpeer.ReadProcess) == nil {
				denied.Add(1)
			}
			return failure()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	config.Authority = authority
	host, err := Start(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer host.CloseContext(t.Context())
	conn, _, err := Dial(t.Context(), config.SocketPath, Authentication{Type: "fabric.auth", Mode: "owner"})
	if err != nil {
		t.Fatal("independent owner denied", err)
	}
	conn.Close()
	if _, err = input.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	input.Close()
	if err = child.Wait(); err != nil {
		t.Fatal("managed selector omission gained owner access or fixture failed", err)
	}
	if denied.Load() != 1 {
		t.Fatal("trusted native process classification was not used")
	}
}

func TestManagedResolverRequiresTrustedOwnerClassification(t *testing.T) {
	config, _ := fixture(t)
	config.ResolveManaged = func(context.Context, ManagedSelector) (fabricauth.Activation, error) {
		return fabricauth.Activation{}, failure()
	}
	if host, err := Start(t.Context(), config); err == nil {
		host.Close()
		t.Fatal("managed enabled with owner-only authority")
	}
	if _, err := os.Lstat(config.SocketPath); !os.IsNotExist(err) {
		t.Fatal("denied configuration created listener")
	}
}
