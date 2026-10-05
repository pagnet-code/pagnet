//go:build linux || darwin

package agentbridge

// The ACCEPT path of the sideport chain, over the real production code:
//
//   - a REAL node host (fabrichost listener + the fabricauth hosted chain
//     with the kernel ownership check + a real node Service over a genuine
//     registry) on a private 0700 socket. The test process IS the kernel
//     root the hosted activation pins (RootPID = self), so the production
//     VerifyOwned ancestry check is exercised for real (at 0 hops) — no
//     fake pre-authed client, no stubbed listener;
//   - the real daemon bridge protocol on a real socket (nonce-validating),
//     advertising the sideport in auth_ok exactly where the daemon puts it;
//   - the ACTUAL RunBridge in process, driven over real pipes in place of
//     the endpoint's stdio (the subprocess leg — daemon-rendered config,
//     spawn, per-activation nonce — is covered by the daemon e2e).
//
// Asserts: a fresh MCP client sees the ORIGINAL direct tools AND the node's
// three canonical tools on the live server (both sets, merged); the
// capabilities stay honest (no tools/list_changed claim, explicit refresh
// instructions); and when the bridge ends (stdin EOF) the node's hosted
// session ends WITH it — the secondary client is closed with the bridge
// lifetime.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
	"github.com/pagnet-code/pagnet/internal/fabricmcp"
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
)

// sessionTracker wraps the node server and records when a served session
// ENDS: the observable effect of the bridge closing its node client (the
// node's session handler returns on the client-side close).
type sessionTracker struct {
	inner fabrichost.VerifiedSessionServer
	mu    sync.Mutex
	ended int
}

func (s *sessionTracker) ServeVerified(ctx context.Context, c net.Conn, r io.Reader, f fabricmcp.SessionFactory) error {
	err := s.inner.ServeVerified(ctx, c, r, f)
	s.mu.Lock()
	s.ended++
	s.mu.Unlock()
	return err
}

func (s *sessionTracker) CloseContext(ctx context.Context) error { return s.inner.CloseContext(ctx) }

func (s *sessionTracker) Ended() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ended
}

func TestRunBridgeSideportAttachesNodeToolsAndClosesWithBridge(t *testing.T) {
	ctx := t.Context()
	const (
		instanceID = "run-bridge-instance"
		generation = "gen-run"
		nonce      = "nonce-run"
	)

	private, err := os.MkdirTemp("", "pgn-run-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(private) })
	nodeSocket := filepath.Join(private, "node.sock")

	// A genuine local installation (0700) + the exact registered endpoint
	// the sideport advertises (stable, non-offer, with the hosted-native
	// binding), and a real owner session as the registry caller.
	installation, err := localinstallation.Bootstrap(ctx, filepath.Join(private, "local"), localinstallation.Options{Settings: localinstallation.DefaultSettings(nodeSocket)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { installation.Close() })
	owner, err := installation.Operator(ctx)
	if err != nil {
		t.Fatal(err)
	}
	store := installation.Store
	root := store.AuthorityIdentity()
	ref, err := fabric.NewEndpointRef(root.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := fabric.EndpointDescriptor{
		Ref: ref, Kind: "actor.agent", Name: "RunBridge", Description: "Sideport run-bridge target",
		Bindings: []fabric.BindingSummary{{ID: "original", Protocol: "pagnet.agent.hosted-native.v1", Version: "1"}},
	}
	revision, err := store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: descriptor})
	if err != nil {
		t.Fatal(err)
	}
	principal := fabric.Principal{Ref: ref.String(), Kind: descriptor.Kind, Issuer: root.Namespace}
	cloudScope, err := nativeauthority.NewCloudScope(nativeauthority.CloudScope{
		ServerURL: "https://app.pagnet.dev", TenantID: "tenant-run", AccountID: "account-run",
		HostID: "host-run", InstanceID: instanceID, Generation: generation,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The kernel root the hosted activation pins: the test process itself —
	// the real dialer, verified by the production ownership check.
	self, err := localpeer.ReadProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	ownerGate := func(_ context.Context, peer localpeer.ProcessSnapshot) error {
		if peer != self {
			return errors.New("local managed owner denied")
		}
		return nil
	}
	validateNodeHosted := func(_ context.Context, peer fabricauth.HostedPeer) (fabric.Principal, error) {
		a := peer.Activation
		if peer.Root.Namespace != root.Namespace || peer.Root.StoreID != root.StoreID || peer.Root.KeyRevision != root.KeyRevision || peer.Root.Owner != root.Owner {
			return fabric.Principal{}, errors.New("node: root identity mismatch")
		}
		if a.Scope != cloudScope || a.Endpoint != ref || a.DescriptorRevision != revision || a.BindingID != "original" || a.NativeGeneration != generation || a.Nonce != nonce {
			return fabric.Principal{}, errors.New("node: activation does not match the selected binding")
		}
		return principal, nil
	}
	// HostedFacts is composed from the signed retained profile in the real
	// node composition; this lifecycle test exercises tools/list and the
	// session lifetime, and fails closed if the node ever demands it.
	hostedNodeFacts := func(context.Context, fabricauth.HostedPeer) (*fabricauth.HostedCallerAuthority, error) {
		return nil, errors.New("node: hosted facts are not composed in this lifecycle test")
	}
	resolveNodeHosted := func(_ context.Context, sel fabrichost.HostedSelector) (fabricauth.HostedActivation, error) {
		if sel.Endpoint != ref || sel.InstanceID != instanceID || sel.Generation != generation || sel.Nonce != nonce {
			return fabricauth.HostedActivation{}, errors.New("node: instance not bound to the selected binding")
		}
		return fabricauth.HostedActivation{
			Scope: cloudScope, Endpoint: ref, DescriptorRevision: revision, BindingID: "original",
			RootPID: self.PID, StartIdentity: strconv.FormatInt(self.Start, 10),
			Nonce: sel.Nonce, NativeGeneration: sel.Generation, NativeSessionID: "native-session-run",
		}, nil
	}
	auth, err := fabricauth.New(fabricauth.Config{
		Root: root, RootOwner: root.Owner, Audience: root.Namespace, SocketPath: nodeSocket,
		CurrentRoot:     store.CurrentAuthorityIdentity,
		HostedValidator: validateNodeHosted,
		HostedFacts:     hostedNodeFacts,
		OwnerValidator:  ownerGate,
	})
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
	canonical, err := fabricmcp.New(fabricmcp.Config{Executor: n})
	if err != nil {
		t.Fatal(err)
	}
	tracker := &sessionTracker{inner: canonical}
	host, err := fabrichost.Start(ctx, fabrichost.Config{SocketPath: nodeSocket, Authority: auth, Server: tracker, ResolveHosted: resolveNodeHosted})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.CloseContext(context.Background()) })

	// The daemon side: the real bridge protocol, nonce-validating, with the
	// sideport in the authenticated auth_ok.
	spRaw, err := json.Marshal(HostedFabricSideport{Socket: nodeSocket, Endpoint: ref, Generation: generation})
	if err != nil {
		t.Fatal(err)
	}
	bridgeSocket := sideportTestServer(t, nonce, string(spRaw))

	// The bridge's own credentials, as the daemon injects them.
	t.Setenv("PAGNET_INSTANCE_ID", instanceID)
	t.Setenv("PAGNET_BRIDGE_NONCE", nonce)
	t.Setenv("PAGNET_NETWORK_ID", "")

	// Real pipes in place of the endpoint's stdio (RunBridge serves MCP on
	// os.Stdin/os.Stdout, exactly as the spawned subprocess does).
	realStdin, realStdout := os.Stdin, os.Stdout
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		inW.Close()
		t.Fatal(err)
	}
	os.Stdin, os.Stdout = inR, outW
	t.Cleanup(func() {
		os.Stdin, os.Stdout = realStdin, realStdout
		_ = inW.Close()
		_ = outR.Close()
	})

	errc := make(chan error, 1)
	go func() {
		errc <- RunBridge(bridgeSocket, "pagnet", "worker", func(s *server.MCPServer, br *Bridge) {
			RegisterWorkerTools(s, br)
		})
	}()

	// ONE persistent reader: a fresh bufio.Reader per call would discard
	// bytes the server already flushed into its buffer.
	out := bufio.NewReader(outR)
	mcpLine := func() []byte {
		t.Helper()
		_ = outR.SetReadDeadline(time.Now().Add(30 * time.Second))
		line, err := out.ReadString('\n')
		if err != nil {
			t.Fatalf("mcp stdio read: %v", err)
		}
		return []byte(strings.TrimRight(line, "\r\n"))
	}
	write := func(v any) {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := inW.Write(append(b, '\n')); err != nil {
			t.Fatalf("mcp stdio write: %v", err)
		}
	}

	// MCP handshake against the LIVE server (the fresh-client view).
	write(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "sideport-run-test", "version": "1.0.0"},
		},
	})
	initLine := mcpLine()
	var initResp struct {
		Result struct {
			Capabilities struct {
				Tools struct {
					ListChanged *bool `json:"listChanged"`
				} `json:"tools"`
			} `json:"capabilities"`
			ServerInfo   struct {
				Name string `json:"name"`
			} `json:"serverInfo"`
			Instructions string `json:"instructions"`
		} `json:"result"`
	}
	if err := json.Unmarshal(initLine, &initResp); err != nil || initResp.Result.ServerInfo.Name != "pagnet" {
		t.Fatalf("MCP initialize = %s", initLine)
	}
	if initResp.Result.Capabilities.Tools.ListChanged != nil && *initResp.Result.Capabilities.Tools.ListChanged {
		t.Fatalf("bridge claimed tools/list_changed it does not implement: %s", initLine)
	}
	if !strings.Contains(initResp.Result.Instructions, "reconnect") {
		t.Fatalf("sideport bridge initialize lacks the explicit refresh requirement: %s", initLine)
	}
	write(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	write(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
	listLine := mcpLine()
	var listResp struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(listLine, &listResp); err != nil {
		t.Fatalf("tools/list = %s: %v", listLine, err)
	}
	names := map[string]bool{}
	for _, tool := range listResp.Result.Tools {
		names[tool.Name] = true
	}
	// BOTH sets: the original direct tools are preserved AND the node's
	// three canonical operations are attached.
	if !names["network_whoami"] {
		t.Fatalf("the original direct tools were lost in the merge: %v", names)
	}
	for _, canonical := range []string{"discover", "describe", "invoke"} {
		if !names[canonical] {
			t.Fatalf("canonical operation %q missing from the live bridge: %v", canonical, names)
		}
	}

	// The bridge ends when the runtime closes stdin: RunBridge returns and
	// its node client goes with it — the node observes the session end.
	_ = inW.Close()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("RunBridge: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("RunBridge did not return on stdin EOF")
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if tracker.Ended() >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if tracker.Ended() < 1 {
		t.Fatal("the node's hosted session survived the bridge's lifetime (client not closed)")
	}
	t.Logf("sideport accept path: %v", names)
}
