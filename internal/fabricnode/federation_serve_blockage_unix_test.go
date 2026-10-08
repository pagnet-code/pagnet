//go:build linux || darwin

package fabricnode

// Two-node blockage acceptance for the installed federation product's
// destination serving (E1 slice-2b).
//
// Node B is a REAL OpenInstalled serve path: the installed service (a stateless
// MCP HTTP provider with an atomic effect counter) is set up through the
// operator setup path, the product open connects it, and the relay listener
// serves bundle-forward bundles on its private relay socket. Node A is a real
// OpenInstalled source whose certified/pinned/link-declared forward goes over
// the unix relay socket. Every trust declaration (certify, pin, link,
// exposure) runs through the REAL private admin sockets.
//
// Accepted: the certified source's real effect executes exactly once (0→1);
// the resent bundle does not re-run (EffectUnknown); an undeclared external
// network (C), an emptied exposure, and a removed link each keep the effect
// at 0.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/adapters/mcp"
	"github.com/pagnet-code/pagnet/fabric/federation"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/mcpbridge"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabricfederation"
	"github.com/pagnet-code/pagnet/internal/fabricservices"
)

// federationServeBootstrap bootstraps a fresh installation with its admin
// socket in a private 0700 run directory, like the slice-2a fixture.
func federationServeBootstrap(t *testing.T, ctx context.Context) (dir, socket string, root registry.AuthorityIdentity) {
	t.Helper()
	parent := t.TempDir()
	socketDir := filepath.Join(parent, "run")
	if e := os.Mkdir(socketDir, 0o700); e != nil {
		t.Fatal(e)
	}
	dir = filepath.Join(parent, "authority")
	socket = filepath.Join(socketDir, "node.sock")
	installed, e := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if e != nil {
		t.Fatal(e)
	}
	root = installed.Store.AuthorityIdentity()
	if e = installed.Close(); e != nil {
		t.Fatal(e)
	}
	return dir, socket, root
}

// federationServeSetupServices installs the real MCP effect provider through
// the operator setup path (InitializeServiceState + NewServiceRuntime +
// Register + Profiles.Install + Connect with catalog bootstrap), then closes
// both runtimes. It returns the registered endpoint reference and revision.
func federationServeSetupServices(t *testing.T, ctx context.Context, dir, binary string, serverURL string, digest [32]byte) (fabric.EndpointRef, fabric.Revision) {
	t.Helper()
	setup, e := OpenInstalled(ctx, InstalledConfig{Directory: dir, Binary: binary})
	if e != nil {
		t.Fatal(e)
	}
	config := DefaultInstalledServiceConfig(serviceRouterCredentials{digest})
	if e = InitializeServiceState(ctx, setup.Installation, setup.Runtime.Boundary, config); e != nil {
		t.Fatal(e)
	}
	serviceSetup, e := NewServiceRuntime(ctx, setup.Installation, setup.Runtime.Boundary, config)
	if e != nil {
		t.Fatal(e)
	}
	owner, e := setup.Installation.Operator(ctx)
	if e != nil {
		t.Fatal(e)
	}
	ref, e := fabric.NewEndpointRef(setup.Installation.Store.AuthorityIdentity().PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	revision, e := setup.Installation.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{
		Ref:    ref,
		Kind:   "service.mcp",
		Name:   "Served effect",
		Bindings: []fabric.BindingSummary{{ID: "mcp", Protocol: "mcp.tools", Version: "2025-11-25", Cancellation: true}},
	}})
	if e != nil {
		t.Fatal(e)
	}
	scope := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: revision, BindingID: "mcp"}
	if _, e = serviceSetup.Profiles.Install(ctx, scope, fabricservices.Profile{
		Protocol: "mcp.tools", Version: "2025-11-25", CredentialSelector: "served-effect-account", BindingDigest: digest,
		MCP: &fabricservices.MCPProfile{URL: serverURL, AllowHTTP: true, Limits: mcp.DefaultLimits},
	}); e != nil {
		t.Fatal(e)
	}
	if e = serviceSetup.Connect(ctx, scope, true); e != nil {
		t.Fatal(e)
	}
	if e = serviceSetup.CloseContext(ctx); e != nil {
		t.Fatal(e)
	}
	if e = setup.CloseContext(ctx); e != nil {
		t.Fatal(e)
	}
	return ref, revision
}

// federationServeOpenProduct opens the installed serve path with the retained
// service provider and the federation surface (relay listener) enabled.
func federationServeOpenProduct(t *testing.T, ctx context.Context, dir, binary, relaySocket string, digest [32]byte) *InstalledNode {
	t.Helper()
	node, e := OpenInstalled(ctx, InstalledConfig{
		Directory:        dir,
		Binary:           binary,
		ServiceProviders: map[string]fabricservices.CredentialProvider{"operator.private": serviceRouterCredentials{digest}},
		Federation:       &InstalledFederationConfig{RelaySocket: relaySocket},
	})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = node.Close() })
	if node.relay == nil {
		t.Fatal("the federation relay listener was not composed")
	}
	// The installed service must settle (connected, no error) before serving.
	until := time.NewTimer(30 * time.Second)
	defer until.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		statuses := node.Services.Status()
		ready := len(statuses) == 1
		for _, s := range statuses {
			ready = ready && s.Connected && s.ErrorCode == ""
		}
		if ready {
			break
		}
		select {
		case <-until.C:
			t.Fatal("destination installed service did not settle", statuses)
		case <-tick.C:
		}
	}
	return node
}

// serveAdminCertify runs the real federation.peer.local-certify over the
// private admin socket and returns the certified certificate.
func serveAdminCertify(t *testing.T, call func(id, operation string, input []byte) (json.RawMessage, *fabric.Error), id string, expectedRevision uint64) fabric.SignedPeerCertificate {
	t.Helper()
	raw, e := json.Marshal(struct {
		ExpectedRevision uint64 `json:"expectedRevision"`
		ExpirySeconds    uint64 `json:"expirySeconds"`
	}{expectedRevision, 0})
	if e != nil {
		t.Fatal(e)
	}
	result, failure := call(id, "federation.peer.local-certify", raw)
	if failure != nil {
		t.Fatalf("federation.peer.local-certify: %v", failure)
	}
	var out struct {
		PublicKey   [32]byte                     `json:"publicKey"`
		KeyRevision string                       `json:"keyRevision"`
		Certificate fabric.SignedPeerCertificate `json:"certificate"`
		Digest      [32]byte                     `json:"digest"`
	}
	if e := json.Unmarshal(result, &out); e != nil {
		t.Fatalf("decode certify receipt: %v (%s)", e, result)
	}
	if fabric.VerifyPeerCertificate(out.Certificate, time.Now()) != nil {
		t.Fatal("certify returned an unverifiable certificate")
	}
	return out.Certificate
}

// serveAdminPin runs the real federation.peer.pin over the private admin socket.
func serveAdminPin(t *testing.T, call func(id, operation string, input []byte) (json.RawMessage, *fabric.Error), id string, expectedRevision uint64, owner fabric.Principal, certificate fabric.SignedPeerCertificate) {
	t.Helper()
	raw, e := json.Marshal(struct {
		ExpectedRevision uint64                       `json:"expectedRevision"`
		Owner            fabric.Principal             `json:"owner"`
		Certificate      fabric.SignedPeerCertificate `json:"certificate"`
	}{expectedRevision, owner, certificate})
	if e != nil {
		t.Fatal(e)
	}
	if _, failure := call(id, "federation.peer.pin", raw); failure != nil {
		t.Fatalf("federation.peer.pin: %v", failure)
	}
}

// serveAdminLinkPut runs the real federation.link.put over the private admin
// socket and returns the committed link revision.
func serveAdminLinkPut(t *testing.T, call func(id, operation string, input []byte) (json.RawMessage, *fabric.Error), id string, expectedRevision uint64, remoteNamespace, remoteStoreID string, channel federation.ChannelBinding, sourceRole bool) uint64 {
	t.Helper()
	raw, e := json.Marshal(struct {
		ExpectedRevision uint64 `json:"expectedRevision"`
		RemoteNamespace  string `json:"remoteNamespace"`
		RemoteStoreID    string `json:"remoteStoreId"`
		ChannelID        []byte `json:"channelId"`
		SourceRoute      []byte `json:"sourceRoute"`
		DestinationRoute []byte `json:"destinationRoute"`
		SourceRole       bool   `json:"sourceRole"`
	}{expectedRevision, remoteNamespace, remoteStoreID, channel.ID[:], channel.SourceRoute[:], channel.DestinationRoute[:], sourceRole})
	if e != nil {
		t.Fatal(e)
	}
	result, failure := call(id, "federation.link.put", raw)
	if failure != nil {
		t.Fatalf("federation.link.put: %v", failure)
	}
	var out struct {
		Link     FederationLink `json:"link"`
		Revision string         `json:"revision"`
	}
	if e := json.Unmarshal(result, &out); e != nil {
		t.Fatalf("decode link receipt: %v (%s)", e, result)
	}
	return parseServeRevision(t, out.Revision)
}

// serveAdminLinkRemove runs the real federation.link.remove.
func serveAdminLinkRemove(t *testing.T, call func(id, operation string, input []byte) (json.RawMessage, *fabric.Error), id string, expectedRevision uint64, channelID [32]byte) {
	t.Helper()
	raw, e := json.Marshal(struct {
		ExpectedRevision uint64 `json:"expectedRevision"`
		ChannelID        []byte `json:"channelId"`
	}{expectedRevision, channelID[:]})
	if e != nil {
		t.Fatal(e)
	}
	if _, failure := call(id, "federation.link.remove", raw); failure != nil {
		t.Fatalf("federation.link.remove: %v", failure)
	}
}

// serveAdminExposurePut runs the real federation.exposure.put.
func serveAdminExposurePut(t *testing.T, call func(id, operation string, input []byte) (json.RawMessage, *fabric.Error), id string, expectedRevision uint64, exposures []FederationExposure) uint64 {
	t.Helper()
	raw, e := json.Marshal(struct {
		ExpectedRevision uint64               `json:"expectedRevision"`
		Exposures        []FederationExposure `json:"exposures"`
	}{expectedRevision, exposures})
	if e != nil {
		t.Fatal(e)
	}
	result, failure := call(id, "federation.exposure.put", raw)
	if failure != nil {
		t.Fatalf("federation.exposure.put: %v", failure)
	}
	var out struct {
		Revision uint64 `json:"revision"`
	}
	if e := json.Unmarshal(result, &out); e != nil {
		t.Fatalf("decode exposure receipt: %v (%s)", e, result)
	}
	return out.Revision
}

func parseServeRevision(t *testing.T, revision string) uint64 {
	t.Helper()
	var value uint64
	if e := json.Unmarshal([]byte(revision), &value); e != nil {
		t.Fatalf("decode revision %q: %v", revision, e)
	}
	return value
}

// federationServeSource is the source node's actual forward composition: the
// owner-authenticated kernel session (peer credentials over a test-owned unix
// socket), the certified local peer, the explicitly pinned remote peer, and
// the per-pair trust gate.
type federationServeSource struct {
	t         *testing.T
	node      *InstalledNode
	owner     fabric.ExecutionContext
	authority *fabricauth.Authority
	session   *fabricauth.Session
	local     registry.CertifiedPeer
	remote    registry.CertifiedPeer
	gate      *fabricfederation.PeerGate
}

// openFederationSource composes the source forward state. The node must
// already be admin-certified; the remote peer must already be pinned. The
// owner session binds a test-owned unix socket (the node's own admin socket is
// held by the host); kernel peer credentials are unchanged.
func openFederationSource(t *testing.T, ctx context.Context, node *InstalledNode, remoteNamespace, remoteStoreID string) *federationServeSource {
	t.Helper()
	sourceDir, e := os.MkdirTemp("", "pgn-federation-serve-source-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(sourceDir) })
	owner, e := node.Installation.Operator(ctx)
	if e != nil {
		t.Fatal(e)
	}
	local, e := node.Federation.Peers.Local(ctx, owner)
	if e != nil {
		t.Fatal(e)
	}
	remote, e := node.Federation.Peers.Remote(ctx, owner, remoteNamespace, remoteStoreID)
	if e != nil {
		t.Fatal(e)
	}
	gate, e := fabricfederation.New(ctx, fabricfederation.Config{
		Peers: node.Federation.Peers, Owner: node.Installation.Operator, Local: local, Remote: remote,
	})
	if e != nil {
		t.Fatal(e)
	}
	authSocket := filepath.Join(sourceDir, "owner.sock")
	authority, e := fabricauth.New(fabricauth.Config{
		Root: local.Authority, RootOwner: local.Authority.Owner, Audience: local.Authority.Namespace,
		SocketPath: authSocket, CurrentRoot: node.Installation.Store.CurrentAuthorityIdentity,
	})
	if e != nil {
		t.Fatal(e)
	}
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: authSocket, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { listener.Close() })
	if e = os.Chmod(authSocket, 0o600); e != nil {
		t.Fatal(e)
	}
	peerConn, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: authSocket, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { peerConn.Close() })
	conn, e := listener.AcceptUnix()
	if e != nil {
		t.Fatal(e)
	}
	session, e := authority.BindOwner(ctx, conn)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { session.Close() })
	return &federationServeSource{t: t, node: node, owner: owner, authority: authority, session: session, local: local, remote: remote, gate: gate}
}

// buildForwardBundle builds, authenticates and signs one real bundle-forward
// envelope + source-root proof through the source's actual kernel session and
// retained root signer, targeting the destination's exposed offer.
func (s *federationServeSource) buildForwardBundle(ctx context.Context, target fabric.EndpointRef, expectedRevision fabric.Revision, input json.RawMessage, replayID string) federation.ForwardBundle {
	t := s.t
	t.Helper()
	original, evidence, e := s.session.Build(ctx, mcpbridge.Call{Operation: fabric.OperationInvoke, Invoke: &fabric.InvokeRequest{
		Target: target, ExpectedRevision: expectedRevision, Input: input,
	}})
	if e != nil {
		t.Fatalf("source session build: %v", e)
	}
	caller, e := s.authority.Authenticate(ctx, fabric.AuthenticationRequest{ExactEnvelope: original, Audience: s.local.Authority.Namespace, PeerEvidence: evidence})
	if e != nil {
		t.Fatalf("source authenticate: %v", e)
	}
	var env fabric.Envelope
	if e = fabric.DecodeJSON(original, &env); e != nil {
		t.Fatalf("decode original envelope: %v", e)
	}
	old := env.Context
	env.Context.Hops++
	forwarded, e := json.Marshal(env)
	if e != nil {
		t.Fatal(e)
	}
	localBinding, e := fabricfederation.Binding(s.local)
	if e != nil {
		t.Fatalf("local binding: %v", e)
	}
	remoteBinding, e := fabricfederation.Binding(s.remote)
	if e != nil {
		t.Fatalf("remote binding: %v", e)
	}
	provenance := func(c fabric.EnvelopeContext) fabric.Provenance {
		return fabric.Provenance{Origin: c.Origin, ParentID: c.ParentID, Ancestry: c.Ancestry, Hops: c.Hops, ExtensionChain: c.ExtensionChain, TriggerLineage: c.TriggerLineage}
	}
	now := time.Now().UTC()
	deadline := ""
	if env.Context.Deadline != nil {
		deadline = env.Context.Deadline.Format(time.RFC3339Nano)
	}
	frame := fabric.ForwardFrame{
		SourceDomain:                 s.local.Authority.Namespace,
		SourceStoreID:                s.local.Authority.StoreID,
		SourceKeyRevision:            s.local.Authority.KeyRevision,
		DestinationDomain:            s.remote.Authority.Namespace,
		DestinationStoreID:           s.remote.Authority.StoreID,
		SourcePeerBindingDigest:      localBinding.BindingDigest,
		DestinationPeerBindingDigest: remoteBinding.BindingDigest,
		Principal:                    caller.PrincipalView(),
		Operation:                    env.Operation,
		Target:                       env.Target,
		ExpectedRevision:             env.ExpectedRevision,
		InvocationID:                 env.ID,
		ReplayID:                     replayID,
		OriginalEnvelopeDigest:       sha256.Sum256(original),
		ForwardedEnvelopeDigest:      sha256.Sum256(forwarded),
		OriginalProvenance:           provenance(old),
		ForwardedProvenance:          provenance(env.Context),
		IssuedAt:                     now.Format(time.RFC3339Nano),
		ExpiresAt:                    now.Add(30 * time.Second).Format(time.RFC3339Nano),
		Deadline:                     deadline,
		BindingProfile:               federation.Profile,
	}
	forwardGate, e := NewSourceForwardGate(s.gate, s.authority, caller)
	if e != nil {
		t.Fatalf("source forward gate: %v", e)
	}
	proof, e := s.node.Installation.Store.SignForwardExact(ctx, s.owner, caller, original, forwarded, frame, forwardGate)
	if e != nil {
		t.Fatalf("source root signer: %v", e)
	}
	return federation.ForwardBundle{Proof: proof, Original: original, Forwarded: forwarded}
}

// serveSourceConfig composes the source's real forward transport config over
// the node's actual sealed exchange key and the per-pair trust gate.
func serveSourceConfig(t *testing.T, node *InstalledNode, source *federationServeSource, channel federation.ChannelBinding) federation.Config {
	t.Helper()
	localBinding, e := fabricfederation.Binding(source.local)
	if e != nil {
		t.Fatalf("source local binding: %v", e)
	}
	remoteBinding, e := fabricfederation.Binding(source.remote)
	if e != nil {
		t.Fatalf("source remote binding: %v", e)
	}
	return federation.Config{
		Local: localBinding, Remote: remoteBinding,
		Keys: node.Federation.ExchangeKeys, Trust: source.gate,
		Channel: channel, SourceRole: true, MaxRecords: federationServingMaxRecords,
	}
}

// sendForwardBundle dials the destination relay socket and sends the bundle
// through a real HPKE forward transport (a fresh encapsulation per
// connection). The error is the transport outcome only; a destination that
// refuses the channel may reset the connection mid-bundle.
func sendForwardBundle(ctx context.Context, relaySocket string, sourceCfg federation.Config, bundle federation.ForwardBundle) error {
	conn, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: relaySocket, Net: "unix"})
	if e != nil {
		return e
	}
	defer conn.Close()
	stream, e := federation.NewConnStream(conn, federationServingConnLifetime)
	if e != nil {
		return e
	}
	duplex, e := federation.NewDuplex(ctx, sourceCfg, stream, federationServingMaxBytes)
	if e != nil {
		_ = duplex.Close()
		return e
	}
	channel, e := federation.NewForwardChannel(duplex)
	if e != nil {
		_ = duplex.Close()
		return e
	}
	defer channel.Close()
	return channel.SendBundle(ctx, bundle)
}

// serveGeneration reports the relay's current result generation for a channel
// (0 when none was recorded yet).
func serveGeneration(relay *federationRelay, channel [32]byte) uint64 {
	_, generation, _ := relay.latestResult(channel)
	return generation
}

// waitServeResult polls the destination relay's retained start result until
// its generation advances past the snapshot. Bundle-forward sends no wire
// response; the relay's own retained result is the honest observation.
func waitServeResult(t *testing.T, ctx context.Context, relay *federationRelay, channel [32]byte, before uint64) FederationStart {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		start, generation, ok := relay.latestResult(channel)
		if ok && generation > before {
			return start
		}
		if time.Now().After(deadline) {
			t.Fatalf("the relay recorded no serving result (generation %d, ok %v)", generation, ok)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// assertNoServeResult asserts that no serving result was recorded for the
// channel within the window: the relay closed the connection before any
// execution could start.
func assertNoServeResult(t *testing.T, relay *federationRelay, channel [32]byte, before uint64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		start, generation, ok := relay.latestResult(channel)
		if ok && generation > before {
			t.Fatalf("the relay recorded an unexpected serving result: %+v", start)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestFederationServeBlockageTwoNodes(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}

	// The destination's real paid effect: a stateless MCP HTTP provider with
	// an atomic effect counter.
	var effects atomic.Int32
	provider := sdk.NewServer(&sdk.Implementation{Name: "served-effect", Version: "1"}, &sdk.ServerOptions{SupportedProtocolVersions: []string{"2025-11-25"}})
	provider.AddTool(&sdk.Tool{Name: "count", Description: "Count one served effect", InputSchema: json.RawMessage(`{"type":"object"}`)}, func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		effects.Add(1)
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "counted"}}}, nil
	})
	server := httptest.NewServer(sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return provider }, &sdk.StreamableHTTPOptions{Stateless: true}))
	defer server.Close()

	// ---- Node B: the destination (real installed serve path). ----
	digestB := [32]byte{0xB0}
	dirB, socketB, rootB := federationServeBootstrap(t, ctx)
	refB, revB := federationServeSetupServices(t, ctx, dirB, binary, server.URL, digestB)
	relayB := filepath.Join(filepath.Dir(socketB), "federation.sock")
	nodeB := federationServeOpenProduct(t, ctx, dirB, binary, relayB, digestB)

	// ---- Node A: the source (real installed serve path). ----
	dirA, socketA, rootA := federationServeBootstrap(t, ctx)
	nodeA, e := OpenInstalled(ctx, InstalledConfig{Directory: dirA, Binary: binary, Federation: &InstalledFederationConfig{}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = nodeA.Close() })

	// ---- Trust + link + exposure declarations, all through the REAL private
	// admin sockets. ----
	callA := dialAdmin(t, ctx, socketA)
	callB := dialAdmin(t, ctx, socketB)

	certA := serveAdminCertify(t, callA, "serve-a-certify", 0)
	certB := serveAdminCertify(t, callB, "serve-b-certify", 0)
	serveAdminPin(t, callA, "serve-a-pin-b", 0, rootB.Owner, certB)
	serveAdminPin(t, callB, "serve-b-pin-a", 0, rootA.Owner, certA)

	// The shared channel + distinct receiver routes, declared on both nodes
	// (B as the destination link, A as the source link).
	channelAB := federation.ChannelBinding{
		ID:               [32]byte{0x42, 0x01},
		SourceRoute:      [32]byte{0x43, 0x01},
		DestinationRoute: [32]byte{0x44, 0x01},
	}
	linkBRevision := serveAdminLinkPut(t, callB, "serve-b-link", 0, rootA.Namespace, rootA.StoreID, channelAB, false)
	serveAdminLinkPut(t, callA, "serve-a-link", 0, rootB.Namespace, rootB.StoreID, channelAB, true)

	// B publishes the exact offer view to A's domain.
	offers, _, e := nodeB.Installation.Store.ListOffers(ctx, refB, revB, "", 8)
	if e != nil || len(offers) != 1 {
		t.Fatalf("destination offer listing: %v (%d offers)", e, len(offers))
	}
	offerB := offers[0]
	exposureB := []FederationExposure{{RemoteDomain: rootA.Namespace, Target: offerB.Ref, Revision: offerB.Revision, BindingID: "mcp"}}
	exposureRevision := serveAdminExposurePut(t, callB, "serve-b-exposure", 0, exposureB)
	if exposureRevision == 0 {
		t.Fatal("the exposure declaration was not committed")
	}

	source := openFederationSource(t, ctx, nodeA, rootB.Namespace, rootB.StoreID)
	sourceCfg := serveSourceConfig(t, nodeA, source, channelAB)

	// ---- Positive: the certified source's real effect executes exactly once.
	bundle := source.buildForwardBundle(ctx, offerB.Ref, offerB.Revision, json.RawMessage(`{"n":1}`), "serve-positive")
	before := serveGeneration(nodeB.relay, channelAB.ID)
	if e = sendForwardBundle(ctx, relayB, sourceCfg, bundle); e != nil {
		t.Fatalf("send positive bundle: %v", e)
	}
	started := waitServeResult(t, ctx, nodeB.relay, channelAB.ID, before)
	if started.Error != nil {
		t.Fatalf("serving start: %v", started.Error)
	}
	if started.Association == nil {
		t.Fatal("serving start returned no final output association")
	}
	if got := effects.Load(); got != 1 {
		t.Fatalf("served effects = %d; want 1 (effect 0->1 once)", got)
	}

	// ---- Resend: the exact same bundle never reruns the paid effect.
	before = serveGeneration(nodeB.relay, channelAB.ID)
	if e = sendForwardBundle(ctx, relayB, sourceCfg, bundle); e != nil {
		t.Fatalf("send resent bundle: %v", e)
	}
	started = waitServeResult(t, ctx, nodeB.relay, channelAB.ID, before)
	if started.Error == nil {
		t.Fatal("the resent bundle was accepted as a fresh execution")
	}
	var typed *fabric.Error
	if !errors.As(started.Error, &typed) {
		t.Fatalf("resent bundle outcome %v is not a structured fabric error", started.Error)
	}
	if typed.Effect != fabric.EffectUnknown {
		t.Fatalf("resent bundle effect = %v; want EffectUnknown", typed.Effect)
	}
	if typed.Code != "federation.RETAINED_EXECUTION" && typed.Code != "federation.EXECUTION_UNKNOWN" {
		t.Fatalf("resent bundle code = %q; want a retained-execution code", typed.Code)
	}
	if got := effects.Load(); got != 1 {
		t.Fatalf("the resent bundle reran the paid effect (%d effects)", got)
	}

	// ---- Blockage 1: an undeclared external network (C) cannot serve on B.
	// C is a real third installation: it certifies itself and pins B through
	// its OWN real admin socket, but B declares no link for C's channel and no
	// exposure for C's domain.
	dirC, socketC, _ := federationServeBootstrap(t, ctx)
	nodeC, e := OpenInstalled(ctx, InstalledConfig{Directory: dirC, Binary: binary, Federation: &InstalledFederationConfig{}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = nodeC.Close() })
	callC := dialAdmin(t, ctx, socketC)
	_ = serveAdminCertify(t, callC, "serve-c-certify", 0)
	serveAdminPin(t, callC, "serve-c-pin-b", 0, rootB.Owner, certB)
	sourceC := openFederationSource(t, ctx, nodeC, rootB.Namespace, rootB.StoreID)
	channelC := federation.ChannelBinding{
		ID:               [32]byte{0xC1, 0x01},
		SourceRoute:      [32]byte{0xC2, 0x01},
		DestinationRoute: [32]byte{0xC3, 0x01},
	}
	sourceCfgC := serveSourceConfig(t, nodeC, sourceC, channelC)
	bundleC := sourceC.buildForwardBundle(ctx, offerB.Ref, offerB.Revision, json.RawMessage(`{"n":2}`), "serve-external")
	before = serveGeneration(nodeB.relay, channelC.ID)
	// The relay may reset the connection once its first-packet lookup finds no
	// link; the guarantee is that nothing executes.
	_ = sendForwardBundle(ctx, relayB, sourceCfgC, bundleC)
	assertNoServeResult(t, nodeB.relay, channelC.ID, before)
	if got := effects.Load(); got != 1 {
		t.Fatalf("undeclared external network executed an effect (%d effects)", got)
	}

	// ---- Blockage 2: the exposed target is no longer published.
	exposureRevision = serveAdminExposurePut(t, callB, "serve-b-exposure-empty", exposureRevision, nil)
	before = serveGeneration(nodeB.relay, channelAB.ID)
	bundle2 := source.buildForwardBundle(ctx, offerB.Ref, offerB.Revision, json.RawMessage(`{"n":3}`), "serve-blocked-exposure")
	if e = sendForwardBundle(ctx, relayB, sourceCfg, bundle2); e != nil {
		t.Fatalf("send empty-exposure bundle: %v", e)
	}
	started = waitServeResult(t, ctx, nodeB.relay, channelAB.ID, before)
	if started.Error == nil {
		t.Fatal("an emptied exposure admitted a fresh dispatch")
	}
	if got := effects.Load(); got != 1 {
		t.Fatalf("an emptied exposure executed an effect (%d effects)", got)
	}

	// ---- Blockage 3: the link is gone even with the exposure restored.
	exposureRevision = serveAdminExposurePut(t, callB, "serve-b-exposure-restore", exposureRevision, exposureB)
	serveAdminLinkRemove(t, callB, "serve-b-link-remove", linkBRevision, channelAB.ID)
	before = serveGeneration(nodeB.relay, channelAB.ID)
	bundle3 := source.buildForwardBundle(ctx, offerB.Ref, offerB.Revision, json.RawMessage(`{"n":4}`), "serve-blocked-link")
	_ = sendForwardBundle(ctx, relayB, sourceCfg, bundle3)
	assertNoServeResult(t, nodeB.relay, channelAB.ID, before)
	if got := effects.Load(); got != 1 {
		t.Fatalf("a removed link executed an effect (%d effects)", got)
	}

	if got := effects.Load(); got != 1 {
		t.Fatalf("final served effects = %d; want exactly 1", got)
	}
}
