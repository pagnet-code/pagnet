//go:build linux || darwin

package daemon

// Phase A step 3 — the actual worker sideport.
//
// Test 1 pins the genuine owner-administration association on the step-2
// fixture: the daemon re-derives the EXACT installed profile through the
// node's selected-binding resolve port, re-probes the genuine original
// worker, and stores (or refuses) the {socket, stable endpoint, original
// generation} triple.
//
// Test 2 is the real topologies e2e: a REAL node host (real registry,
// real fabricauth hosted chain over the fixture's genuine installation
// and live native worker — the node-side glue mirrors exactly the
// production wiring, because this package cannot import fabricnode: it
// imports the daemon, and a test import would cycle) listens on a
// private socket; the owner-administration association is advertised ONLY
// in the daemon's authenticated bridge handshake; a REAL bridge
// subprocess (the daemon-rendered pagnet worker spawned by a live
// fake-persistent endpoint) consumes it from its own auth_ok, attempts
// the hosted dial with its own nonce/instance, and — the node correctly
// refusing a bridge whose instance is not the associated original
// worker — serves its original tools alongside an explicit stderr error
// (the verified transition: old direct tools preserved, honest
// capabilities, actionable refresh).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/internal/agentbridge"
	"github.com/pagnet-code/pagnet/internal/fabricagent"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
	"github.com/pagnet-code/pagnet/internal/fabricmcp"
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"github.com/pagnet-code/pagnet/transport"
)

// hostedNativeBindingProtocol mirrors the node's explicit original-worker
// binding protocol (the value the fixture registers under the id
// "original").
const hostedNativeBindingProtocol = "pagnet.agent.hosted-native.v1"

// hostedNativeResolvePort mirrors the fixture's node selected-binding
// wiring: the exact registered descriptor, its hosted-native binding and
// the installed profile — never a value taken from a caller.
func (f *hostedGuardFixture) hostedNativeResolvePort(ctx context.Context, instanceID string) (registry.DescriptorBatchScope, fabricagent.HostedProfile, error) {
	descriptor, err := f.installation.Store.GetEndpoint(ctx, f.ref, f.revision)
	if err != nil {
		return registry.DescriptorBatchScope{}, fabricagent.HostedProfile{}, err
	}
	binding := ""
	for _, b := range descriptor.Bindings {
		if b.Protocol == hostedNativeBindingProtocol {
			if binding != "" {
				return registry.DescriptorBatchScope{}, fabricagent.HostedProfile{}, errors.New("ambiguous hosted binding")
			}
			binding = b.ID
		}
	}
	if binding == "" {
		return registry.DescriptorBatchScope{}, fabricagent.HostedProfile{}, errors.New("no hosted native binding")
	}
	scope := registry.DescriptorBatchScope{Endpoint: f.ref, ExpectedEndpointRevision: descriptor.Revision, BindingID: binding}
	profile, _, err := f.profiles.Get(ctx, scope)
	if err != nil {
		return scope, fabricagent.HostedProfile{}, err
	}
	if profile.Scope.InstanceID != instanceID {
		return scope, fabricagent.HostedProfile{}, errors.New("instance not bound to the selected binding")
	}
	return scope, profile, nil
}

func TestAssociateHostedFabricSideport_GenuineOwnerAdministration(t *testing.T) {
	f := newHostedGuardFixture(t)
	ctx := t.Context()
	d := f.d
	d.HostedFabricSideports = NewHostedFabricSideports(f.hostedNativeResolvePort)
	if d.HostedFabricSideports == nil {
		t.Fatal("resolve port present: composition must exist")
	}
	if got := NewHostedFabricSideports(nil); got != nil {
		t.Fatal("nil resolve port must yield nil (no invented authority)")
	}

	nodeDir, err := os.MkdirTemp("", "pgn-sideport-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(nodeDir) })
	sp := agentbridge.HostedFabricSideport{
		Socket:     filepath.Join(nodeDir, "node.sock"),
		Endpoint:   f.ref,
		Generation: f.profile.Scope.Generation,
	}

	// The genuine association: exact profile from the resolve port,
	// endpoint + generation byte-matched, genuine worker re-probed.
	if err := d.AssociateHostedFabricSideport(ctx, f.profile.Scope.InstanceID, sp); err != nil {
		t.Fatalf("genuine owner administration refused: %v", err)
	}
	if got, ok := d.HostedFabricSideports.For(f.profile.Scope.InstanceID); !ok || got != sp {
		t.Fatalf("association = %+v ok=%v, want the exact stored triple", got, ok)
	}

	// Wrong original generation: refused, the stored triple untouched.
	badGen := sp
	badGen.Generation = "other-generation"
	if err := d.AssociateHostedFabricSideport(ctx, f.profile.Scope.InstanceID, badGen); !errors.Is(err, ErrNativeObservationConflict) {
		t.Fatalf("wrong generation err = %v, want conflict", err)
	}
	// A different stable endpoint (even under the same domain): refused.
	badEP := sp
	otherRef, err := fabric.NewEndpointRef(f.root.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	badEP.Endpoint = otherRef
	if err := d.AssociateHostedFabricSideport(ctx, f.profile.Scope.InstanceID, badEP); !errors.Is(err, ErrNativeObservationConflict) {
		t.Fatalf("wrong endpoint err = %v, want conflict", err)
	}
	// An instance the selected binding never installed: refused by the
	// resolve port itself.
	if err := d.AssociateHostedFabricSideport(ctx, domain.NewID().String(), sp); err == nil {
		t.Fatal("unknown instance associated")
	}
	// An invalid socket shape (exceeds the unix path bound): refused
	// before any authority is consulted.
	badSock := sp
	badSock.Socket = strings.Repeat("x", 512)
	if err := d.AssociateHostedFabricSideport(ctx, f.profile.Scope.InstanceID, badSock); err == nil {
		t.Fatal("invalid socket path associated")
	}
	// A daemon without the probe capability (no live native lane) cannot
	// re-probe the genuine worker: refused.
	unprobed := &Daemon{Config: Config{HostedFabricSideports: NewHostedFabricSideports(f.hostedNativeResolvePort)}}
	if err := unprobed.AssociateHostedFabricSideport(ctx, f.profile.Scope.InstanceID, sp); err == nil {
		t.Fatal("association succeeded without the genuine worker probe")
	}
	// Process-death boundary: the dead activation advertises nothing.
	d.invalidateHostedSideport(f.profile.Scope.InstanceID)
	if _, ok := d.HostedFabricSideports.For(f.profile.Scope.InstanceID); ok {
		t.Fatal("invalidation did not drop the association")
	}
}

func TestBridgeSideportAdvertisedHookedTransitionPreserved(t *testing.T) {
	f := newHostedGuardFixture(t)
	ctx := t.Context()
	d := f.d

	// The REAL node host: the fixture's genuine installation (registry,
	// authority, keys) with the hosted chain over the live native worker,
	// on a private 0700 socket. The glue below mirrors the production
	// node wiring step for step (this package cannot import it:
	// fabricnode imports the daemon).
	nodeDir, err := os.MkdirTemp("", "pgn-node-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(nodeDir) })
	nodeSocket := filepath.Join(nodeDir, "node.sock")

	// The mandatory chained owner guard: registered original workers plus
	// a local-managed gate that admits only this test's node host process.
	testRoot, err := localpeer.ReadProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	guard, err := NewHostedOwnerGuard(func(_ context.Context, peer localpeer.ProcessSnapshot) error {
		if peer != testRoot {
			return errors.New("local managed owner denied")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := d.nativeWorkerFor(f.conn, f.profile.Scope.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.Register(proxy); err != nil {
		t.Fatalf("register the genuine original worker: %v", err)
	}
	d.HostedOwnerGuard = guard
	if err := d.HostedOwnerGuardReady(ctx, guard); err != nil {
		t.Fatalf("owner guard readiness fence: %v", err)
	}

	// selectedNodeBinding: the exact registered descriptor, its single
	// hosted-native binding and the installed profile — the node's
	// selection authority (never caller-supplied identity).
	selectedNodeBinding := func(ctx context.Context, ref fabric.EndpointRef, revision fabric.Revision, binding string) (fabric.EndpointDescriptor, registry.DescriptorBatchScope, fabricagent.HostedProfile, error) {
		if ref.IsOffer() || ref.Domain() != f.root.Namespace {
			return fabric.EndpointDescriptor{}, registry.DescriptorBatchScope{}, fabricagent.HostedProfile{}, errors.New("node: endpoint outside the installation domain")
		}
		descriptor, err := f.installation.Store.GetEndpoint(ctx, ref, revision)
		if err != nil {
			return fabric.EndpointDescriptor{}, registry.DescriptorBatchScope{}, fabricagent.HostedProfile{}, err
		}
		selected := ""
		for _, b := range descriptor.Bindings {
			if b.Protocol == hostedNativeBindingProtocol && (binding == "" || binding == b.ID) {
				if selected != "" {
					return fabric.EndpointDescriptor{}, registry.DescriptorBatchScope{}, fabricagent.HostedProfile{}, errors.New("node: ambiguous hosted binding")
				}
				selected = b.ID
			}
		}
		if selected == "" {
			return fabric.EndpointDescriptor{}, registry.DescriptorBatchScope{}, fabricagent.HostedProfile{}, errors.New("node: no hosted native binding")
		}
		scope := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: descriptor.Revision, BindingID: selected}
		profile, _, err := f.profiles.Get(ctx, scope)
		return descriptor, scope, profile, err
	}
	// nodeVerified: root identity, the exact selected profile, the
	// daemon's genuine worker-IPC activation verification, and the
	// registered descriptor's principal (never the installation owner).
	nodeVerified := func(ctx context.Context, peer fabricauth.HostedPeer) (fabric.Principal, registry.DescriptorBatchScope, error) {
		if peer.Root.Namespace != f.root.Namespace || peer.Root.StoreID != f.root.StoreID || peer.Root.KeyRevision != f.root.KeyRevision || peer.Root.Owner != f.root.Owner || !bytes.Equal(peer.Root.PublicKey, f.root.PublicKey) {
			return fabric.Principal{}, registry.DescriptorBatchScope{}, errors.New("node: root identity mismatch")
		}
		a := peer.Activation
		descriptor, scope, profile, err := selectedNodeBinding(ctx, a.Endpoint, a.DescriptorRevision, a.BindingID)
		if err != nil {
			return fabric.Principal{}, scope, err
		}
		if err := d.VerifyHostedActivation(ctx, profile, peer); err != nil {
			return fabric.Principal{}, scope, err
		}
		principal := fabric.Principal{Ref: descriptor.Ref.String(), Kind: descriptor.Kind, Issuer: f.root.Namespace}
		if principal == f.root.Owner || !fabric.ValidNamespacedName(principal.Kind) {
			return fabric.Principal{}, scope, errors.New("node: hosted principal must be the registered endpoint actor")
		}
		return principal, scope, nil
	}
	validateNodeHosted := func(ctx context.Context, peer fabricauth.HostedPeer) (fabric.Principal, error) {
		p, _, err := nodeVerified(ctx, peer)
		return p, err
	}
	hostedNodeFacts := func(ctx context.Context, peer fabricauth.HostedPeer) (*fabricauth.HostedCallerAuthority, error) {
		p, scope, err := nodeVerified(ctx, peer)
		if err != nil {
			return nil, err
		}
		return f.profiles.CallerAuthority(ctx, scope, p)
	}
	resolveNodeHosted := func(ctx context.Context, sel fabrichost.HostedSelector) (fabricauth.HostedActivation, error) {
		_, scope, profile, err := selectedNodeBinding(ctx, sel.Endpoint, "", "")
		if err != nil || profile.Scope.InstanceID != sel.InstanceID {
			return fabricauth.HostedActivation{}, errors.New("node: instance not bound to the selected binding")
		}
		return d.ResolveHostedActivation(ctx, profile, scope.Endpoint, scope.ExpectedEndpointRevision, scope.BindingID, sel.Peer, sel.Nonce, sel.Generation)
	}

	auth, err := fabricauth.New(fabricauth.Config{
		Root: f.root, RootOwner: f.root.Owner, Audience: f.root.Namespace, SocketPath: nodeSocket,
		CurrentRoot:     f.installation.Store.CurrentAuthorityIdentity,
		HostedValidator: validateNodeHosted,
		HostedFacts:     hostedNodeFacts,
		OwnerValidator:  guard.Validate,
	})
	if err != nil {
		t.Fatal(err)
	}
	index, err := f.installation.Store.LoadIndex(ctx, search.Config{})
	if err != nil {
		t.Fatal(err)
	}
	n, err := node.New(node.Config{Audience: f.root.Namespace, Authenticator: auth, Search: index, Descriptors: f.installation.Store})
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := fabricmcp.New(fabricmcp.Config{Executor: n})
	if err != nil {
		t.Fatal(err)
	}
	host, err := fabrichost.Start(ctx, fabrichost.Config{SocketPath: nodeSocket, Authority: auth, Server: canonical, ResolveHosted: resolveNodeHosted})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.CloseContext(context.Background()) })

	// Control probe BEFORE anything else: a forged hosted auth against
	// the real listener is refused (the listener is genuinely in the
	// path, and it is the real chain — not an echo).
	forge, err := net.Dial("unix", nodeSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer forge.Close()
	forge.Write([]byte(`{"type":"fabric.auth","mode":"hosted","endpoint":"` + f.ref.String() + `","workerId":"forger","generation":"forged","nonce":"forged"}` + "\n"))
	forge.SetReadDeadline(time.Now().Add(3 * time.Second))
	forgeData, _ := io.ReadAll(forge)
	if bytes.Contains(forgeData, []byte("fabric.ready")) {
		t.Fatal("forged hosted auth was accepted by the real node")
	}

	// The bridge side of the fixture daemon.
	if err := d.startBridgeSocket(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.stopBridgeSocket() })
	startBridgeRelayResponder(t, f.server)
	// The daemon-side read loop routing the responder's agent.response
	// envelopes back to the waiting bridge clients (the fixture has no
	// control-plane read loop of its own).
	go func() {
		for {
			_, raw, err := f.conn.ReadMessage()
			if err != nil {
				return
			}
			var env transport.Envelope
			if json.Unmarshal(raw, &env) != nil {
				continue
			}
			if env.Type == transport.MsgAgentResponse {
				d.deliverAgentResponse(env)
			}
		}
	}()

	// The association for the daemon-managed instance this test launches.
	// (The genuine Associate path is pinned in the companion test; the
	// daemon-managed instance has no native journal entry to resolve, so
	// the seed exercises the advertisement + hook chain directly.)
	d.HostedFabricSideports = NewHostedFabricSideports(f.hostedNativeResolvePort)
	sp := agentbridge.HostedFabricSideport{
		Socket:     nodeSocket,
		Endpoint:   f.ref,
		Generation: f.profile.Scope.Generation,
	}

	launchSideportInstance := func(t *testing.T, instanceID string) {
		t.Helper()
		env, err := transport.NewEnvelope(transport.MsgLaunchAgent, transport.LaunchAgentPayload{
			CommandID: domain.NewID().String(), InstanceID: instanceID,
			Runtime: string(domain.RuntimeFakePersistent), Kind: "worker",
		})
		if err != nil {
			t.Fatal(err)
		}
		d.handleCommand(nil, env)
		waitForEndpointLive(t, d, instanceID)
	}

	pf := mustPersistentFake(t, d)

	// 1) The association is advertised ONLY in the authenticated
	// handshake: an in-tree raw client (the endpoint itself, the S1
	// hostile-bridge fixture) with the daemon-minted nonce sees the
	// EXACT triple in the auth_ok it is served. The association is
	// seeded before the launch, so the handshake ordering is
	// deterministic.
	hostileFile := filepath.Join(t.TempDir(), "hostile-sideport-result.json")
	pf.Env = []string{
		"PAGNET_FAKE_HOSTILE_BRIDGE=1",
		"PAGNET_FAKE_BRIDGE_RESULT_FILE=" + hostileFile,
	}
	hostileID := domain.NewID().String()
	d.HostedFabricSideports.Store(hostileID, sp)
	launchSideportInstance(t, hostileID)
	hostileLines := readBridgeResult(t, hostileFile)
	assertAuthOK(t, hostileLines, hostileID)
	raw, err := json.Marshal(hostileLines[0]["sideport"])
	if err != nil {
		t.Fatal("auth_ok carried no sideport")
	}
	var gotSp agentbridge.HostedFabricSideport
	if err := json.Unmarshal(raw, &gotSp); err != nil {
		t.Fatalf("auth_ok sideport malformed: %v (%s)", err, raw)
	}
	if gotSp.Socket != sp.Socket || gotSp.Generation != sp.Generation || gotSp.Endpoint.String() != sp.Endpoint.String() {
		t.Fatalf("advertised sideport = %+v, want exactly %+v", gotSp, sp)
	}
	// 2) A rejected identity gets the refusal and NO sideport (the
	// nonce stage is portable: it fires before the process-tree check).
	c2 := bridgeDial(t, d.bridgePath)
	bad := c2.authFull(t, hostileID, "", "not-the-nonce", "worker")
	assertBridgeError(t, bad, "bridge nonce invalid")
	if _, has := bad["sideport"]; has {
		t.Fatal("rejected identity received a sideport")
	}

	// 3) The REAL bridge subprocess: the fixture spawns the daemon-
	// rendered pagnet worker as the endpoint's child (the production
	// path) and records what a fresh MCP client sees.
	resultFile := filepath.Join(t.TempDir(), "sideport-bridge-result.json")
	pf.Env = []string{
		"PAGNET_FAKE_SPAWN_BRIDGE=1",
		"PAGNET_FAKE_BRIDGE_RESULT_FILE=" + resultFile,
		"PAGNET_FAKE_BRIDGE_LIST_TOOLS=1",
	}
	spawnID := domain.NewID().String()
	d.HostedFabricSideports.Store(spawnID, sp)
	launchSideportInstance(t, spawnID)
	lines := readBridgeResult(t, resultFile)
	if len(lines) < 4 {
		t.Fatalf("bridge observed %d lines, want initialize + tools/call + tools/list + done: %v", len(lines), lines)
	}
	initRaw, _ := json.Marshal(lines[0])
	if id, _ := lines[0]["id"].(float64); id != 1 || lines[0]["result"] == nil {
		t.Fatalf("MCP initialize = %v, want a successful handshake", lines[0])
	}
	// Honesty: the bridge must NOT claim tools/list_changed — the tool
	// list is fixed for the bridge's lifetime (the claim must be absent
	// or false; the raw JSON carries the explicit false, not a true).
	initResult, _ := lines[0]["result"].(map[string]any)
	caps, _ := initResult["capabilities"].(map[string]any)
	toolsCap, _ := caps["tools"].(map[string]any)
	if lc, present := toolsCap["listChanged"].(bool); present && lc {
		t.Fatalf("bridge claimed tools/list_changed it does not implement: %s", initRaw)
	}
	// The sideport bridge carries the actionable explicit refresh
	// requirement in the initialize response.
	if !strings.Contains(string(initRaw), "reconnect") {
		t.Fatalf("initialize lacks the explicit refresh instruction: %s", initRaw)
	}
	// The original tools are preserved during the transition: the
	// scripted network_whoami is relayed end-to-end through the daemon.
	if id, _ := lines[1]["id"].(float64); id != 2 {
		t.Fatalf("tools/call response id = %v, want 2", lines[1])
	}
	if text := mcpResultText(lines[1]); !strings.Contains(text, "network_whoami") {
		t.Fatalf("tools/call result = %q, want the relayed network_whoami", text)
	}
	// The hosted canonical tools are absent: the real node refused this
	// bridge's hosted dial (its instance is not the associated original
	// worker) — the bridge serves its original surface, not a subset or
	// a fake.
	list, _ := lines[2]["result"].(map[string]any)
	tools, _ := list["tools"].([]any)
	names := map[string]bool{}
	for _, tool := range tools {
		name, _ := tool.(map[string]any)["name"].(string)
		names[name] = true
	}
	if !names["network_whoami"] {
		t.Fatalf("tools/list lost the original surface: %v", names)
	}
	for _, canonical := range []string{"discover", "describe", "invoke"} {
		if names[canonical] {
			t.Fatalf("refused hosted dial still published %q", canonical)
		}
	}
	// The refusal is explicit on stderr — the actionable error, not
	// silence.
	done, _ := lines[3]["fixture"].(string)
	stderrText, _ := lines[3]["stderr"].(string)
	if done != "done" || !strings.Contains(stderrText, "hosted fabric sideport unavailable") {
		t.Fatalf("bridge stderr = %q (fixture %q), want the explicit sideport refusal", stderrText, done)
	}
	t.Logf("sideport e2e: advertised in auth_ok, hooked with the real nonce/instance, refused by the real node, original tools preserved")
}
