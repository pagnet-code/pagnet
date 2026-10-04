//go:build linux || darwin

package fabricauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	fabricidentity "github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/mcpbridge"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
)

func ownerFixture(t *testing.T) (*Authority, *registry.Store, string) {
	t.Helper()
	owner := fabric.Principal{Ref: "spiffe://local/owner", Kind: "local.owner", Issuer: "retained.owner"}
	store, e := registry.Bootstrap(context.Background(), filepath.Join(t.TempDir(), "domain"), owner)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { store.Close() })
	root := store.AuthorityIdentity()
	private, e := os.MkdirTemp("", "pgn-fa-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(private) })
	socket := filepath.Join(private, "peer.sock")
	a, e := New(Config{Root: root, RootOwner: owner, Audience: root.Namespace, SocketPath: socket, CurrentRoot: func(ctx context.Context) (registry.AuthorityIdentity, error) {
		return store.CurrentAuthorityIdentity(ctx)
	}})
	if e != nil {
		t.Fatal(e)
	}
	return a, store, socket
}
func ownerSocket(t *testing.T, path string) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	if os.Chmod(path, 0600) != nil {
		t.Fatal("private socket mode")
	}
	dial, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	accepted, e := listener.AcceptUnix()
	if e != nil {
		t.Fatal(e)
	}
	// Preserve the socket inode while accepted connections are authenticated.
	listener.SetUnlinkOnClose(false)
	t.Cleanup(func() { accepted.Close(); dial.Close(); os.Remove(path) })
	return accepted, dial
}
func discoverCall() mcpbridge.Call {
	return mcpbridge.Call{Operation: fabric.OperationDiscover, Discover: &fabric.DiscoverRequest{Query: "local", Limit: 10}}
}
func authenticate(t *testing.T, a *Authority, raw []byte, evidence any) fabric.ExecutionContext {
	t.Helper()
	c, e := a.Authenticate(context.Background(), fabric.AuthenticationRequest{ExactEnvelope: raw, Audience: a.config.Audience, PeerEvidence: evidence})
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestRealOwnerPeerOriginalNodeAndExactInput(t *testing.T) {
	a, store, path := ownerFixture(t)
	conn, _ := ownerSocket(t, path)
	session, e := a.BindOwner(context.Background(), conn)
	if e != nil {
		t.Fatal(e)
	}
	defer session.Close()
	ref, _ := fabric.NewEndpointRef(store.AuthorityIdentity().PublicKey)
	call := mcpbridge.Call{Operation: fabric.OperationInvoke, Invoke: &fabric.InvokeRequest{Target: ref, ExpectedRevision: "exact-revision", Input: json.RawMessage(` { "integer": 9007199254740993, "html": "<agent>" } `)}}
	raw, evidence, e := session.Build(context.Background(), call)
	if e != nil {
		t.Fatal(e)
	}
	c := authenticate(t, a, raw, evidence)
	envelope, e := c.DecodeVerifiedEnvelope(raw, a.config.Audience)
	if e != nil {
		t.Fatal(e)
	}
	if envelope.Principal != store.AuthorityIdentity().Owner || envelope.Source != envelope.Principal.Ref || envelope.Context.Origin != envelope.Principal.Ref || envelope.Target == nil || *envelope.Target != ref || envelope.ExpectedRevision != "exact-revision" || !bytes.Contains(envelope.Payload, []byte("9007199254740993")) {
		t.Fatal("typed request lost identity/value", envelope)
	}
	var value struct {
		Integer json.Number `json:"integer"`
		HTML    string      `json:"html"`
	}
	if fabric.DecodeJSON(envelope.Payload, &value) != nil || value.Integer.String() != "9007199254740993" || value.HTML != "<agent>" {
		t.Fatal("input values changed")
	}
	if envelope.ID == "" || envelope.CreatedAt.IsZero() || envelope.Context.ParentID != "" || len(envelope.Context.Ancestry) != 0 {
		t.Fatal("fabricated lineage")
	}
	next, _, e := session.Build(context.Background(), call)
	if e != nil {
		t.Fatal(e)
	}
	var other fabric.Envelope
	fabric.DecodeJSON(next, &other)
	if other.ID == envelope.ID {
		t.Fatal("ID reused")
	}
	// Actual node authenticates the same exact original through the real factory.
	service, e := node.New(node.Config{Audience: a.config.Audience, Authenticator: a})
	if e != nil {
		t.Fatal(e)
	}
	raw, evidence, e = session.Build(context.Background(), discoverCall())
	if e != nil {
		t.Fatal(e)
	}
	_, e = service.Execute(context.Background(), raw, evidence)
	var structured *fabric.Error
	if !errors.As(e, &structured) || structured.Code != fabric.CodeUnsupported {
		t.Fatal("actual node did not authenticate before missing search", e)
	}
}
func TestOpaqueProofOneUseAndForgeryRefusal(t *testing.T) {
	a, _, path := ownerFixture(t)
	conn, _ := ownerSocket(t, path)
	session, e := a.BindOwner(context.Background(), conn)
	if e != nil {
		t.Fatal(e)
	}
	defer session.Close()
	for _, mutation := range []string{"principal", "lineage", "target", "id", "audience", "serialized", "forged"} {
		t.Run(mutation, func(t *testing.T) {
			raw, evidence, e := session.Build(context.Background(), discoverCall())
			if e != nil {
				t.Fatal(e)
			}
			r := fabric.AuthenticationRequest{ExactEnvelope: raw, Audience: a.config.Audience, PeerEvidence: evidence}
			var envelope fabric.Envelope
			fabric.DecodeJSON(raw, &envelope)
			switch mutation {
			case "principal":
				envelope.Principal.Ref = "spiffe://forged"
				envelope.Source = envelope.Principal.Ref
				r.ExactEnvelope, _ = json.Marshal(envelope)
			case "lineage":
				envelope.Context.ParentID = "invented"
				envelope.Context.Ancestry = []string{"invented"}
				r.ExactEnvelope, _ = json.Marshal(envelope)
			case "target":
				envelope.Operation = fabric.OperationInvoke
				ref, _ := fabric.NewEndpointRef(make([]byte, 32))
				envelope.Target = &ref
				r.ExactEnvelope, _ = json.Marshal(envelope)
			case "id":
				envelope.ID = "user-picked"
				r.ExactEnvelope, _ = json.Marshal(envelope)
			case "audience":
				r.Audience = "another-audience"
			case "serialized":
				if _, e = json.Marshal(evidence); e == nil {
					t.Fatal("private evidence serialized")
				}
				r.PeerEvidence = map[string]any{"session": session, "digest": sha256.Sum256(raw)}
			case "forged":
				r.PeerEvidence = &proof{session: session, digest: sha256.Sum256(raw), expires: time.Now().Add(time.Minute)}
			}
			if _, e = a.Authenticate(context.Background(), r); e == nil {
				t.Fatal("forgery accepted")
			}
		})
	}
	raw, evidence, e := session.Build(context.Background(), discoverCall())
	if e != nil {
		t.Fatal(e)
	}
	authenticate(t, a, raw, evidence)
	if _, e = a.Authenticate(context.Background(), fabric.AuthenticationRequest{ExactEnvelope: raw, Audience: a.config.Audience, PeerEvidence: evidence}); e == nil {
		t.Fatal("proof replay accepted")
	}
}
func TestProofCrossFactorySessionAndLiveConnection(t *testing.T) {
	a, _, path := ownerFixture(t)
	conn, dial := ownerSocket(t, path)
	s, e := a.BindOwner(context.Background(), conn)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	other, e := New(a.config)
	if e != nil {
		t.Fatal(e)
	}
	raw, p, e := s.Build(context.Background(), discoverCall())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = other.Authenticate(context.Background(), fabric.AuthenticationRequest{ExactEnvelope: raw, Audience: a.config.Audience, PeerEvidence: p}); e == nil {
		t.Fatal("crossfactory proof accepted")
	}
	copyProof := *(p.(*proof))
	if _, e = a.Authenticate(context.Background(), fabric.AuthenticationRequest{ExactEnvelope: raw, Audience: a.config.Audience, PeerEvidence: &copyProof}); e == nil {
		t.Fatal("copied proof accepted")
	}
	dial.Close()
	if _, e = a.Authenticate(context.Background(), fabric.AuthenticationRequest{ExactEnvelope: raw, Audience: a.config.Audience, PeerEvidence: p}); e == nil {
		t.Fatal("closed remote connection accepted")
	}
	if _, _, e = s.Build(context.Background(), discoverCall()); e == nil {
		t.Fatal("closed peer built new original")
	}
}
func TestProofQuotaExpiryCloseAndCurrentRootFence(t *testing.T) {
	a, _, path := ownerFixture(t)
	a.config.MaxPending = 1
	a.config.ProofTTL = time.Second
	conn, _ := ownerSocket(t, path)
	s, e := a.BindOwner(context.Background(), conn)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	raw, p, e := s.Build(context.Background(), discoverCall())
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Build(context.Background(), discoverCall()); e == nil {
		t.Fatal("pending quota ignored")
	}
	expired := p.(*proof)
	expired.expires = time.Now().Add(-time.Second)
	s.pending[expired] = expired.expires
	if _, e = a.Authenticate(context.Background(), fabric.AuthenticationRequest{ExactEnvelope: raw, Audience: a.config.Audience, PeerEvidence: p}); e == nil {
		t.Fatal("expired proof accepted")
	}
	if _, _, e = s.Build(context.Background(), discoverCall()); e != nil {
		t.Fatal("expired quota not reclaimed", e)
	}
	s.Close()
	if _, _, e = s.Build(context.Background(), discoverCall()); e == nil {
		t.Fatal("closed session issued proof")
	}
	a.config.ProofTTL = time.Second
	s, e = a.BindOwner(context.Background(), conn)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	raw, p, e = s.Build(context.Background(), discoverCall())
	if e != nil {
		t.Fatal(e)
	}
	root := a.config.Root
	root.StoreID = strings.Repeat("b", 64)
	a.config.CurrentRoot = func(context.Context) (registry.AuthorityIdentity, error) { return root, nil }
	if _, e = a.Authenticate(context.Background(), fabric.AuthenticationRequest{ExactEnvelope: raw, Audience: a.config.Audience, PeerEvidence: p}); e == nil {
		t.Fatal("changed retained store identity accepted")
	}
}
func TestOwnerPeerPIDBirthAndPrivateSocketFence(t *testing.T) {
	a, _, path := ownerFixture(t)
	conn, _ := ownerSocket(t, path)
	s, e := a.BindOwner(context.Background(), conn)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	s.process.Start++
	if _, _, e = s.Build(context.Background(), discoverCall()); e == nil {
		t.Fatal("changed kernel start accepted")
	}
	s.process.Start--
	if os.Chmod(path, 0666) != nil {
		t.Fatal("chmod")
	}
	if _, _, e = s.Build(context.Background(), discoverCall()); e == nil {
		t.Fatal("public socket accepted")
	}
}

type setupFence struct{}

func (setupFence) WithAdmission(_ context.Context, f fabricidentity.AdmissionFacts, commit func(fabricidentity.Witness) error) error {
	return commit(fabricidentity.Witness{Version: "test.owner.v1", FinalizedDigest: f.FinalizedDigest, Value: json.RawMessage(`{}`)})
}
func managedScope(t *testing.T, store *registry.Store) (nativeauthority.Scope, fabricidentity.Controller, fabricidentity.Binding) {
	t.Helper()
	ctx := context.Background()
	root := store.AuthorityIdentity()
	owner, _ := fabric.NewAuthenticatedContext(root.Owner, root.Namespace, []byte("trusted setup"))
	ref, _ := fabric.NewEndpointRef(root.PublicKey)
	rev, e := store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "agent.local", Name: "Local", Description: "Actual local agent", Bindings: []fabric.BindingSummary{{ID: "native", Protocol: "local.native", Version: "1"}}}})
	if e != nil {
		t.Fatal(e)
	}
	authority, e := fabricidentity.New(store, setupFence{})
	if e != nil {
		t.Fatal(e)
	}
	controller, e := authority.AcquireController(ctx, owner, fabricidentity.Scope{Endpoint: ref, DescriptorRevision: rev, BindingID: "native"}, 0, "setup", "controller")
	if e != nil {
		t.Fatal(e)
	}
	binding, e := authority.BindWorker(ctx, owner, controller, 0, fabricidentity.WorkerBinding{WorkerID: "actual-worker", StateDirectoryID: "retained-directory", OwnershipGeneration: "ownership1", ActualRuntime: "test-native", ProfileDigest: sha256.Sum256([]byte("profile"))})
	if e != nil {
		t.Fatal(e)
	}
	scope, e := nativeauthority.NewLocalScope(root, binding)
	if e != nil {
		t.Fatal(e)
	}
	return scope, controller, binding
}
func TestActualChildManagedPeerRequiresCurrentSource(t *testing.T) {
	if os.Getenv("PAGNET_FABRICAUTH_CHILD") == "1" {
		c, e := net.Dial("unix", os.Getenv("PAGNET_FABRICAUTH_SOCKET"))
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		var b [1]byte
		if _, e = c.Read(b[:]); e != nil {
			t.Fatal(e)
		}
		return
	}
	a, store, path := ownerFixture(t)
	scope, _, binding := managedScope(t, store)
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	os.Chmod(path, 0600)
	child := exec.Command(os.Args[0], "-test.run=^TestActualChildManagedPeerRequiresCurrentSource$")
	child.Env = append(os.Environ(), "PAGNET_FABRICAUTH_CHILD=1", "PAGNET_FABRICAUTH_SOCKET="+path)
	if child.Start() != nil {
		t.Fatal("child")
	}
	defer func() { child.Process.Kill(); child.Wait() }()
	listener.SetDeadline(time.Now().Add(5 * time.Second))
	conn, e := listener.AcceptUnix()
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	rootProcess, e := localpeer.ReadProcess(os.Getpid())
	if e != nil {
		t.Fatal(e)
	}
	activation := Activation{Scope: scope, RootPID: rootProcess.PID, StartIdentity: strconv.FormatInt(rootProcess.Start, 10), Nonce: "actual-owner-captured-nonce", NativeGeneration: "native1", NativeSessionID: "session1"}
	if _, e = a.BindManaged(context.Background(), conn, activation); e == nil {
		t.Fatal("managed mode accepted without source validator")
	}
	var revoked atomic.Bool
	var checks atomic.Int32
	endpoint, _ := scope.Local()
	principal := fabric.Principal{Ref: endpoint.Endpoint.String(), Kind: "agent.local", Issuer: a.config.Root.Namespace}
	// This fixture supplies actual signed registry binding verification and a
	// trusted supervisor snapshot. Production injects the native owner gate.
	a.config.ManagedValidator = func(ctx context.Context, p ManagedPeer) (fabric.Principal, error) {
		checks.Add(1)
		if revoked.Load() || p.Activation != activation || p.Process.PID != child.Process.Pid || !sameRoot(p.Root, store.AuthorityIdentity()) || registry.VerifyAuthorityRecord(p.Root, binding.Proof) != nil {
			return fabric.Principal{}, denied()
		}
		return principal, nil
	}
	if _, e = a.BindOwner(context.Background(), conn); e == nil {
		t.Fatal("managed-enabled configuration without owner classification elevated child")
	}
	a.config.OwnerValidator = func(ctx context.Context, p localpeer.ProcessSnapshot) error {
		if ctx.Err() != nil || p.PID == child.Process.Pid {
			return denied()
		}
		return nil
	}
	if _, e = a.BindOwner(context.Background(), conn); e == nil {
		t.Fatal("managed child omitted selectors and became the root owner")
	}
	s, e := a.BindManaged(context.Background(), conn, activation)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	raw, p, e := s.Build(context.Background(), discoverCall())
	if e != nil {
		t.Fatal(e)
	}
	trusted := authenticate(t, a, raw, p)
	if trusted.PrincipalView() != principal || trusted.ProvenanceView().Origin != principal.Ref || trusted.ProvenanceView().ParentID != "" || checks.Load() < 4 {
		t.Fatal("managed source/current checks missing")
	}
	raw, p, e = s.Build(context.Background(), discoverCall())
	if e != nil {
		t.Fatal(e)
	}
	revoked.Store(true)
	if _, e = a.Authenticate(context.Background(), fabric.AuthenticationRequest{ExactEnvelope: raw, Audience: a.config.Audience, PeerEvidence: p}); e == nil {
		t.Fatal("revoked current source accepted")
	}
	revoked.Store(false)
	bad := activation
	bad.StartIdentity = strconv.FormatInt(rootProcess.Start+1, 10)
	if _, e = a.BindManaged(context.Background(), conn, bad); e == nil {
		t.Fatal("changed activation birth accepted")
	}
	bad = activation
	bad.NativeSessionID = "other-session"
	if _, e = a.BindManaged(context.Background(), conn, bad); e == nil {
		t.Fatal("different activation accepted")
	}
	conn.Write([]byte{1})
}

func TestActualSeparateConnectionsCannotTransplantProof(t *testing.T) {
	a, _, path := ownerFixture(t)
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	os.Chmod(path, 0600)
	connect := func() (*net.UnixConn, *net.UnixConn) {
		dial, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
		if e != nil {
			t.Fatal(e)
		}
		server, e := listener.AcceptUnix()
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { server.Close(); dial.Close() })
		return server, dial
	}
	firstConn, _ := connect()
	secondConn, secondDial := connect()
	first, e := a.BindOwner(context.Background(), firstConn)
	if e != nil {
		t.Fatal(e)
	}
	defer first.Close()
	second, e := a.BindOwner(context.Background(), secondConn)
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	raw, evidence, e := first.Build(context.Background(), discoverCall())
	if e != nil {
		t.Fatal(e)
	}
	transplanted := *(evidence.(*proof))
	transplanted.session = second
	if _, e = a.Authenticate(context.Background(), fabric.AuthenticationRequest{ExactEnvelope: raw, Audience: a.config.Audience, PeerEvidence: &transplanted}); e == nil {
		t.Fatal("crossconnection proof accepted")
	}
	authenticate(t, a, raw, evidence)
	raw, evidence, e = second.Build(context.Background(), discoverCall())
	if e != nil {
		t.Fatal(e)
	}
	secondDial.Write([]byte("unread data"))
	secondDial.Close()
	if _, e = a.Authenticate(context.Background(), fabric.AuthenticationRequest{ExactEnvelope: raw, Audience: a.config.Audience, PeerEvidence: evidence}); e == nil {
		t.Fatal("closed peer with unread data accepted")
	}
}

func TestClosedActualRetainedRegistryRejectsLocalProof(t *testing.T) {
	a, store, path := ownerFixture(t)
	conn, _ := ownerSocket(t, path)
	s, e := a.BindOwner(context.Background(), conn)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	raw, p, e := s.Build(context.Background(), discoverCall())
	if e != nil {
		t.Fatal(e)
	}
	store.Close()
	if _, e = a.Authenticate(context.Background(), fabric.AuthenticationRequest{ExactEnvelope: raw, Audience: a.config.Audience, PeerEvidence: p}); e == nil {
		t.Fatal("closed actual registry authenticated proof")
	}
	if _, _, e = s.Build(context.Background(), discoverCall()); e == nil {
		t.Fatal("closed actual registry issued original")
	}
}
