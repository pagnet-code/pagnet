//go:build linux || darwin

package fabricnode

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/federation"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/mcpbridge"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabricfederation"
)

type remoteInstalledPeer struct {
	installation *localinstallation.Installation
	owner        fabric.ExecutionContext
	peers        *registry.PeerIdentity
	cert         registry.CertifiedPeer
	socket       string
	key          []byte
}

type remoteKeys map[[32]byte][]byte

func (k remoteKeys) ExchangePrivateKey(_ context.Context, p federation.PeerBinding) ([]byte, error) {
	raw := k[p.BindingDigest]
	if len(raw) != 32 {
		return nil, localDenied()
	}
	return bytes.Clone(raw), nil
}
func remoteInstalled(t *testing.T) remoteInstalledPeer {
	t.Helper()
	dir, e := os.MkdirTemp("", "pgn-remote-boundary-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "fabric.sock")
	installation, e := localinstallation.Bootstrap(t.Context(), filepath.Join(dir, "domain"), localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { installation.Close() })
	owner, e := installation.Operator(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	peers, e := registry.NewPeerIdentity(t.Context(), installation.Store, func(ctx context.Context, c fabric.ExecutionContext, r registry.AuthorityIdentity) error {
		if c.PrincipalView() != r.Owner {
			return localDenied()
		}
		return installation.WithCurrentOperator(ctx, c, func(context.Context) error { return nil })
	})
	if e != nil {
		t.Fatal(e)
	}
	key, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	var public [32]byte
	copy(public[:], key.PublicKey().Bytes())
	now := time.Now()
	cert, e := peers.CertifyLocal(t.Context(), owner, 0, public, 1, now.Add(-time.Second), now.Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	return remoteInstalledPeer{installation, owner, peers, cert, socket, key.Bytes()}
}

type blindFixtureStream struct {
	federation.PacketStream
	t         *testing.T
	forbidden [][]byte
}

func (s blindFixtureStream) Write(ctx context.Context, p federation.Packet) error {
	raw, e := federation.EncodePacket(p)
	if e != nil {
		return e
	}
	for _, secret := range s.forbidden {
		if bytes.Contains(raw, secret) {
			s.t.Error("blind relay disclosed semantic metadata")
		}
	}
	return s.PacketStream.Write(ctx, p)
}
func actualEncryptedBundle(t *testing.T, source, destination federation.Config, bundle federation.ForwardBundle) federation.ForwardBundle {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	left, relayLeft := net.Pipe()
	relayRight, right := net.Pipe()
	stream := func(c net.Conn) federation.PacketStream {
		s, e := federation.NewConnStream(c, time.Second)
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	a, e := federation.NewDuplex(ctx, source, stream(left), 4<<20)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	b, e := federation.NewDuplex(ctx, destination, stream(right), 4<<20)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	sender, e := federation.NewForwardChannel(a)
	if e != nil {
		t.Fatal(e)
	}
	receiver, e := federation.NewForwardChannel(b)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		done <- federation.RelayOpaque(ctx, stream(relayLeft), blindFixtureStream{stream(relayRight), t, [][]byte{[]byte(source.Local.Authority.Namespace), []byte(source.Remote.Authority.Namespace), []byte(`"query":"private"`)}}, source.Channel, federation.RelayLimits{MaxPackets: 64, MaxBytes: 4 << 20, Lifetime: 5 * time.Second})
	}()
	sent := make(chan error, 1)
	go func() { sent <- sender.SendBundle(ctx, bundle) }()
	received, e := receiver.ReceiveBundle(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = <-sent; e != nil {
		t.Fatal(e)
	}
	sender.Close()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("blind relay failed to join")
	}
	return received
}
func TestActualKernelSourceClosedRootForwardRemoteEvidenceAndRetirement(t *testing.T) {
	for _, scenario := range []string{"complete", "transform_failure", "capture_quota", "native"} {
		t.Run(scenario, func(t *testing.T) { actualKernelRemoteScenario(t, scenario) })
	}
}

func actualKernelRemoteScenario(t *testing.T, scenario string) {
	a, b := remoteInstalled(t), remoteInstalled(t)
	pinB, e := a.peers.PinRemote(t.Context(), a.owner, 0, b.cert.Authority, b.cert.Certificate)
	if e != nil {
		t.Fatal(e)
	}
	pinA, e := b.peers.PinRemote(t.Context(), b.owner, 0, a.cert.Authority, a.cert.Certificate)
	if e != nil {
		t.Fatal(e)
	}
	ga, e := fabricfederation.New(t.Context(), fabricfederation.Config{Peers: a.peers, Owner: a.installation.Operator, Local: a.cert, Remote: pinB})
	if e != nil {
		t.Fatal(e)
	}
	gb, e := fabricfederation.New(t.Context(), fabricfederation.Config{Peers: b.peers, Owner: b.installation.Operator, Local: b.cert, Remote: pinA})
	if e != nil {
		t.Fatal(e)
	}
	auth, e := fabricauth.New(fabricauth.Config{Root: a.cert.Authority, RootOwner: a.cert.Authority.Owner, Audience: a.cert.Authority.Namespace, SocketPath: a.socket, CurrentRoot: a.installation.Store.CurrentAuthorityIdentity})
	if e != nil {
		t.Fatal(e)
	}
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: a.socket, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	if e = os.Chmod(a.socket, 0600); e != nil {
		t.Fatal(e)
	}
	peer, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: a.socket, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	conn, e := listener.AcceptUnix()
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	session, e := auth.BindOwner(t.Context(), conn)
	if e != nil {
		t.Fatal(e)
	}
	defer session.Close()
	original, evidence, e := session.Build(t.Context(), mcpbridge.Call{Operation: fabric.OperationDiscover, Discover: &fabric.DiscoverRequest{Query: "private", Limit: 1}})
	if e != nil {
		t.Fatal(e)
	}
	caller, e := auth.Authenticate(t.Context(), fabric.AuthenticationRequest{ExactEnvelope: original, Audience: a.cert.Authority.Namespace, PeerEvidence: evidence})
	if e != nil {
		t.Fatal(e)
	}
	var envelope fabric.Envelope
	if fabric.DecodeJSON(original, &envelope) != nil {
		t.Fatal("actual source malformed")
	}
	envelope.Context.Hops++
	forwarded, _ := json.Marshal(envelope)
	ab, _ := fabricfederation.Binding(a.cert)
	bb, _ := fabricfederation.Binding(b.cert)
	now := time.Now().UTC()
	deadline := ""
	if envelope.Context.Deadline != nil {
		deadline = envelope.Context.Deadline.Format(time.RFC3339Nano)
	}
	provenance := func(c fabric.EnvelopeContext) fabric.Provenance {
		return fabric.Provenance{Origin: c.Origin, ParentID: c.ParentID, Ancestry: c.Ancestry, Hops: c.Hops, ExtensionChain: c.ExtensionChain, TriggerLineage: c.TriggerLineage}
	}
	var before fabric.Envelope
	fabric.DecodeJSON(original, &before)
	frame := fabric.ForwardFrame{SourceDomain: ab.Authority.Namespace, SourceStoreID: ab.Authority.StoreID, SourceKeyRevision: ab.Authority.KeyRevision, DestinationDomain: bb.Authority.Namespace, DestinationStoreID: bb.Authority.StoreID, SourcePeerBindingDigest: ab.BindingDigest, DestinationPeerBindingDigest: bb.BindingDigest, Principal: caller.PrincipalView(), Operation: envelope.Operation, InvocationID: envelope.ID, ReplayID: "fresh-source-nonce", OriginalEnvelopeDigest: sha256.Sum256(original), ForwardedEnvelopeDigest: sha256.Sum256(forwarded), OriginalProvenance: provenance(before.Context), ForwardedProvenance: provenance(envelope.Context), IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(30 * time.Second).Format(time.RFC3339Nano), Deadline: deadline, BindingProfile: federation.Profile}
	gate, e := NewSourceForwardGate(ga, auth, caller)
	if e != nil {
		t.Fatal(e)
	}
	proof, e := a.installation.Store.SignForwardExact(t.Context(), a.owner, caller, original, forwarded, frame, gate)
	if e != nil {
		t.Fatal(e)
	}
	local, e := newLocalBoundary(t.Context(), b.installation.Store, b.owner, b.installation, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	exposures, e := NewFederationExposures(t.Context(), b.installation.Store, b.installation.Operator, b.installation, b.installation.Keys)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = exposures.Put(t.Context(), 0, FederationExposureConfiguration{}); e != nil {
		t.Fatal(e)
	}
	cfg := federation.Config{Local: bb, Remote: ab, Trust: gb, Keys: remoteKeys{bb.BindingDigest: b.key}, MaxRecords: 128, Channel: federation.ChannelBinding{ID: [32]byte{1}, SourceRoute: [32]byte{2}, DestinationRoute: [32]byte{3}}}
	boundary, e := NewRemoteBoundary(t.Context(), local, gb, exposures, cfg, federation.VerifyLimits{MaxLifetime: time.Minute})
	if e != nil {
		t.Fatal(e)
	}
	bundle := federation.ForwardBundle{Proof: proof, Original: original, Forwarded: forwarded}
	sourceCfg := federation.Config{Local: ab, Remote: bb, Trust: ga, Keys: remoteKeys{ab.BindingDigest: a.key}, SourceRole: true, Channel: cfg.Channel, MaxRecords: 128}
	bundle = actualEncryptedBundle(t, sourceCfg, cfg, bundle)
	var captured fabric.ExecutionContext
	var capturedEvidence any
	var capturedPhaseGuard func(*registry.AuthorityTx) error
	if e = boundary.WithForwardRequest(t.Context(), bundle, func(ctx context.Context, c fabric.ExecutionContext, evidence any) error {
		captured = c
		capturedEvidence = evidence
		authenticated, e := boundary.Authenticate(ctx, fabric.AuthenticationRequest{ExactEnvelope: forwarded, Audience: b.cert.Authority.Namespace, PeerEvidence: evidence})
		if e != nil {
			return e
		}
		if authenticated.PrincipalView() != a.cert.Authority.Owner {
			t.Fatal("remote coerced into local owner")
		}
		phase, e := c.DecodeVerifiedEnvelope(forwarded, b.cert.Authority.Namespace)
		if e != nil {
			return e
		}
		capturedPhaseGuard, e = boundary.CurrentPhaseWitness(ctx, c, forwarded, phase)
		if e != nil {
			return e
		}
		if e = b.installation.Store.WithNativeAuthority(ctx, b.owner, registry.AuthorityScope{HistoryOnly: true, MaxOperations: 16}, capturedPhaseGuard); e != nil {
			return e
		}
		altered := append([]byte(nil), forwarded...)
		altered[0] ^= 1
		if _, e = boundary.CurrentPhaseWitness(ctx, c, altered, phase); e == nil {
			t.Fatal("changed original authenticated extension phase")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e = b.installation.Store.WithNativeAuthority(t.Context(), b.owner, registry.AuthorityScope{HistoryOnly: true, MaxOperations: 16}, capturedPhaseGuard); e == nil {
		t.Fatal("escaped remote phase guard became fresh authority")
	}
	if _, e = boundary.binding(captured); e == nil {
		t.Fatal("expired callback became current authority")
	}
	if _, e = boundary.Authenticate(t.Context(), fabric.AuthenticationRequest{ExactEnvelope: forwarded, Audience: b.cert.Authority.Namespace, PeerEvidence: capturedEvidence}); e == nil {
		t.Fatal("escaped evidence")
	}
	if scenario == "native" {
		exerciseActualRemoteNativeFinal(t, a, b, auth, session, ga, boundary, exposures, cfg, sourceCfg)
	} else {
		exerciseActualRemotePaidFinal(t, a, b, auth, session, ga, boundary, exposures, cfg, sourceCfg, scenario)
	}
	session.Close()
	if _, e = a.installation.Store.SignForwardExact(t.Context(), a.owner, caller, original, forwarded, frame, gate); e == nil {
		t.Fatal("closed actual kernel source signed fresh proof")
	}
	if e = b.peers.RevokeRemote(t.Context(), b.owner, pinA.Authority.Namespace, pinA.Authority.StoreID, pinA.Revision); e != nil {
		t.Fatal(e)
	}
	if e = boundary.WithForwardRequest(t.Context(), bundle, func(context.Context, fabric.ExecutionContext, any) error {
		t.Fatal("revoked link accepted")
		return nil
	}); e == nil {
		t.Fatal("revoked pin")
	}
}
