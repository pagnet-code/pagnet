//go:build linux || darwin

package fabricnode

import (
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/federation"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricadmin"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
)

// openFederationFixture bootstraps a fresh installation and opens an installed
// node with the federation surface enabled over its real private admin socket.
func openFederationFixture(t *testing.T, ctx context.Context) (*InstalledNode, string, registry.AuthorityIdentity) {
	t.Helper()
	parent := t.TempDir()
	socketDir := filepath.Join(parent, "run")
	if err := os.Mkdir(socketDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "authority")
	socket := filepath.Join(socketDir, "node.sock")
	installed, err := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if err != nil {
		t.Fatal(err)
	}
	root := installed.Store.AuthorityIdentity()
	if err = installed.Close(); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	n, err := OpenInstalled(ctx, InstalledConfig{Directory: dir, Binary: binary, Federation: &InstalledFederationConfig{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = n.Close() })
	if n.Federation == nil {
		t.Fatal("the federation surface was not composed")
	}
	return n, socket, root
}

// dialAdmin dials the node's real private admin socket and returns a call
// helper that fails the test on a transport error.
func dialAdmin(t *testing.T, ctx context.Context, socket string) func(id, operation string, input []byte) (json.RawMessage, *fabric.Error) {
	t.Helper()
	admin, err := fabricadmin.Dial(ctx, socket)
	if err != nil {
		t.Fatalf("dial the real private admin socket: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	return func(id, operation string, input []byte) (json.RawMessage, *fabric.Error) {
		t.Helper()
		response, err := admin.Call(ctx, fabricadmin.Request{Version: fabricadmin.Version, ID: id, Operation: operation, Input: input})
		if err != nil {
			t.Fatalf("%s transport: %v", operation, err)
		}
		if response.Error != nil {
			return nil, response.Error
		}
		return response.Result, nil
	}
}

// deriveX25519Public recovers the X25519 public key from the 32-byte private
// key the KeyProvider returns, proving it is the pair of the certified public.
func deriveX25519Public(t *testing.T, private []byte) [32]byte {
	t.Helper()
	priv, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	pubRaw := priv.PublicKey().Bytes()
	if len(pubRaw) != 32 {
		t.Fatalf("public key is %d bytes; want 32", len(pubRaw))
	}
	var out [32]byte
	copy(out[:], pubRaw)
	return out
}

// TestFederationPeerExchangeCertifyKeyProvider proves the exchange-key certify
// round-trip + the KeyProvider contract: the certified certificate verifies,
// the local-get mirrors it, the KeyProvider returns the private key whose
// public half is the certified one (wrong public/revision denied), and a
// rotation advances both the certificate and the exchange key.
func TestFederationPeerExchangeCertifyKeyProvider(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	n, socket, root := openFederationFixture(t, ctx)
	call := dialAdmin(t, ctx, socket)

	// First certify at the create base.
	certifyInput, err := json.Marshal(struct {
		ExpectedRevision uint64 `json:"expectedRevision"`
		ExpirySeconds    uint64 `json:"expirySeconds"`
	}{0, 0})
	if err != nil {
		t.Fatal(err)
	}
	certifyResult, failure := call("federation-peer-certify-1", "federation.peer.local-certify", certifyInput)
	if failure != nil {
		t.Fatalf("federation.peer.local-certify: %v", failure)
	}
	var certify struct {
		PublicKey   [32]byte                     `json:"publicKey"`
		KeyRevision string                       `json:"keyRevision"`
		Certificate fabric.SignedPeerCertificate `json:"certificate"`
		Digest      [32]byte                     `json:"digest"`
	}
	if err := json.Unmarshal(certifyResult, &certify); err != nil {
		t.Fatalf("decode certify receipt: %v (%s)", err, certifyResult)
	}
	if fabric.VerifyPeerCertificate(certify.Certificate, time.Now()) != nil {
		t.Fatalf("the certified certificate does not verify: %s", certifyResult)
	}
	if certify.Certificate.Certificate.ExchangeKeyRevision != 1 || certify.KeyRevision != "1" {
		t.Fatalf("first certify key revision = %s; want 1", certify.KeyRevision)
	}

	// local-get mirrors the certified identity.
	getResult, failure := call("federation-peer-get-1", "federation.peer.local-get", []byte(`{}`))
	if failure != nil {
		t.Fatalf("federation.peer.local-get: %v", failure)
	}
	var get struct {
		PublicKey   [32]byte `json:"publicKey"`
		KeyRevision string   `json:"keyRevision"`
		Certified   bool     `json:"certified"`
	}
	if err := json.Unmarshal(getResult, &get); err != nil {
		t.Fatalf("decode get receipt: %v (%s)", err, getResult)
	}
	if !get.Certified || get.PublicKey != certify.PublicKey || get.KeyRevision != "1" {
		t.Fatalf("get = %+v; want certified with the first public key at revision 1", get)
	}

	// KeyProvider: the certified binding resolves the private key whose public
	// half is the certified public key.
	binding := federation.PeerBinding{
		Authority:           registry.AuthorityIdentity{Namespace: root.Namespace, StoreID: root.StoreID},
		ExchangePublicKey:   certify.PublicKey,
		ExchangeKeyRevision: 1,
	}
	private, err := n.Federation.ExchangeKeys.ExchangePrivateKey(ctx, binding)
	if err != nil {
		t.Fatalf("KeyProvider for the certified binding: %v", err)
	}
	if len(private) != 32 {
		t.Fatalf("KeyProvider returned %d bytes; want 32", len(private))
	}
	if got := deriveX25519Public(t, private); got != certify.PublicKey {
		t.Fatalf("KeyProvider private key derives %x; want the certified public %x", got, certify.PublicKey)
	}
	// A wrong public key is denied (a rotated or foreign binding).
	wrongPub := binding
	wrongPub.ExchangePublicKey = [32]byte{0xde, 0xad}
	if _, err = n.Federation.ExchangeKeys.ExchangePrivateKey(ctx, wrongPub); !isFabricCode(err, fabric.CodeUnauthenticated) {
		t.Fatalf("wrong-public KeyProvider = %v; want CodeUnauthenticated", err)
	}
	// A stale revision is denied.
	wrongRev := binding
	wrongRev.ExchangeKeyRevision = 99
	if _, err = n.Federation.ExchangeKeys.ExchangePrivateKey(ctx, wrongRev); !isFabricCode(err, fabric.CodeUnauthenticated) {
		t.Fatalf("stale-revision KeyProvider = %v; want CodeUnauthenticated", err)
	}

	// Rotation: certify again at the current certificate base. The exchange key
	// and certificate both advance; the old binding is now denied.
	rotateInput, err := json.Marshal(struct {
		ExpectedRevision uint64 `json:"expectedRevision"`
		ExpirySeconds    uint64 `json:"expirySeconds"`
	}{1, 0})
	if err != nil {
		t.Fatal(err)
	}
	rotateResult, failure := call("federation-peer-certify-2", "federation.peer.local-certify", rotateInput)
	if failure != nil {
		t.Fatalf("rotation certify: %v", failure)
	}
	var rotate struct {
		PublicKey   [32]byte `json:"publicKey"`
		KeyRevision string   `json:"keyRevision"`
	}
	if err := json.Unmarshal(rotateResult, &rotate); err != nil {
		t.Fatalf("decode rotation receipt: %v (%s)", err, rotateResult)
	}
	if rotate.KeyRevision != "2" || rotate.PublicKey == certify.PublicKey {
		t.Fatalf("rotation = %+v; want a new public key at revision 2", rotate)
	}
	if _, err = n.Federation.ExchangeKeys.ExchangePrivateKey(ctx, binding); !isFabricCode(err, fabric.CodeUnauthenticated) {
		t.Fatalf("rotated-out binding still resolves = %v; want CodeUnauthenticated", err)
	}
	rotatedBinding := binding
	rotatedBinding.ExchangePublicKey = rotate.PublicKey
	rotatedBinding.ExchangeKeyRevision = 2
	if _, err = n.Federation.ExchangeKeys.ExchangePrivateKey(ctx, rotatedBinding); err != nil {
		t.Fatalf("rotated binding = %v; want the new private key", err)
	}
}

// TestFederationPeerPinUnpinTwoInstallations proves explicit pin/unpin across
// two real installations: B pins A's certified original (verified + retrievable
// as a remote peer), pinning one's own namespace is refused, a tampered
// certificate is refused, and unpin removes the remote peer.
func TestFederationPeerPinUnpinTwoInstallations(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
	defer cancel()
	_, socketA, rootA := openFederationFixture(t, ctx)
	nodeB, socketB, rootB := openFederationFixture(t, ctx)
	if rootA.Namespace == rootB.Namespace {
		t.Fatal("two independent fixtures must not share a namespace")
	}
	callA := dialAdmin(t, ctx, socketA)
	callB := dialAdmin(t, ctx, socketB)

	// A certifies its local exchange key + identity.
	if _, failure := callA("federation-a-certify", "federation.peer.local-certify", []byte(`{"expectedRevision":0}`)); failure != nil {
		t.Fatalf("A certify: %v", failure)
	}
	aGet, failure := callA("federation-a-get", "federation.peer.local-get", []byte(`{}`))
	if failure != nil {
		t.Fatalf("A get: %v", failure)
	}
	var aCert struct {
		Certificate fabric.SignedPeerCertificate `json:"certificate"`
	}
	if err := json.Unmarshal(aGet, &aCert); err != nil {
		t.Fatalf("decode A certificate: %v (%s)", err, aGet)
	}

	// B explicitly pins A's certified original (pasted out-of-band).
	pinInput, err := json.Marshal(struct {
		ExpectedRevision uint64                       `json:"expectedRevision"`
		Owner            fabric.Principal             `json:"owner"`
		Certificate      fabric.SignedPeerCertificate `json:"certificate"`
	}{0, rootA.Owner, aCert.Certificate})
	if err != nil {
		t.Fatal(err)
	}
	pinResult, failure := callB("federation-b-pin-a", "federation.peer.pin", pinInput)
	if failure != nil {
		t.Fatalf("B pins A: %v", failure)
	}
	var pin struct {
		Authority   registry.AuthorityIdentity   `json:"authority"`
		Certificate fabric.SignedPeerCertificate `json:"certificate"`
		Revision    string                       `json:"revision"`
	}
	if err := json.Unmarshal(pinResult, &pin); err != nil {
		t.Fatalf("decode pin receipt: %v (%s)", err, pinResult)
	}
	if pin.Authority.Namespace != rootA.Namespace || pin.Authority.StoreID != rootA.StoreID || pin.Revision != "1" {
		t.Fatalf("pin receipt = %+v; want A's authority at revision 1", pin)
	}

	// The pin is retrievable as a remote peer on B.
	ownerB, err := nodeB.Installation.Operator(ctx)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := nodeB.Federation.Peers.Remote(ctx, ownerB, rootA.Namespace, rootA.StoreID)
	if err != nil {
		t.Fatalf("B reads the pinned remote A: %v", err)
	}
	expectedDigest, err := aCert.Certificate.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if remote.Digest != expectedDigest || remote.Authority.Namespace != rootA.Namespace || remote.Authority.StoreID != rootA.StoreID {
		t.Fatal("the pinned remote peer differs from A's certified original")
	}

	// Self-pin: A pinning A's own namespace is refused (a node is not its own remote).
	selfPinInput, err := json.Marshal(struct {
		ExpectedRevision uint64                       `json:"expectedRevision"`
		Owner            fabric.Principal             `json:"owner"`
		Certificate      fabric.SignedPeerCertificate `json:"certificate"`
	}{0, rootA.Owner, aCert.Certificate})
	if err != nil {
		t.Fatal(err)
	}
	if _, failure = callA("federation-a-selfpin", "federation.peer.pin", selfPinInput); failure == nil || failure.Code != fabric.CodeUnauthenticated {
		t.Fatalf("self-pin = %v; want CodeUnauthenticated", failure)
	}

	// Tampered certificate: B refuses a certificate whose signature is corrupted.
	tampered := aCert.Certificate
	tampered.Signature = append([]byte(nil), aCert.Certificate.Signature...)
	tampered.Signature[0] ^= 0x01
	tamperedInput, err := json.Marshal(struct {
		ExpectedRevision uint64                       `json:"expectedRevision"`
		Owner            fabric.Principal             `json:"owner"`
		Certificate      fabric.SignedPeerCertificate `json:"certificate"`
	}{1, rootA.Owner, tampered})
	if err != nil {
		t.Fatal(err)
	}
	if _, failure = callB("federation-b-pin-tampered", "federation.peer.pin", tamperedInput); failure == nil || failure.Code != fabric.CodeUnauthenticated {
		t.Fatalf("tampered-pin = %v; want CodeUnauthenticated", failure)
	}

	// Unpin: B removes the remote A at the pinned revision; it is now gone.
	unpinInput, err := json.Marshal(struct {
		ExpectedRevision uint64 `json:"expectedRevision"`
		Namespace        string `json:"namespace"`
		StoreID          string `json:"storeId"`
	}{1, rootA.Namespace, rootA.StoreID})
	if err != nil {
		t.Fatal(err)
	}
	if _, failure = callB("federation-b-unpin", "federation.peer.unpin", unpinInput); failure != nil {
		t.Fatalf("B unpin: %v", failure)
	}
	// Unpin revokes (Retired stays false, Revoked=true): the pinned peer is no
	// longer a current trusted peer, so Remote denies with unauthenticated
	// (a revoked peer is not "absent" — it is deliberately de-trusted).
	if _, err = nodeB.Federation.Peers.Remote(ctx, ownerB, rootA.Namespace, rootA.StoreID); !isFabricCode(err, fabric.CodeUnauthenticated) {
		t.Fatalf("remote after unpin = %v; want CodeUnauthenticated (revoked)", err)
	}
}

// TestFederationPeerLinkOwnerFence proves the non-owner session fence holds for
// the full peer/link surface: a managed (non-owner) session cannot establish on
// the owner-only administration surface, so no peer or link operation is
// reachable without the genuine owner.
func TestFederationPeerLinkOwnerFence(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	_, socket, root := openFederationFixture(t, ctx)
	ref, err := fabric.NewEndpointRef(root.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	managed, _, err := fabrichost.DialProtocol(ctx, socket, fabrichost.Authentication{Type: "fabric.auth", Mode: "managed", Endpoint: ref, WorkerID: "federation-probe", Generation: "gen", Nonce: "nonce"}, fabrichost.AdminProtocol)
	if err == nil {
		if managed != nil {
			managed.Close()
		}
		t.Fatal("non-owner session established on the administration surface")
	}
	var typed *fabric.Error
	if !errors.As(err, &typed) || typed.Code != fabric.CodeUnauthenticated {
		t.Fatalf("non-owner denial = %v; want typed CodeUnauthenticated", err)
	}
}

// TestFederationLinkLifecycleAndCAS proves the per-channel link registry: a put
// at the create base is retrievable, a stale base conflicts, a self-target is
// refused, and remove retires the link (subsequent get is not-found).
func TestFederationLinkLifecycleAndCAS(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	_, socket, root := openFederationFixture(t, ctx)
	call := dialAdmin(t, ctx, socket)

	// A foreign peer identity (54-char namespace, 64-char store id) + opaque
	// channel/route values (distinct 32-byte routes).
	remoteKey := make([]byte, 32)
	remoteKey[0] = 0x11
	remoteRef, err := fabric.NewEndpointRef(remoteKey)
	if err != nil {
		t.Fatal(err)
	}
	remoteNamespace := remoteRef.Domain()
	if remoteNamespace == root.Namespace {
		t.Fatal("fixture foreign domain collided with the local domain")
	}
	remoteStoreID := hex.EncodeToString(make([]byte, 32))
	channelID := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	sourceRoute := make([]byte, 32)
	destinationRoute := make([]byte, 32)
	for i := range sourceRoute {
		sourceRoute[i] = 2
		destinationRoute[i] = 3
	}
	putLink := func(expected uint64, remote, store string, sourceRole bool) []byte {
		raw, _ := json.Marshal(struct {
			ExpectedRevision uint64 `json:"expectedRevision"`
			RemoteNamespace  string `json:"remoteNamespace"`
			RemoteStoreID    string `json:"remoteStoreId"`
			ChannelID        []byte `json:"channelId"`
			SourceRoute      []byte `json:"sourceRoute"`
			DestinationRoute []byte `json:"destinationRoute"`
			SourceRole       bool   `json:"sourceRole"`
		}{expected, remote, store, channelID, sourceRoute, destinationRoute, sourceRole})
		return raw
	}

	// Put at the create base -> revision 1.
	putResult, failure := call("federation-link-put", "federation.link.put", putLink(0, remoteNamespace, remoteStoreID, true))
	if failure != nil {
		t.Fatalf("federation.link.put: %v", failure)
	}
	var put struct {
		Link     FederationLink `json:"link"`
		Revision string         `json:"revision"`
	}
	if err := json.Unmarshal(putResult, &put); err != nil || put.Revision != "1" {
		t.Fatalf("put receipt = %s; want revision 1", putResult)
	}
	if put.Link.RemoteNamespace != remoteNamespace || put.Link.RemoteStoreID != remoteStoreID || !put.Link.SourceRole {
		t.Fatalf("put link = %+v; want the declared peer + source role", put.Link)
	}

	// Get mirrors the put.
	getInput, _ := json.Marshal(struct {
		ChannelID []byte `json:"channelId"`
	}{channelID})
	getResult, failure := call("federation-link-get", "federation.link.get", getInput)
	if failure != nil {
		t.Fatalf("federation.link.get: %v", failure)
	}
	var get struct {
		Link     FederationLink `json:"link"`
		Revision string         `json:"revision"`
	}
	if err := json.Unmarshal(getResult, &get); err != nil || get.Revision != "1" || get.Link != put.Link {
		t.Fatalf("get = %+v (revision %s); want the put link at revision 1", get.Link, get.Revision)
	}

	// A stale create base with different content conflicts (the identical
	// (base, content) pair would be the signed exact-retry no-op, not a
	// conflict — so the source role differs here to force the CAS conflict).
	if _, failure = call("federation-link-stale", "federation.link.put", putLink(0, remoteNamespace, remoteStoreID, false)); failure == nil || failure.Code != fabric.CodeStaleReference {
		t.Fatalf("stale put base = %v; want CodeStaleReference", failure)
	}

	// A self-target is refused.
	if _, failure = call("federation-link-self", "federation.link.put", putLink(0, root.Namespace, remoteStoreID, true)); failure == nil || failure.Code != fabric.CodeInvalidInput {
		t.Fatalf("self-target put = %v; want CodeInvalidInput", failure)
	}

	// Remove retires the link at the current base.
	removeInput, _ := json.Marshal(struct {
		ExpectedRevision uint64 `json:"expectedRevision"`
		ChannelID        []byte `json:"channelId"`
	}{1, channelID})
	if _, failure = call("federation-link-remove", "federation.link.remove", removeInput); failure != nil {
		t.Fatalf("federation.link.remove: %v", failure)
	}
	// Subsequent get is not-found.
	if _, failure = call("federation-link-get-after", "federation.link.get", getInput); failure == nil || failure.Code != fabric.CodeNotFound {
		t.Fatalf("get after remove = %v; want CodeNotFound", failure)
	}
}
