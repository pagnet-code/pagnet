// The installed federation product's private owner-administration surface.
// This slice composes the retained signed exposure configuration plus the
// persistent peer/link config substrate (federation.exposure.put/get,
// federation.peer.local-get/local-certify/pin/unpin, federation.link.put/
// get/remove): the sealed X25519 exchange keypair, the owner-certified local
// peer identity, the explicitly pinned remote peers, and the per-channel link
// registry. The per-link boundary+runtime and the relay listener are a
// subsequent serving slice and are deliberately absent here. The handlers merge
// into the node's existing admin server (the same handlers-map pattern as
// AgentAdministration / ServiceAdministration / InstalledHosted.Administration);
// duplicate operation names are startup errors, as today. Every act runs under
// the genuine owner session and each surface's own owner fence.

package fabricnode

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/federation"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricadmin"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
)

// InstalledFederationConfig is the explicit installed federation surface. A
// nil InstalledConfig.Federation means the surface is unavailable (explicit,
// never implicit). The relay socket is a subsequent serving slice.
type InstalledFederationConfig struct{}

// InstalledFederation is the composed installed federation surface over the
// loaded installation: the retained signed exposure record, the sealed exchange
// keypair, the owner-certified local peer identity, the pinned remote peers,
// and the per-channel link registry.
type InstalledFederation struct {
	node         *InstalledNode
	Exposures    *FederationExposures
	ExchangeKeys *FederationExchangeKeys
	Links        *FederationLinks
	Peers        *registry.PeerIdentity
}

// newInstalledFederation composes the federation surface from the installation's
// actual store, owner, operator and keys. A missing exposure/exchange/link
// record is not an error: the first declaration creates it.
func newInstalledFederation(ctx context.Context, n *InstalledNode) (*InstalledFederation, error) {
	if ctx == nil || n == nil || n.Installation == nil {
		return nil, localDenied()
	}
	installation := n.Installation
	owner := func(ctx context.Context) (fabric.ExecutionContext, error) { return installation.Operator(ctx) }
	exposures, err := NewFederationExposures(ctx, installation.Store, owner, installation, installation.Keys)
	if err != nil {
		return nil, err
	}
	exchangeKeys, err := NewFederationExchangeKeys(installation)
	if err != nil {
		return nil, err
	}
	links, err := NewFederationLinks(installation)
	if err != nil {
		return nil, err
	}
	// The peer gate rechecks genuine current-operator authority (never a
	// serialized principal) without calling the peer handle recursively.
	peers, err := registry.NewPeerIdentity(ctx, installation.Store, func(ctx context.Context, c fabric.ExecutionContext, r registry.AuthorityIdentity) error {
		if c.PrincipalView() != r.Owner {
			return localDenied()
		}
		return installation.WithCurrentOperator(ctx, c, func(context.Context) error { return nil })
	})
	if err != nil {
		return nil, err
	}
	return &InstalledFederation{node: n, Exposures: exposures, ExchangeKeys: exchangeKeys, Links: links, Peers: peers}, nil
}

// currentOwner resolves the genuine current operator capability for a store call
// that requires an explicit owner (the registry peer identity). It is not a
// substitute for the handler's access.VerifyCurrent + the store's own fence.
func (f *InstalledFederation) currentOwner(ctx context.Context) (fabric.ExecutionContext, error) {
	if f == nil || f.node == nil || f.node.Installation == nil {
		var zero fabric.ExecutionContext
		return zero, localDenied()
	}
	return f.node.Installation.Operator(ctx)
}

// decodeFederationInput decodes a private owner input with bounded strict JSON
// and rejects unknown fields, as by every other operation.
func decodeFederationInput(input []byte, target interface{}, op string) error {
	if e := fabric.DecodeJSON(input, target); e != nil {
		return e
	}
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.DisallowUnknownFields()
	if e := dec.Decode(target); e != nil {
		return fabric.NewError(fabric.CodeInvalidInput, op+" contains unsupported fields")
	}
	return nil
}

// fixedBytes32 converts a wire byte slice (base64 in JSON) into a fixed
// 32-byte routing value, rejecting any other length.
func fixedBytes32(b []byte) ([32]byte, error) {
	var out [32]byte
	if len(b) != 32 {
		return out, fabric.NewError(fabric.CodeInvalidInput, "Federation routing value must be 32 bytes")
	}
	copy(out[:], b)
	return out, nil
}

// Administration returns the federation product's private owner-administration
// handlers. A nil product contributes no operations.
func (f *InstalledFederation) Administration() map[string]fabricadmin.Handler {
	if f == nil {
		return nil
	}
	return map[string]fabricadmin.Handler{
		"federation.exposure.put":       f.federationExposurePut,
		"federation.exposure.get":       f.federationExposureGet,
		"federation.peer.local-get":     f.federationPeerLocalGet,
		"federation.peer.local-certify": f.federationPeerLocalCertify,
		"federation.peer.pin":           f.federationPeerPin,
		"federation.peer.unpin":         f.federationPeerUnpin,
		"federation.link.put":           f.federationLinkPut,
		"federation.link.get":           f.federationLinkGet,
		"federation.link.remove":        f.federationLinkRemove,
	}
}

// federationExposurePutInput is the private owner input for declaring the
// node's signed exposure configuration. The CAS base is an explicit JSON
// number in the input; the generic request-level expectedRevision string is
// rejected, as by every other operation.
type federationExposurePutInput struct {
	ExpectedRevision uint64               `json:"expectedRevision"`
	Exposures        []FederationExposure `json:"exposures"`
}

func (f *InstalledFederation) federationExposurePut(ctx context.Context, access *fabricauth.OwnerAdministration, request fabricadmin.Request) (json.RawMessage, error) {
	if f == nil || f.node == nil || f.Exposures == nil || access == nil || request.Operation != "federation.exposure.put" || request.ExpectedRevision != "" || access.VerifyCurrent(ctx) != nil {
		return nil, localDenied()
	}
	var input federationExposurePutInput
	if err := fabric.DecodeJSON(request.Input, &input); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(request.Input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Federation exposure put contains unsupported fields")
	}
	revision, err := f.Exposures.Put(ctx, input.ExpectedRevision, FederationExposureConfiguration{Exposures: input.Exposures})
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Revision uint64 `json:"revision"`
	}{revision})
}

func (f *InstalledFederation) federationExposureGet(ctx context.Context, access *fabricauth.OwnerAdministration, request fabricadmin.Request) (json.RawMessage, error) {
	if f == nil || f.node == nil || f.Exposures == nil || access == nil || request.Operation != "federation.exposure.get" || request.ExpectedRevision != "" || access.VerifyCurrent(ctx) != nil {
		return nil, localDenied()
	}
	var input struct{}
	if err := fabric.DecodeJSON(request.Input, &input); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(request.Input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Federation exposure get contains unsupported fields")
	}
	configuration, revision, err := f.Exposures.Current(ctx)
	if err != nil {
		return nil, err
	}
	exposures := configuration.Exposures
	if exposures == nil {
		exposures = []FederationExposure{}
	}
	return json.Marshal(struct {
		Revision  uint64               `json:"revision"`
		Exposures []FederationExposure `json:"exposures"`
	}{revision, exposures})
}

// federationPeerLocalGet reports the retained local exchange keypair and whether
// the local peer identity is certified. A not-yet-certified identity is the
// not-configured state (Certified=false), not an error.
func (f *InstalledFederation) federationPeerLocalGet(ctx context.Context, access *fabricauth.OwnerAdministration, request fabricadmin.Request) (json.RawMessage, error) {
	if f == nil || f.node == nil || f.Peers == nil || f.ExchangeKeys == nil || access == nil || request.Operation != "federation.peer.local-get" || request.ExpectedRevision != "" || access.VerifyCurrent(ctx) != nil {
		return nil, localDenied()
	}
	if err := decodeFederationInput(request.Input, new(struct{}), "Federation peer get"); err != nil {
		return nil, err
	}
	owner, e := f.currentOwner(ctx)
	if e != nil {
		return nil, e
	}
	out := struct {
		PublicKey   [32]byte                      `json:"publicKey"`
		KeyRevision uint64                        `json:"keyRevision,string"`
		Certified   bool                          `json:"certified"`
		Certificate *fabric.SignedPeerCertificate `json:"certificate,omitempty"`
		Authority   *registry.AuthorityIdentity   `json:"authority,omitempty"`
	}{}
	pub, keyRevision, _, found, e := f.ExchangeKeys.Current(ctx, owner)
	if e != nil {
		return nil, e
	}
	if found {
		out.PublicKey = pub
		out.KeyRevision = keyRevision
	}
	cert, e := f.Peers.Local(ctx, owner)
	if e != nil {
		var missing *fabric.Error
		if !(errors.As(e, &missing) && missing.Code == fabric.CodeNotFound) {
			return nil, e
		}
	} else {
		out.Certified = true
		out.Certificate = &cert.Certificate
		auth := cert.Authority
		out.Authority = &auth
	}
	return json.Marshal(out)
}

// federationCertifyDefaultExpirySeconds is the local certificate validity when
// the operator omits it (90 days), within the peer-frame 366-day bound.
const federationCertifyDefaultExpirySeconds = 90 * 24 * 3600

type federationPeerCertifyInput struct {
	ExpectedRevision uint64 `json:"expectedRevision"`
	ExpirySeconds    uint64 `json:"expirySeconds"`
}

// federationPeerLocalCertify generates-or-rotates the sealed local exchange key
// and then certifies it with the retained root (two separate ledger records; a
// partial failure is fail-closed, never a half-trusted identity). The CAS base
// is the certificate's revision; the exchange record's base is read live.
func (f *InstalledFederation) federationPeerLocalCertify(ctx context.Context, access *fabricauth.OwnerAdministration, request fabricadmin.Request) (json.RawMessage, error) {
	if f == nil || f.node == nil || f.Peers == nil || f.ExchangeKeys == nil || access == nil || request.Operation != "federation.peer.local-certify" || request.ExpectedRevision != "" || access.VerifyCurrent(ctx) != nil {
		return nil, localDenied()
	}
	var input federationPeerCertifyInput
	if err := decodeFederationInput(request.Input, &input, "Federation peer certify"); err != nil {
		return nil, err
	}
	expiry := input.ExpirySeconds
	if expiry == 0 {
		expiry = federationCertifyDefaultExpirySeconds
	}
	if expiry == 0 || expiry > 366*24*3600 {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Federation certificate expiry exceeds bound")
	}
	owner, e := f.currentOwner(ctx)
	if e != nil {
		return nil, e
	}
	_, _, exchangeBase, _, e := f.ExchangeKeys.Current(ctx, owner)
	if e != nil {
		return nil, e
	}
	pub, keyRevision, _, e := f.ExchangeKeys.GenerateOrRotate(ctx, owner, exchangeBase)
	if e != nil {
		return nil, e
	}
	now := time.Now().UTC()
	cert, e := f.Peers.CertifyLocal(ctx, owner, input.ExpectedRevision, pub, keyRevision, now, now.Add(time.Duration(expiry)*time.Second))
	if e != nil {
		return nil, e
	}
	return json.Marshal(struct {
		PublicKey   [32]byte                     `json:"publicKey"`
		KeyRevision uint64                       `json:"keyRevision,string"`
		Certificate fabric.SignedPeerCertificate `json:"certificate"`
		Digest      [32]byte                     `json:"digest"`
	}{pub, keyRevision, cert.Certificate, cert.Digest})
}

type federationPeerPinInput struct {
	ExpectedRevision uint64                       `json:"expectedRevision"`
	Owner            fabric.Principal             `json:"owner"`
	Certificate      fabric.SignedPeerCertificate `json:"certificate"`
}

// federationPeerPin is explicit owner approval of a remote peer's ORIGINAL
// authority + certificate (pasted out-of-band), never automatic trust. The
// authority is derived from the certificate plus the remote owner identity.
func (f *InstalledFederation) federationPeerPin(ctx context.Context, access *fabricauth.OwnerAdministration, request fabricadmin.Request) (json.RawMessage, error) {
	if f == nil || f.node == nil || f.Peers == nil || access == nil || request.Operation != "federation.peer.pin" || request.ExpectedRevision != "" || access.VerifyCurrent(ctx) != nil {
		return nil, localDenied()
	}
	var input federationPeerPinInput
	if err := decodeFederationInput(request.Input, &input, "Federation peer pin"); err != nil {
		return nil, err
	}
	if input.Owner.Ref == "" || input.Owner.Kind == "" || input.Owner.Issuer == "" {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Federation pin requires the remote owner identity")
	}
	c := input.Certificate.Certificate
	authority := registry.AuthorityIdentity{
		Namespace:   c.Namespace,
		StoreID:     c.StoreID,
		Owner:       input.Owner,
		PublicKey:   append([]byte(nil), c.RootPublicKey[:]...),
		KeyRevision: c.RootKeyRevision,
	}
	owner, e := f.currentOwner(ctx)
	if e != nil {
		return nil, e
	}
	cert, e := f.Peers.PinRemote(ctx, owner, input.ExpectedRevision, authority, input.Certificate)
	if e != nil {
		return nil, e
	}
	return json.Marshal(struct {
		Authority   registry.AuthorityIdentity   `json:"authority"`
		Certificate fabric.SignedPeerCertificate `json:"certificate"`
		Digest      [32]byte                     `json:"digest"`
		Revision    uint64                       `json:"revision,string"`
	}{cert.Authority, cert.Certificate, cert.Digest, cert.Revision})
}

type federationPeerUnpinInput struct {
	ExpectedRevision uint64 `json:"expectedRevision"`
	Namespace        string `json:"namespace"`
	StoreID          string `json:"storeId"`
}

func (f *InstalledFederation) federationPeerUnpin(ctx context.Context, access *fabricauth.OwnerAdministration, request fabricadmin.Request) (json.RawMessage, error) {
	if f == nil || f.node == nil || f.Peers == nil || access == nil || request.Operation != "federation.peer.unpin" || request.ExpectedRevision != "" || access.VerifyCurrent(ctx) != nil {
		return nil, localDenied()
	}
	var input federationPeerUnpinInput
	if err := decodeFederationInput(request.Input, &input, "Federation peer unpin"); err != nil {
		return nil, err
	}
	owner, e := f.currentOwner(ctx)
	if e != nil {
		return nil, e
	}
	e = f.Peers.RevokeRemote(ctx, owner, input.Namespace, input.StoreID, input.ExpectedRevision)
	if e != nil {
		return nil, e
	}
	return json.Marshal(struct{}{})
}

type federationLinkPutInput struct {
	ExpectedRevision uint64   `json:"expectedRevision"`
	RemoteNamespace  string   `json:"remoteNamespace"`
	RemoteStoreID    string   `json:"remoteStoreId"`
	ChannelID        []byte   `json:"channelId"`
	SourceRoute      []byte   `json:"sourceRoute"`
	DestinationRoute []byte   `json:"destinationRoute"`
	SourceRole       bool     `json:"sourceRole"`
}

func (f *InstalledFederation) federationLinkPut(ctx context.Context, access *fabricauth.OwnerAdministration, request fabricadmin.Request) (json.RawMessage, error) {
	if f == nil || f.node == nil || f.Links == nil || access == nil || request.Operation != "federation.link.put" || request.ExpectedRevision != "" || access.VerifyCurrent(ctx) != nil {
		return nil, localDenied()
	}
	var input federationLinkPutInput
	if err := decodeFederationInput(request.Input, &input, "Federation link put"); err != nil {
		return nil, err
	}
	channelID, e := fixedBytes32(input.ChannelID)
	if e != nil {
		return nil, e
	}
	sourceRoute, e := fixedBytes32(input.SourceRoute)
	if e != nil {
		return nil, e
	}
	destinationRoute, e := fixedBytes32(input.DestinationRoute)
	if e != nil {
		return nil, e
	}
	owner, e := f.currentOwner(ctx)
	if e != nil {
		return nil, e
	}
	link := FederationLink{
		RemoteNamespace: input.RemoteNamespace,
		RemoteStoreID:   input.RemoteStoreID,
		Channel:         federation.ChannelBinding{ID: channelID, SourceRoute: sourceRoute, DestinationRoute: destinationRoute},
		SourceRole:      input.SourceRole,
	}
	committed, revision, e := f.Links.Put(ctx, owner, input.ExpectedRevision, link)
	if e != nil {
		return nil, e
	}
	return json.Marshal(struct {
		Link     FederationLink `json:"link"`
		Revision uint64         `json:"revision,string"`
	}{committed, revision})
}

type federationLinkGetInput struct {
	ChannelID []byte `json:"channelId"`
}

func (f *InstalledFederation) federationLinkGet(ctx context.Context, access *fabricauth.OwnerAdministration, request fabricadmin.Request) (json.RawMessage, error) {
	if f == nil || f.node == nil || f.Links == nil || access == nil || request.Operation != "federation.link.get" || request.ExpectedRevision != "" || access.VerifyCurrent(ctx) != nil {
		return nil, localDenied()
	}
	var input federationLinkGetInput
	if err := decodeFederationInput(request.Input, &input, "Federation link get"); err != nil {
		return nil, err
	}
	channelID, e := fixedBytes32(input.ChannelID)
	if e != nil {
		return nil, e
	}
	owner, e := f.currentOwner(ctx)
	if e != nil {
		return nil, e
	}
	link, revision, found, e := f.Links.Get(ctx, owner, channelID)
	if e != nil {
		return nil, e
	}
	if !found {
		return nil, fabric.NewError(fabric.CodeNotFound, "Federation link absent")
	}
	return json.Marshal(struct {
		Link     FederationLink `json:"link"`
		Revision uint64         `json:"revision,string"`
	}{link, revision})
}

type federationLinkRemoveInput struct {
	ExpectedRevision uint64 `json:"expectedRevision"`
	ChannelID        []byte `json:"channelId"`
}

func (f *InstalledFederation) federationLinkRemove(ctx context.Context, access *fabricauth.OwnerAdministration, request fabricadmin.Request) (json.RawMessage, error) {
	if f == nil || f.node == nil || f.Links == nil || access == nil || request.Operation != "federation.link.remove" || request.ExpectedRevision != "" || access.VerifyCurrent(ctx) != nil {
		return nil, localDenied()
	}
	var input federationLinkRemoveInput
	if err := decodeFederationInput(request.Input, &input, "Federation link remove"); err != nil {
		return nil, err
	}
	channelID, e := fixedBytes32(input.ChannelID)
	if e != nil {
		return nil, e
	}
	owner, e := f.currentOwner(ctx)
	if e != nil {
		return nil, e
	}
	e = f.Links.Retire(ctx, owner, input.ExpectedRevision, channelID)
	if e != nil {
		return nil, e
	}
	return json.Marshal(struct{}{})
}
