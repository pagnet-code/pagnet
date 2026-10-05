package fabricnode

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"sync/atomic"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/federation"
	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricfederation"
	"github.com/pagnet-code/pagnet/internal/fabricservices"
)

// RemoteBoundary is a distinct infrastructure authentication/exposure boundary.
// Peer certificates never become local owner identity or business permissions.
// Paid authorization remains in configured destination dispatch interceptors.
type RemoteBoundary struct {
	local     *LocalBoundary
	peers     *fabricfederation.PeerGate
	exposures *FederationExposures
	config    federation.Config
	limits    federation.VerifyLimits
}
type remoteRequestBinding struct {
	boundary   *RemoteBoundary
	principal  fabric.Principal
	original   []byte
	assertion  [32]byte
	deadline   time.Time
	lifetime   context.Context
	active     atomic.Bool
	invocation string
	control    *fabric.ControlFrame
}

func NewRemoteBoundary(ctx context.Context, local *LocalBoundary, peers *fabricfederation.PeerGate, exposures *FederationExposures, c federation.Config, limits federation.VerifyLimits) (*RemoteBoundary, error) {
	if ctx == nil || local == nil || peers == nil || exposures == nil || local.store != exposures.store || c.SourceRole || c.Keys == nil || c.MaxRecords == 0 || c.MaxRecords > federation.MaxChannelRecords || c.Trust != peers || c.Channel.ID == ([32]byte{}) || c.Channel.SourceRoute == ([32]byte{}) || c.Channel.DestinationRoute == ([32]byte{}) || c.Local.Authority.Namespace != local.root.Namespace || c.Local.Authority.StoreID != local.root.StoreID || limits.MaxLifetime <= 0 || limits.MaxLifetime > 5*time.Minute || limits.MaxClockSkew < 0 || limits.MaxClockSkew > 30*time.Second {
		return nil, localDenied()
	}
	if e := local.operatorCurrent(ctx, local.owner, func(context.Context) error { return nil }); e != nil {
		return nil, e
	}
	if e := peers.WithCurrent(ctx, c.Local, c.Remote, func(context.Context) error { return nil }); e != nil {
		return nil, e
	}
	if e := exposures.Reload(ctx); e != nil {
		return nil, e
	}
	c.Local.Authority.PublicKey = bytes.Clone(c.Local.Authority.PublicKey)
	c.Remote.Authority.PublicKey = bytes.Clone(c.Remote.Authority.PublicKey)
	return &RemoteBoundary{local, peers, exposures, c, limits}, nil
}
func (b *RemoteBoundary) binding(c fabric.ExecutionContext) (*remoteRequestBinding, error) {
	if b == nil {
		return nil, localDenied()
	}
	r, ok := c.AuthenticationEvidence().(*remoteRequestBinding)
	if !ok || r == nil || r.boundary != b || r.principal != c.PrincipalView() || !r.active.Load() || r.lifetime.Err() != nil || !time.Now().Before(r.deadline) || c.VerifyAuthenticatedData(r.original, b.local.root.Namespace) != nil {
		return nil, localDenied()
	}
	return r, nil
}

// WithForwardRequest validates original source-root attestation/current pair,
// then releases peer SQL BEFORE node execution. Every later paid/source TX
// independently rechecks pins and exact exposure. Callback lifetime never turns
// an original paid proof into permission for a later control request.
func (b *RemoteBoundary) WithForwardRequest(ctx context.Context, bundle federation.ForwardBundle, next func(context.Context, fabric.ExecutionContext, any) error) error {
	if b == nil || ctx == nil || next == nil {
		return localDenied()
	}
	owned, err := federation.EncodeForwardBundle(bundle)
	if err != nil {
		return err
	}
	defer clear(owned)
	bundle, err = federation.DecodeForwardBundle(owned)
	if err != nil {
		return err
	}
	var verified fabric.ExecutionContext
	if e := federation.VerifyForwardBundle(ctx, b.config, bundle, b.limits, func(_ context.Context, c fabric.ExecutionContext) error { verified = c; return nil }); e != nil {
		return e
	}
	expires, e := time.Parse(time.RFC3339Nano, bundle.Proof.Frame.ExpiresAt)
	if e != nil {
		return e
	}
	lifetime, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	raw, e := federation.EncodeForwardBundle(bundle)
	if e != nil {
		return e
	}
	defer clear(raw)
	r := &remoteRequestBinding{boundary: b, principal: verified.PrincipalView(), original: bytes.Clone(bundle.Forwarded), assertion: sha256.Sum256(raw), deadline: expires, lifetime: lifetime, invocation: bundle.Proof.Frame.InvocationID}
	r.active.Store(true)
	defer r.active.Store(false)
	caller, e := fabric.NewAuthenticatedForwardContextWithEvidence(r.principal, b.local.root.Namespace, r.original, bundle.Proof.Frame.ForwardedProvenance, r)
	if e != nil {
		return e
	}
	return next(lifetime, caller, r)
}
func (b *RemoteBoundary) Authenticate(ctx context.Context, r fabric.AuthenticationRequest) (fabric.ExecutionContext, error) {
	binding, ok := r.PeerEvidence.(*remoteRequestBinding)
	if !ok || binding == nil || binding.boundary != b || r.Audience != b.local.root.Namespace || !bytes.Equal(r.ExactEnvelope, binding.original) {
		return fabric.ExecutionContext{}, localDenied()
	}
	var env fabric.Envelope
	if fabric.DecodeJSON(r.ExactEnvelope, &env) != nil || env.Validate() != nil {
		return fabric.ExecutionContext{}, localDenied()
	}
	caller, e := fabric.NewAuthenticatedForwardContextWithEvidence(binding.principal, r.Audience, r.ExactEnvelope, fabric.Provenance{Origin: env.Context.Origin, ParentID: env.Context.ParentID, Ancestry: env.Context.Ancestry, Hops: env.Context.Hops, ExtensionChain: env.Context.ExtensionChain, TriggerLineage: env.Context.TriggerLineage}, binding)
	if e != nil {
		return caller, e
	}
	_, e = b.binding(caller)
	return caller, e
}
func (b *RemoteBoundary) checkTx(ctx context.Context, tx *registry.AuthorityTx, caller fabric.ExecutionContext, target fabric.EndpointRef, revision fabric.Revision, binding string) error {
	r, e := b.binding(caller)
	if e != nil {
		return e
	}
	if e = b.peers.WithCurrentTx(ctx, tx, b.config.Local, b.config.Remote, func(context.Context) error {
		return b.exposures.CheckTx(tx, b.config.Remote.Authority.Namespace, target, revision, binding)
	}); e != nil {
		return e
	}
	if !r.active.Load() || r.lifetime.Err() != nil || !time.Now().Before(r.deadline) {
		return localDenied()
	}
	return nil
}
func (b *RemoteBoundary) witness(caller fabric.ExecutionContext, target fabric.EndpointRef, revision fabric.Revision, binding string) (identity.Witness, error) {
	r, e := b.binding(caller)
	if e != nil {
		return identity.Witness{}, e
	}
	open := func() bool { return r.active.Load() && r.lifetime.Err() == nil && time.Now().Before(r.deadline) }
	return identity.Witness{Version: "pagnet.remote-boundary.v1", CurrentCallerKind: "remote-peer.request", CurrentCallerOpen: open, RemoteCaller: &identity.RemoteCallerWitness{Principal: r.principal, RequestDigest: sha256.Sum256(r.original), AssertionDigest: r.assertion, AssociationOpen: open, VerifyCurrent: func(tx *registry.AuthorityTx) error {
		return b.checkTx(r.lifetime, tx, caller, target, revision, binding)
	}}}, nil
}
func (b *RemoteBoundary) WithAdmission(ctx context.Context, f identity.AdmissionFacts, next func(identity.Witness) error) error {
	if b == nil || next == nil {
		return localDenied()
	}
	if f.Purpose != identity.PurposeInvokeAdmission {
		return b.local.WithAdmission(ctx, f, next)
	}
	if _, e := b.binding(f.Caller); e != nil {
		return e
	}
	if b.local.verifyFacts(f) != nil {
		return localDenied()
	}
	w, e := b.witness(f.Caller, f.Target, f.TargetRevision, f.Scope.BindingID)
	if e != nil {
		return e
	}
	w.FinalizedDigest = f.FinalizedDigest
	w.Value = json.RawMessage(`{"boundary":"certified-remote"}`)
	return b.local.selectedPlanWitness(ctx, nil, w, next)
}

// AuthenticateControl verifies a fresh finite source-root assertion over the
// exact control bytes. Historical signatures alone cannot mint this evidence.
func (b *RemoteBoundary) AuthenticateControl(ctx context.Context, c federation.Config, request federation.ControlRequest, next func(context.Context, fabric.ExecutionContext) error) error {
	if b == nil || ctx == nil || next == nil || c.Channel != b.config.Channel || c.Local.BindingDigest != b.config.Local.BindingDigest || c.Remote.BindingDigest != b.config.Remote.BindingDigest {
		return localDenied()
	}
	owned, err := json.Marshal(request)
	if err != nil || len(owned) > 24<<10 {
		return localDenied()
	}
	defer clear(owned)
	if fabric.DecodeJSONWithLimits(owned, &request, fabric.WireLimits{MaxBytes: 24 << 10, MaxDepth: 16, MaxMembers: 512}) != nil {
		return localDenied()
	}
	c = b.config
	f := request.Proof.Frame
	raw, e := f.SigningBytes()
	if e != nil {
		return e
	}
	issued, e := time.Parse(time.RFC3339Nano, f.IssuedAt)
	if e != nil {
		return e
	}
	expires, e := time.Parse(time.RFC3339Nano, f.ExpiresAt)
	if e != nil {
		return e
	}
	now := time.Now()
	if now.Before(issued) || !now.Before(expires) || expires.Sub(issued) > b.limits.MaxLifetime || f.SourceDomain != c.Remote.Authority.Namespace || f.SourceStoreID != c.Remote.Authority.StoreID || f.SourceKeyRevision != c.Remote.Authority.KeyRevision || f.DestinationDomain != c.Local.Authority.Namespace || f.DestinationStoreID != c.Local.Authority.StoreID || f.SourcePeerBindingDigest != c.Remote.BindingDigest || f.DestinationPeerBindingDigest != c.Local.BindingDigest || f.PayloadDigest != sha256.Sum256(request.Payload) || len(request.Payload) > 4096 || len(c.Remote.Authority.PublicKey) != ed25519.PublicKeySize || !ed25519.Verify(c.Remote.Authority.PublicKey, raw, request.Proof.Signature) {
		return localDenied()
	}
	if e = b.peers.WithCurrent(ctx, c.Local, c.Remote, func(context.Context) error { return nil }); e != nil {
		return e
	}
	lifetime, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	r := &remoteRequestBinding{boundary: b, principal: f.Principal, original: bytes.Clone(raw), assertion: sha256.Sum256(append(bytes.Clone(raw), request.Proof.Signature...)), deadline: expires, lifetime: lifetime, invocation: f.InvocationID, control: &f}
	r.active.Store(true)
	defer r.active.Store(false)
	caller, e := fabric.NewAuthenticatedContextWithEvidence(f.Principal, c.Local.Authority.Namespace, raw, r)
	if e != nil {
		return e
	}
	return next(lifetime, caller)
}
func (b *RemoteBoundary) WithRetainedSourceRequest(ctx context.Context, caller fabric.ExecutionContext, p fabric.Principal, id, action string, next func(context.Context) error) error {
	r, e := b.binding(caller)
	if e != nil || p != r.principal || id != r.invocation || next == nil {
		return localDenied()
	}
	if action != "source_inspect" && action != "source_frame" && action != "source_verify" {
		return localDenied()
	}
	return next(ctx)
}
func (b *RemoteBoundary) AuthorizeRetainedSourceTx(ctx context.Context, tx *registry.AuthorityTx, caller fabric.ExecutionContext, receipt fabricservices.Receipt, action string) error {
	r, e := b.binding(caller)
	if e != nil || receipt.Facts.Principal != r.principal || receipt.Facts.InvocationID != r.invocation {
		return localDenied()
	}
	if action != "source_inspect" && action != "source_frame" && action != "source_verify" {
		return localDenied()
	}
	return b.checkTx(ctx, tx, caller, receipt.Facts.Target, receipt.Facts.Revision, receipt.Facts.Scope.BindingID)
}
