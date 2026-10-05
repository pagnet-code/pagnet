package fabricnode

import (
	"bytes"
	"context"
	"crypto/sha256"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/node/dispatch"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricservices"
)

type remoteDispatchStampKey struct{}
type remoteDispatchStamp struct {
	boundary               *RemoteBoundary
	caller                 fabric.Principal
	invocation             string
	original, final, input [32]byte
	target                 fabric.EndpointRef
	revision               fabric.Revision
	scope                  registry.DescriptorBatchScope
	fingerprint            [32]byte
}

// WithCurrent performs only current infrastructure checks before profile lookup.
// Its callback is outside SQL. Paid dispatch subsequently rechecks exact selected
// binding/exposure in its OWN destination transaction; this is not a grant cache.
func (b *RemoteBoundary) WithCurrent(ctx context.Context, c fabric.ExecutionContext, d fabric.EndpointDescriptor, next func(context.Context) error) error {
	if b == nil || next == nil {
		return localDenied()
	}
	if _, ok := c.AuthenticationEvidence().(*remoteRequestBinding); !ok {
		return b.local.WithCurrent(ctx, c, d, next)
	}
	if _, e := b.binding(c); e != nil {
		return e
	}
	if d.Ref.Domain() != b.local.root.Namespace || d.Ref.IsOffer() || d.Revision == "" {
		return localDenied()
	}
	if e := b.peers.WithCurrent(ctx, b.config.Local, b.config.Remote, func(context.Context) error { return nil }); e != nil {
		return e
	}
	return next(ctx)
}

// WithDispatch consumes actual engine-finalized routing, never caller payload
// routing. REDIRECT has already rerun configured interceptors; exact exposure
// checks run again for that finalized target and selected physical binding.
func (b *RemoteBoundary) WithDispatch(ctx context.Context, caller fabric.ExecutionContext, original, final []byte, d fabric.EndpointDescriptor, offer *fabric.OfferDescriptor, selection dispatch.Selection, next func(context.Context) (fabric.InvocationStream, error)) (fabric.InvocationStream, error) {
	if b == nil || next == nil {
		return nil, localDenied()
	}
	if _, ok := caller.AuthenticationEvidence().(*remoteRequestBinding); !ok {
		return b.local.WithDispatch(ctx, caller, original, final, d, offer, selection, next)
	}
	actual, raw, transformed, ok := node.FinalizedRequestFromContext(ctx)
	if !ok || !bytes.Equal(raw, original) || !bytes.Equal(transformed, final) || actual.AuthenticationEvidence() != caller.AuthenticationEvidence() || caller.VerifyAuthenticatedData(original, b.local.root.Namespace) != nil {
		return nil, localDenied()
	}
	if _, e := b.binding(caller); e != nil {
		return nil, e
	}
	var env fabric.Envelope
	if fabric.DecodeJSON(final, &env) != nil || env.Validate() != nil || env.Operation != fabric.OperationInvoke || env.Target == nil || env.Target.Endpoint() != d.Ref || d.Ref.Domain() != b.local.root.Namespace || d.Revision != selection.EndpointRevision || selection.Adapter == nil || selection.Fingerprint == ([32]byte{}) {
		return nil, localDenied()
	}
	published := false
	for _, binding := range d.Bindings {
		published = published || binding.ID == selection.BindingID
	}
	if !published {
		return nil, localDenied()
	}
	if offer != nil && (offer.Ref != *env.Target || offer.Revision != env.ExpectedRevision || offer.BindingID != selection.BindingID) {
		return nil, localDenied()
	}
	scope := registry.DescriptorBatchScope{Endpoint: d.Ref, ExpectedEndpointRevision: d.Revision, BindingID: selection.BindingID}
	// No downstream provider callback runs under the setup/exposure transaction.
	if e := b.local.operatorCurrent(ctx, b.local.owner, func(ctx context.Context) error {
		return b.local.store.WithNativeAuthority(ctx, b.local.owner, registry.AuthorityScope{}, func(tx *registry.AuthorityTx) error {
			return b.checkTx(ctx, tx, caller, *env.Target, env.ExpectedRevision, scope.BindingID)
		})
	}); e != nil {
		return nil, e
	}
	stamp := &remoteDispatchStamp{boundary: b, caller: caller.PrincipalView(), invocation: env.ID, original: sha256.Sum256(original), final: sha256.Sum256(final), input: sha256.Sum256(env.Payload), target: *env.Target, revision: env.ExpectedRevision, scope: scope, fingerprint: selection.Fingerprint}
	return next(context.WithValue(ctx, remoteDispatchStampKey{}, stamp))
}
func (b *RemoteBoundary) AuthorizeTx(ctx context.Context, tx *registry.AuthorityTx, caller fabric.ExecutionContext, f fabricservices.InvocationFacts, action string) error {
	if b == nil {
		return localDenied()
	}
	if _, ok := caller.AuthenticationEvidence().(*remoteRequestBinding); !ok {
		return b.local.AuthorizeTx(ctx, tx, caller, f, action)
	}
	s, ok := ctx.Value(remoteDispatchStampKey{}).(*remoteDispatchStamp)
	if !ok || s == nil || s.boundary != b || s.caller != caller.PrincipalView() || f.Principal != s.caller || f.InvocationID != s.invocation || f.OriginalSHA != s.original || f.FinalizedSHA != s.final || f.InputSHA != s.input || f.Target != s.target || f.Revision != s.revision || f.Scope != s.scope || f.Fingerprint != s.fingerprint || caller.VerifyAuthenticatedDigest(s.original, b.local.root.Namespace) != nil {
		return localDenied()
	}
	switch action {
	case "reserve", "replay", "append", "frame", "read", "find", "pull", "associate", "associate_admission":
	default:
		return fabric.NewError(fabric.CodeUnsupported, "Remote service action is unavailable")
	}
	if e := b.local.verifyExtensionPlanTx(ctx, tx); e != nil {
		return e
	}
	return b.checkTx(ctx, tx, caller, f.Target, f.Revision, f.Scope.BindingID)
}
