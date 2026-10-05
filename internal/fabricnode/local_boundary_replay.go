package fabricnode

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabricservices"
)

// WithReplayRequest reconstructs only a CURRENT private dispatch stamp from
// the actual node capability. The outer node verifier does not retain the
// original adapter callback's context. No historical receipt or public alias
// can manufacture this association or authenticate a current caller.
func (b *LocalBoundary) WithReplayRequest(ctx context.Context, caller fabric.ExecutionContext, f fabricservices.InvocationFacts, next func(context.Context) error) error {
	if b == nil || ctx == nil || next == nil || ctx.Err() != nil {
		return localDenied()
	}
	actual, original, final, ok := node.FinalizedRequestFromContext(ctx)
	if !ok || actual.PrincipalView() != caller.PrincipalView() || caller.PrincipalView() != f.Principal || caller.VerifyAuthenticatedDigest(f.OriginalSHA, b.root.Namespace) != nil || actual.VerifyAuthenticatedDigest(f.OriginalSHA, b.root.Namespace) != nil || sha256.Sum256(original) != f.OriginalSHA || sha256.Sum256(final) != f.FinalizedSHA {
		return localDenied()
	}
	if _, err := caller.DecodeVerifiedEnvelope(original, b.root.Namespace); err != nil {
		return err
	}
	var env fabric.Envelope
	if fabric.DecodeJSON(final, &env) != nil || env.Validate() != nil || env.Operation != fabric.OperationInvoke || env.ID != f.InvocationID || env.Principal != f.Principal || env.Target == nil || *env.Target != f.Target || env.ExpectedRevision == "" || env.ExpectedRevision != f.Revision || env.Target.Endpoint() != f.Scope.Endpoint || env.Target.Domain() != b.root.Namespace || env.Context.IdempotencyKey == "" || sha256.Sum256(env.Payload) != f.InputSHA || f.Fingerprint == ([32]byte{}) {
		return localDenied()
	}
	if env.Context.Deadline != nil && !time.Now().Before(*env.Context.Deadline) {
		return fabric.NewError(fabric.CodeDeadlineExceeded, "Current replay request deadline expired")
	}
	endpoint, err := b.store.GetEndpoint(ctx, f.Scope.Endpoint, f.Scope.ExpectedEndpointRevision)
	if err != nil {
		return err
	}
	if endpoint.Ref != f.Scope.Endpoint || endpoint.Revision != f.Scope.ExpectedEndpointRevision {
		return localDenied()
	}
	published := false
	for _, binding := range endpoint.Bindings {
		published = published || binding.ID == f.Scope.BindingID
	}
	if !published {
		return localDenied()
	}
	if f.Target.IsOffer() {
		offer, err := b.store.GetOffer(ctx, f.Target, f.Revision)
		if err != nil {
			return err
		}
		if offer.Ref != f.Target || offer.Revision != f.Revision || offer.BindingID != f.Scope.BindingID {
			return localDenied()
		}
	} else if f.Revision != endpoint.Revision {
		return localDenied()
	}
	return b.callerFacts(ctx, caller, func(_ context.Context, facts fabricauth.CurrentCallerFacts) error {
		b.mu.RLock()
		association := b.sessions
		b.mu.RUnlock()
		stamp := &dispatchStamp{boundary: b, association: association, authenticatedCaller: caller, caller: f.Principal, originalSHA: f.OriginalSHA, finalizedSHA: f.FinalizedSHA, inputSHA: f.InputSHA, invocationID: f.InvocationID, target: f.Target, revision: f.Revision, scope: f.Scope, fingerprint: f.Fingerprint}
		if facts.Managed != nil {
			authority := facts.Managed.Authority
			stamp.managed = &authority
		} else if facts.Principal != b.root.Owner {
			return localDenied()
		}
		// Retain invocation lifetime, never the bounded preflight timeout's context.
		return guardedBoundary(ctx, func(c context.Context, n func(context.Context) error) error { return n(c) }, func(c context.Context) error { return next(context.WithValue(c, dispatchStampKey{}, stamp)) })
	})
}

// AuthorizeHistoryTx is called only AFTER the ledger has verified its actual
// retained SAME-root alias, original receipt and current private profile. A
// public signature alone cannot authorize source disclosure. Current managed
// retirement and owner Session.Close are rechecked at this destination TX.
func (b *LocalBoundary) AuthorizeHistoryTx(ctx context.Context, tx *registry.AuthorityTx, caller fabric.ExecutionContext, current, original fabricservices.InvocationFacts, action string) error {
	if b == nil || ctx == nil || tx == nil || ctx.Err() != nil {
		return localDenied()
	}
	if err := b.verifyExtensionPlanTx(ctx, tx); err != nil {
		return err
	}

	switch action {
	case "alias_admit", "alias_verify", "alias_pull":
	default:
		return fabric.NewError(fabric.CodeUnsupported, "Local replay action is not supported")
	}
	if current.InvocationID == original.InvocationID || current.Principal != original.Principal || current.Target != original.Target || current.Revision != original.Revision || current.Scope != original.Scope || current.Fingerprint != original.Fingerprint || current.InputSHA != original.InputSHA {
		return localDenied()
	}
	stamp, err := b.exactCurrentStamp(ctx, caller, current)
	if err != nil {
		return err
	}
	return b.authorizeStampTx(tx, stamp)
}

// exactCurrentStamp is shared by replay and ordinary service authorization so
// caller digests never receive a historical receipt exception.
func (b *LocalBoundary) exactCurrentStamp(ctx context.Context, caller fabric.ExecutionContext, f fabricservices.InvocationFacts) (*dispatchStamp, error) {
	if b == nil || ctx == nil || ctx.Err() != nil {
		return nil, localDenied()
	}
	s, ok := ctx.Value(dispatchStampKey{}).(*dispatchStamp)
	if !ok || s == nil || s.boundary != b || s.caller != caller.PrincipalView() || caller.VerifyAuthenticatedDigest(s.originalSHA, b.root.Namespace) != nil || f.Principal != s.caller || f.InvocationID != s.invocationID || f.Target != s.target || f.Revision != s.revision || f.Scope != s.scope || f.Fingerprint != s.fingerprint || f.OriginalSHA != s.originalSHA || f.FinalizedSHA != s.finalizedSHA || f.InputSHA != s.inputSHA {
		return nil, localDenied()
	}
	return s, nil
}
func (b *LocalBoundary) authorizeStampTx(tx *registry.AuthorityTx, s *dispatchStamp) error {
	b.mu.RLock()
	closed := b.closed
	b.mu.RUnlock()
	if closed {
		return localDenied()
	}
	if s.association == nil || !s.association.AssociationOpen(s.authenticatedCaller) {
		return localDenied()
	}
	if s.resume != nil {
		if s.resume.original != s.caller || s.resume.resumer.PrincipalView() != s.authenticatedCaller.PrincipalView() {
			return localDenied()
		}
		if err := s.resume.verifyTx(tx); err != nil {
			return err
		}
		if s.managed != nil {
			if s.managed.Principal != s.resume.resumer.PrincipalView() {
				return localDenied()
			}
			return tx.VerifyCurrentNativeCaller(*s.managed)
		}
		if s.resume.resumer.PrincipalView() != b.root.Owner {
			return localDenied()
		}
		return nil
	}
	if s.managed != nil {
		if s.managed.Principal != s.caller {
			return localDenied()
		}
		return tx.VerifyCurrentNativeCaller(*s.managed)
	}
	if s.caller != b.root.Owner {
		return localDenied()
	}
	return nil
}
