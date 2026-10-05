package fabricauth

import (
	"context"
	"crypto/sha256"
	"sync/atomic"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// sessionBinding is minted only after the actual single-use kernel-peer proof
// succeeds. No global association table or serialized assertion recreates it.
type sessionBinding struct {
	authority      *Authority
	session        *Session
	principal      fabric.Principal
	originalDigest [32]byte
	administration *OwnerAdministration
	retained       atomic.Bool
	released       atomic.Bool
}

func (*sessionBinding) MarshalJSON() ([]byte, error) { return nil, denied() }
func (*sessionBinding) UnmarshalJSON([]byte) error   { return denied() }

// WithCurrentCaller requires the exact original invocation in addition to the
// private current association. Paid deadlines remain the downstream authority's
// responsibility; current historical read/stop does not refresh them.
func (a *Authority) WithCurrentCaller(ctx context.Context, caller fabric.ExecutionContext, original []byte, next func(context.Context) error) error {
	if a == nil || ctx == nil || next == nil {
		return denied()
	}
	b, ok := caller.AuthenticationEvidence().(*sessionBinding)
	if !ok || b == nil || b.administration != nil || len(original) == 0 || sha256.Sum256(original) != b.originalDigest {
		return denied()
	}
	if _, err := caller.DecodeVerifiedEnvelope(original, a.config.Audience); err != nil {
		return err
	}
	return a.WithCurrentContext(ctx, caller, next)
}

// WithCurrentContext revalidates the live local session. Session mutex and
// registry locks are released before invoking recursively composed policy;
// this is not a cross-transaction retirement/revocation fence. Destination
// admission must consume current authority facts in its own transaction.
func (a *Authority) WithCurrentContext(ctx context.Context, caller fabric.ExecutionContext, next func(context.Context) error) error {
	if a == nil || ctx == nil || ctx.Err() != nil || next == nil {
		return denied()
	}
	b, ok := caller.AuthenticationEvidence().(*sessionBinding)
	if !ok || b == nil || b.authority != a || b.session == nil || b.session.authority != a || !b.open() || b.principal != caller.PrincipalView() || caller.VerifyAuthenticatedDigest(b.originalDigest, a.config.Audience) != nil {
		return denied()
	}
	checked, cancel := context.WithTimeout(ctx, a.config.CheckTimeout)
	defer cancel()
	b.session.mu.Lock()
	principal, err := b.session.verify(checked)
	b.session.mu.Unlock()
	if err != nil || principal != b.principal || !b.open() {
		return denied()
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return next(ctx)
}

// RecognizesCurrentCaller checks only the private provider association. It is
// used to choose a verifier, never as current authorization or a liveness cache.
func (a *Authority) RecognizesCurrentCaller(caller fabric.ExecutionContext) bool {
	if a == nil {
		return false
	}
	b, ok := caller.AuthenticationEvidence().(*sessionBinding)
	return ok && b != nil && b.authority == a && b.session != nil && b.session.authority == a && b.open() && b.principal == caller.PrincipalView() && caller.VerifyAuthenticatedDigest(b.originalDigest, a.config.Audience) == nil
}

// VerifyRetainedRoot lets trusted private composition seal this authority to
// its actual installation without exposing a mutable authentication setter.
func (a *Authority) VerifyRetainedRoot(ctx context.Context, root registry.AuthorityIdentity) error {
	if a == nil || ctx == nil || !sameRoot(a.config.Root, root) {
		return denied()
	}
	return a.current(ctx)
}

// AssociationOpen is a cheap destination-transaction revocation check, not a
// substitute for live kernel/source preflight. It never acquires Session.mu or
// performs Root/native IO and cannot deadlock with an authenticator preflight.
func (a *Authority) AssociationOpen(caller fabric.ExecutionContext) bool {
	if !a.RecognizesCurrentCaller(caller) {
		return false
	}
	return !caller.AuthenticationEvidence().(*sessionBinding).session.revoked.Load()
}
