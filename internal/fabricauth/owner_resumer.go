package fabricauth

import (
	"context"
	"sync"

	"github.com/pagnet-code/pagnet/fabric"
)

func (b *sessionBinding) open() bool {
	if b == nil || b.session == nil || b.session.revoked.Load() {
		return false
	}
	if b.administration == nil {
		return true
	}
	return !b.released.Load() && (b.retained.Load() || (b.administration.active.Load() && b.administration.lifetime.Err() == nil))
}

// WithResumerContext binds the exact private administration request to its real
// owner session. This control-purpose context cannot enter ordinary paid invoke.
func (a *OwnerAdministration) WithResumerContext(ctx context.Context, next func(context.Context, fabric.ExecutionContext) error) error {
	if next == nil || a.VerifyCurrent(ctx) != nil || !a.resumer.CompareAndSwap(false, true) {
		return denied()
	}
	b := &sessionBinding{authority: a.session.authority, session: a.session, principal: a.principal, originalDigest: a.digest, administration: a}
	c, err := fabric.NewAuthenticatedContextWithEvidence(a.principal, b.authority.config.Audience, a.exact, b)
	if err != nil {
		return err
	}
	if !b.open() {
		return denied()
	}
	return next(ctx, c)
}

// RetainOwnerResumer is trusted continuation composition, called only after a
// genuine fresh claim is consumed. Closing the admin callback prevents new
// retention; closing the underlying session revokes even an owned claim.
func (a *Authority) RetainOwnerResumer(ctx context.Context, caller fabric.ExecutionContext) (func(), error) {
	if !a.RecognizesCurrentCaller(caller) {
		return nil, denied()
	}
	b := caller.AuthenticationEvidence().(*sessionBinding)
	if b.administration == nil {
		if err := a.WithCurrentContext(ctx, caller, func(context.Context) error { return nil }); err != nil {
			return nil, err
		}
		return func() {}, nil
	}
	admin := b.administration
	if err := admin.VerifyCurrent(ctx); err != nil {
		return nil, err
	}
	admin.controlMu.Lock()
	defer admin.controlMu.Unlock()
	if !admin.active.Load() || admin.lifetime.Err() != nil || !b.open() || !b.retained.CompareAndSwap(false, true) {
		return nil, denied()
	}
	var once sync.Once
	return func() { once.Do(func() { b.released.Store(true) }) }, nil
}
