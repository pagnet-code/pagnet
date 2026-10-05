package fabricauth

import (
	"context"
	"crypto/sha256"
	"sync/atomic"

	"github.com/pagnet-code/pagnet/fabric"
)

// OwnerAdministration is an opaque, request-bound current kernel owner
// capability. It is not an invocation context, grant or serialized credential.
// Its lifetime ends when the synchronous administration callback returns.
type OwnerAdministration struct {
	session   *Session
	lifetime  context.Context
	active    atomic.Bool
	principal fabric.Principal
	digest    [32]byte
}

func (*OwnerAdministration) MarshalJSON() ([]byte, error) { return nil, denied() }
func (*OwnerAdministration) UnmarshalJSON([]byte) error   { return denied() }
func (a *OwnerAdministration) PrincipalView() fabric.Principal {
	if a == nil {
		return fabric.Principal{}
	}
	return a.principal
}
func (a *OwnerAdministration) RequestDigest() [32]byte {
	if a == nil {
		return [32]byte{}
	}
	return a.digest
}

// VerifyCurrent rechecks the original kernel PID/UID/birth, retained root and
// managed-owner guard. Call outside SQL/provider locks, never inside a retained
// Store transaction: current root verification uses that actual Store.
func (a *OwnerAdministration) VerifyCurrent(ctx context.Context) error {
	if a == nil || a.session == nil || ctx == nil || ctx.Err() != nil || a.lifetime == nil || a.lifetime.Err() != nil || !a.active.Load() {
		return denied()
	}
	s := a.session
	checked, cancel := context.WithTimeout(ctx, s.authority.config.CheckTimeout)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !a.active.Load() || s.revoked.Load() || s.activation != nil {
		return denied()
	}
	principal, err := s.verify(checked)
	if err != nil || principal != a.principal || principal != s.authority.config.RootOwner || !a.active.Load() || a.lifetime.Err() != nil || checked.Err() != nil {
		return denied()
	}
	return nil
}

// WithOwnerAdministration authenticates directly from the bound kernel session.
// It never calls Build or creates a fake discovery/invocation envelope. Neither
// requested owner mode nor a managed endpoint's valid session grants this port.
// Session.mu is released over the handler and recursive current checks.
func (s *Session) WithOwnerAdministration(ctx context.Context, exact []byte, next func(context.Context, *OwnerAdministration) error) error {
	if s == nil || ctx == nil || ctx.Err() != nil || next == nil || len(exact) == 0 || len(exact) > 64<<10 {
		return denied()
	}
	var request any
	if fabric.DecodeJSONWithLimits(exact, &request, fabric.WireLimits{MaxBytes: 64 << 10, MaxDepth: 64, MaxMembers: 4096}) != nil {
		return denied()
	}
	capability := &OwnerAdministration{session: s, principal: s.authority.config.RootOwner, digest: sha256.Sum256(exact), lifetime: ctx}
	capability.active.Store(true)
	defer capability.active.Store(false)
	if err := capability.VerifyCurrent(ctx); err != nil {
		return err
	}
	if err := next(ctx, capability); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return capability.VerifyCurrent(ctx)
}
