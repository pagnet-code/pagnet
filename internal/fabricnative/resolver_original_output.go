package fabricnative

import (
	"context"
	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
)

// OriginalOutputResolver refreshes only already accepted physical ownership.
// This port is separate from viewer Refresh and can never launch a replacement.
type OriginalOutputResolver interface {
	RefreshOriginalOutput(context.Context, *identity.OriginalOutputCapture, identity.NativeDispatchReservation, nativeauthority.Scope) (WorkerHandle, error)
}

func (r *Resolver) RefreshOriginalOutput(ctx context.Context, c *identity.OriginalOutputCapture, reservation identity.NativeDispatchReservation, original nativeauthority.Scope) (WorkerHandle, error) {
	if r == nil || c == nil || ctx == nil {
		return WorkerHandle{}, checkpointDenied()
	}
	b := c.OriginalBinding()
	physical, err := nativeauthority.NewLocalScope(r.config.Authority.Identity(), b)
	if err != nil || !physical.SamePhysical(original) {
		return WorkerHandle{}, checkpointDenied()
	}
	if err = r.config.Authority.ValidateOriginalOutput(ctx, r.config.Owner, c, reservation); err != nil {
		return WorkerHandle{}, err
	}
	// The protected operator is used only for existing worker IPC adoption.
	// The source's own cap, not this operator, authorizes subsequent Page/ACK.
	h, err := r.resolve(ctx, r.config.Owner, b.Scope.Endpoint, "", original, false)
	if err != nil {
		return WorkerHandle{}, err
	}
	if err = r.config.Authority.ValidateOriginalOutput(ctx, r.config.Owner, c, reservation); err != nil {
		clear(h.ControlKey)
		return WorkerHandle{}, err
	}
	return h, nil
}
