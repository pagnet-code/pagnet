package daemon

import (
	"context"
	"errors"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

func (d *Daemon) doResolveRuntimeInteraction(p transport.ResolveRuntimeInteractionPayload) error {
	if p.InstanceID == "" || p.SessionID == "" || p.NativeInteractionID == "" || p.OptionID == "" || p.ExpiresAt.IsZero() || !time.Now().Before(p.ExpiresAt) {
		return errors.New("native approval request expired or invalid")
	}
	if c, private := d.contextForInstance(p.InstanceID); private {
		gate := d.ownerContextGate(c.ID)
		if gate == nil {
			return errors.New("protected context unavailable")
		}
		gate.RLock()
		defer gate.RUnlock()
	}
	if err := d.verifyOwnerApproval(p); err != nil {
		return err
	}
	if d.sessions == nil {
		return errors.New("native approval unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := d.sessions.ResolvePendingInteraction(ctx, p.InstanceID, p.SessionID, p.NativeInteractionID, p.OptionID); err != nil {
		return errors.New("native approval was not confirmed")
	}
	return nil
}
