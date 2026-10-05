package daemon

import (
	"context"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/localpeer"
)

// HostedOwnerGuardReady is a startup fence, never called on the invocation hot
// path. Original registry inspection is bounded and performed only to expose
// an explicitly hosted-enabled node. Unknown or disconnected original workers
// cannot silently become owner-mode peers; no snapshot/SID adoption occurs here.
func (d *Daemon) HostedOwnerGuardReady(ctx context.Context, guard *HostedOwnerGuard) error {
	if d == nil || ctx == nil || ctx.Err() != nil || guard == nil || d.HostedOwnerGuard != guard || d.nativeRegistry == nil {
		return hostedOwnerDenied()
	}
	records, err := d.nativeRegistry.List()
	if err != nil {
		return err
	}
	for _, record := range records {
		if err = ctx.Err(); err != nil {
			return err
		}
		// A crash can leave an actually started worker in "launching" before
		// acknowledgement. That state must not skip the original owner fence.
		if record.LaunchState == "reserved" {
			continue
		}
		guard.mu.RLock()
		root, found := guard.workers[record.Scope]
		guard.mu.RUnlock()
		if !found {
			return fabric.NewError(fabric.CodeTargetUnavailable, "Original hosted worker authentication must finish before enabling the node")
		}
		current, readErr := localpeer.ReadProcess(root.PID)
		if readErr != nil || current.Start != root.Start || current.UID != root.UID {
			return fabric.NewError(fabric.CodeTargetUnavailable, "Original hosted worker incarnation requires authenticated reconciliation before enabling the node")
		}
	}
	return nil
}
