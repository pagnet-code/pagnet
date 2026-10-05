package fabricnode

import (
	"bytes"
	"context"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// CurrentPhaseWitness authenticates the live, private destination request for
// each extension call. It does not grant business authority or guess a physical
// binding before dispatch. Dispatch independently checks the finalized target's
// explicit exposure and selected binding in its original admission transaction.
func (b *RemoteBoundary) CurrentPhaseWitness(ctx context.Context, caller fabric.ExecutionContext, original []byte, phase fabric.Envelope) (func(*registry.AuthorityTx) error, error) {
	if ctx == nil || ctx.Err() != nil || phase.Validate() != nil {
		return nil, localDenied()
	}
	request, err := b.binding(caller)
	if err != nil || !bytes.Equal(original, request.original) {
		return nil, localDenied()
	}
	verified, err := caller.DecodeVerifiedEnvelope(original, b.local.root.Namespace)
	if err != nil || phase.ID != verified.ID || phase.Principal != verified.Principal || phase.Operation != verified.Operation {
		return nil, localDenied()
	}
	if err = b.peers.WithCurrent(ctx, b.config.Local, b.config.Remote, func(context.Context) error { return nil }); err != nil {
		return nil, err
	}
	return func(tx *registry.AuthorityTx) error {
		if ctx.Err() != nil {
			return localDenied()
		}
		if _, err := b.binding(caller); err != nil {
			return err
		}
		return b.peers.WithCurrentTx(ctx, tx, b.config.Local, b.config.Remote, func(context.Context) error {
			_, err := b.binding(caller)
			return err
		})
	}, nil
}
