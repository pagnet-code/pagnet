package fabricnode

import (
	"context"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// currentStateReadValidator is the production ValidateReadResult port that
// ComposeRetained installs whenever the composition runs interceptors. It runs
// after request and response interception and re-reads the retained registry,
// so an extension cannot disclose a reference the registry no longer holds,
// present a stale revision as current, or turn an absent target into a
// descriptor. Per-selection describe errors are part of the wire contract and
// pass: the gate validates what is disclosed, never what is absent.
func currentStateReadValidator(store *registry.Store) node.ReadResultValidator {
	return func(ctx context.Context, _ fabric.ExecutionContext, _ fabric.Envelope, result node.Result) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if result.Discover != nil {
			for _, candidate := range result.Discover.Candidates {
				if _, err := store.GetEndpoint(ctx, candidate.Document.Ref, ""); err != nil {
					return fabric.NewError(fabric.CodeProtocolError, "Intercepted discovery result discloses an endpoint the current registry does not hold")
				}
			}
			return nil
		}
		if result.Describe == nil {
			return fabric.NewError(fabric.CodeProtocolError, "Intercepted read result carries no discover or describe payload")
		}
		for _, item := range result.Describe.Descriptions {
			if item.Error != nil {
				continue
			}
			switch {
			case item.Endpoint != nil:
				current, err := store.GetEndpoint(ctx, item.Endpoint.Ref, "")
				if err != nil || current.Revision != item.Endpoint.Revision {
					return fabric.NewError(fabric.CodeProtocolError, "Intercepted describe result is not the current registry state")
				}
			case item.Offer != nil:
				current, err := store.GetOffer(ctx, item.Offer.Ref, "")
				if err != nil || current.Revision != item.Offer.Revision {
					return fabric.NewError(fabric.CodeProtocolError, "Intercepted describe result is not the current registry state")
				}
			default:
				return fabric.NewError(fabric.CodeProtocolError, "Intercepted describe result disclosed no current descriptor")
			}
		}
		return nil
	}
}
